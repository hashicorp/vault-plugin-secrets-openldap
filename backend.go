package openldap

import (
	"context"
	"strings"
	"sync"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/locksutil"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/hashicorp/vault/sdk/queue"
)

type backend struct {
	*framework.Backend
	sync.RWMutex
	client ldapClient

	// CredRotationQueue is an in-memory priority queue used to track Static Roles
	// that require periodic rotation. Backends will have a PriorityQueue
	// initialized on setup, but only backends that are mounted by a primary
	// server or mounted as a local mount will perform the rotations.
	//
	// cancelQueue is used to remove the priority queue and terminate the
	// background ticker.
	credRotationQueue *queue.PriorityQueue
	cancelQueue       context.CancelFunc

	// managedUsers contains the set of LDAP usernames managed by the secrets engine
	// static role and check-in/check-out systems. It is used to ensure that users
	// are exclusively managed by one system and not both. Access to managedUsers is
	// synchronized by the managedUserLock.
	managedUsers    map[string]struct{}
	managedUserLock sync.Mutex

	// roleLocks is used to lock modifications to roles in the queue, to ensure
	// concurrent requests are not modifying the same role and possibly causing
	// issues with the priority queue.
	roleLocks []*locksutil.LockEntry

	// checkOutLocks are used for avoiding races when working with library sets
	// in the check-in/check-out system.
	checkOutLocks []*locksutil.LockEntry
}

func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	ldapClient := NewClient(conf.Logger)
	b := Backend(ldapClient)
	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}

	return b, nil
}

func Backend(client ldapClient) *backend {
	b := &backend{
		client:            client,
		credRotationQueue: queue.New(),
		roleLocks:         locksutil.CreateLocks(),
		checkOutLocks:     locksutil.CreateLocks(),
		managedUsers:      make(map[string]struct{}),
	}

	b.Backend = &framework.Backend{
		Help: strings.TrimSpace(backendHelp),
		PathsSpecial: &logical.Paths{
			LocalStorage: []string{
				framework.WALPrefix,
			},
			SealWrapStorage: []string{
				configPath,
				staticRolePath + "*",
			},
		},
		Paths: framework.PathAppend(
			b.pathConfig(),
			b.pathDynamicRoles(),
			b.pathDynamicCredsCreate(),
			b.pathStaticRoles(),
			b.pathStaticCredsCreate(),
			b.pathRotateCredentials(),
			b.pathSetCheckIn(),
			b.pathSetManageCheckIn(),
			b.pathSetCheckOut(),
			b.pathSetStatus(),
			b.pathSets(),
			b.pathListSets(),
		),
		InitializeFunc: b.initialize,
		Secrets: []*framework.Secret{
			dynamicSecretCreds(b),
			checkoutSecretCreds(b),
		},
		Clean:       b.clean,
		BackendType: logical.TypeLogical,
	}

	return b
}

func (b *backend) initialize(ctx context.Context, initRequest *logical.InitializationRequest) error {
	// Create a context with a cancel method for processing any WAL entries and
	// populating the queue
	ictx, cancel := context.WithCancel(context.Background())
	b.cancelQueue = cancel

	// Load managed LDAP users into memory from storage
	if err := b.loadManagedUsers(ctx, initRequest.Storage); err != nil {
		return err
	}

	// Load static role queue and kickoff new periodic ticker
	go b.initQueue(ictx, initRequest)

	return nil
}

func (b *backend) clean(ctx context.Context) {
	b.invalidateQueue()
}

// invalidateQueue cancels any background queue loading and destroys the queue.
func (b *backend) invalidateQueue() {
	b.Lock()
	defer b.Unlock()

	if b.cancelQueue != nil {
		b.cancelQueue()
	}
	b.credRotationQueue = nil
}

// loadManagedUsers loads users managed by the secrets engine from storage into
// the backend's managedUsers set. Users are loaded from both the static role and
// check-in/check-out systems. Returns an error if one occurs during loading.
func (b *backend) loadManagedUsers(ctx context.Context, s logical.Storage) error {
	b.managedUserLock.Lock()
	defer b.managedUserLock.Unlock()

	// Clear managed users before loading to ensure that the full set is
	// loaded from storage. This is important during initialization after
	// leadership changes to keep the set consistent with storage.
	b.managedUsers = make(map[string]struct{})

	// Load users managed under static roles
	staticRoles, err := s.List(ctx, staticRolePath)
	if err != nil {
		return err
	}
	for _, roleName := range staticRoles {
		staticRole, err := b.staticRole(ctx, s, roleName)
		if err != nil {
			return err
		}
		if staticRole == nil {
			continue
		}

		b.setManagedUsers(staticRole.StaticAccount.Username)
	}

	// Load users managed under library sets
	librarySets, err := s.List(ctx, libraryPrefix)
	if err != nil {
		return err
	}
	for _, setName := range librarySets {
		set, err := readSet(ctx, s, setName)
		if err != nil {
			return err
		}
		if set == nil {
			continue
		}

		b.setManagedUsers(set.ServiceAccountNames...)
	}

	return nil
}

// isManagedUser returns true if any of the given users are already managed
// by the secrets engine. Must be called with the managedUserLock held.
func (b *backend) isManagedUser(user string) bool {
	_, exists := b.managedUsers[user]
	return exists
}

// setManagedUsers sets the given users as managed by the secrets engine.
// Must be called with the managedUserLock held.
func (b *backend) setManagedUsers(users ...string) {
	for _, user := range users {
		b.managedUsers[user] = struct{}{}
	}
}

// deleteManagedUsers sets the user as unmanaged by the secrets engine.
// Must be called with the managedUserLock held.
func (b *backend) deleteManagedUsers(users ...string) {
	for _, user := range users {
		delete(b.managedUsers, user)
	}
}

const backendHelp = `
The LDAP backend supports managing existing LDAP entry passwords by providing:

 * end points to add entries
 * manual rotation of entry passwords
 * auto rotation of entry passwords
 * check-in/check-out for libraries of entries
 
The LDAP secret engine supports OpenLDAP, Active Directory, and IBM RACF 
implementations via schema configuration.

After mounting this secret backend, configure it using the "ldap/config" path.
`
