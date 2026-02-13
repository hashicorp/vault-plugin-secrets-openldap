// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: MPL-2.0

package openldap

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/hashicorp/go-secure-stdlib/base62"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/consts"
	"github.com/hashicorp/vault/sdk/helper/locksutil"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/hashicorp/vault/sdk/queue"
	"github.com/mitchellh/mapstructure"
)

const (
	// Interval to check the queue for items needing rotation
	queueTickSeconds  = 5
	queueTickInterval = queueTickSeconds * time.Second

	// WAL storage key used for static account rotations
	staticWALKey = "staticRotationKey"
)

// populateQueue loads the priority queue with existing static accounts. This
// occurs at initialization, after any WAL entries of failed or interrupted
// rotations have been processed. It lists the roles from storage and searches
// for any that have an associated static account, then adds them to the
// priority queue for rotations.
func (b *backend) populateQueue(ctx context.Context, s logical.Storage, roles map[string]*roleEntry) {
	log := b.Logger()
	log.Info("populating role rotation queue")

	// Build map of role name / wal entries
	walMap, err := b.loadStaticWALs(ctx, s)
	if err != nil {
		log.Warn("unable to load rotation WALs", "error", err)
	}

	for roleName, role := range roles {
		select {
		case <-ctx.Done():
			log.Info("rotation queue restore cancelled")
			return
		default:
		}

		if role == nil {
			log.Error("role not found in storage", "roleName", roleName)
			continue
		}

		// If an account's NextVaultRotation period is nil, it means that the
		// role was created before we added the `NextVaultRotation` field. In this
		// case, we need to calculate the next rotation time based on the
		// LastVaultRotation and the RotationPeriod. However, if the role was
		// created with skip_import_rotation set, we need to use the current time
		// instead of LastVaultRotation because LastVaultRotation is 0
		// This situation was fixed by https://github.com/hashicorp/vault-plugin-secrets-openldap/pull/140.
		if role.StaticAccount.NextVaultRotation.IsZero() {
			log.Debug("NextVaultRotation is zero", roleName)
			// Previously skipped import rotation roles had a LastVaultRotation value of zero
			if role.StaticAccount.LastVaultRotation.IsZero() {
				role.StaticAccount.SetNextVaultRotation(time.Now())
			} else {
				role.StaticAccount.SetNextVaultRotation(role.StaticAccount.LastVaultRotation)
			}

			entry, err := logical.StorageEntryJSON(staticRolePath+roleName, role)
			if err != nil {
				log.Warn("failed to build write storage entry", "error", err, "roleName", roleName)
			} else if err := s.Put(ctx, entry); err != nil {
				log.Warn("failed to write storage entry", "error", err, "roleName", roleName)
			}
		}

		item := queue.Item{
			Key:      roleName,
			Priority: role.StaticAccount.NextRotationTime().Unix(),
		}

		// For dual-account roles in grace_period state, schedule at grace period end
		if role.StaticAccount.DualAccountMode && role.StaticAccount.RotationState == "grace_period" && !role.StaticAccount.GracePeriodEnd.IsZero() {
			item.Priority = role.StaticAccount.GracePeriodEnd.Unix()
		}

		// Check if role name is in map
		walEntry := walMap[roleName]
		if walEntry != nil {
			// Check walEntry last vault time
			if walEntry.LastVaultRotation.IsZero() {
				// A WAL's last Vault rotation can only ever be 0 for a role that
				// was never successfully created. So we know this WAL couldn't
				// have been created for this role we just retrieved from storage.
				// i.e. it must be a hangover from a previous attempt at creating
				// a role with the same name
				log.Debug("deleting WAL with zero last rotation time", "WAL ID", walEntry.walID, "created", walEntry.walCreatedAt)
				if err := framework.DeleteWAL(ctx, s, walEntry.walID); err != nil {
					log.Warn("unable to delete zero-time WAL", "error", err, "WAL ID", walEntry.walID)
				}
			} else if walEntry.LastVaultRotation.Before(role.StaticAccount.LastVaultRotation) {
				// WAL's last vault rotation record is older than the role's data, so
				// delete and move on
				log.Debug("deleting outdated WAL", "WAL ID", walEntry.walID, "created", walEntry.walCreatedAt)
				if err := framework.DeleteWAL(ctx, s, walEntry.walID); err != nil {
					log.Warn("unable to delete WAL", "error", err, "WAL ID", walEntry.walID)
				}
			} else {
				log.Info("found WAL for role",
					"role", item.Key,
					"WAL ID", walEntry.walID)
				item.Value = walEntry.walID
				item.Priority = time.Now().Unix()
			}
		}

		if err := b.pushItem(&item); err != nil {
			log.Warn("unable to enqueue item", "error", err, "role", roleName)
		}
	}
}

// runTicker kicks off a periodic ticker that invoke the automatic credential
// rotation method at a determined interval. The default interval is 5 seconds.
func (b *backend) runTicker(ctx context.Context, s logical.Storage) {
	b.Logger().Info("starting periodic ticker")
	tick := time.NewTicker(queueTickInterval)
	defer tick.Stop()
	for {
		select {
		case <-tick.C:
			b.rotateCredentials(ctx, s)

		case <-ctx.Done():
			b.Logger().Info("stopping periodic ticker")
			return
		}
	}
}

// setCredentialsWAL is used to store information in a WAL that can retry a
// credential setting or rotation in the event of partial failure.
type setCredentialsWAL struct {
	NewPassword       string    `json:"new_password" mapstructure:"new_password"`
	RoleName          string    `json:"role_name" mapstructure:"role_name"`
	Username          string    `json:"username" mapstructure:"username"`
	DN                string    `json:"dn" mapstructure:"dn"`
	PasswordPolicy    string    `json:"password_policy" mapstructure:"password_policy"`
	LastVaultRotation time.Time `json:"last_vault_rotation" mapstructure:"last_vault_rotation"`

	// Dual-account fields for initial setup WAL recovery
	NewPasswordB string `json:"new_password_b,omitempty" mapstructure:"new_password_b"`
	UsernameB    string `json:"username_b,omitempty" mapstructure:"username_b"`
	DNB          string `json:"dn_b,omitempty" mapstructure:"dn_b"`

	// Private fields which will not be included in json.Marshal/Unmarshal.
	walID        string
	walCreatedAt int64 // Unix time at which the WAL was created.
}

// rotateCredentials sets a new password for a static account. This method is
// invoked in the runTicker method, which is in it's own go-routine, and invoked
// periodically (approximately every 5 seconds).
//
// This method loops through the priority queue, popping the highest priority
// item until it encounters the first item that does not yet need rotation,
// based on the current time.
func (b *backend) rotateCredentials(ctx context.Context, s logical.Storage) {
	for b.rotateCredential(ctx, s) {
	}
}

func (b *backend) rotateCredential(ctx context.Context, s logical.Storage) bool {
	// Quit rotating credentials if shutdown has started
	select {
	case <-ctx.Done():
		return false
	default:
	}
	item, err := b.popFromRotationQueue()
	if err != nil {
		if err != queue.ErrEmpty {
			b.Logger().Error("error popping item from queue", "err", err)
		}
		return false
	}

	// Guard against possible nil item
	if item == nil {
		return false
	}

	// Grab the exclusive lock for this Role, to make sure we don't incur and
	// writes during the rotation process
	lock := locksutil.LockForKey(b.roleLocks, item.Key)
	lock.Lock()
	defer lock.Unlock()

	// Validate the role still exists
	role, err := b.staticRole(ctx, s, item.Key)
	if err != nil {
		b.Logger().Error("unable to load role", "role", item.Key, "error", err)
		item.Priority = time.Now().Add(10 * time.Second).Unix()
		if err := b.pushItem(item); err != nil {
			b.Logger().Error("unable to push item on to queue", "error", err)
		}
		return true
	}
	if role == nil {
		b.Logger().Warn("role not found", "role", item.Key, "error", err)
		return true
	}

	// If "now" is less than the Item priority, then this item does not need to
	// be rotated
	if time.Now().Unix() < item.Priority {
		if err := b.pushItem(item); err != nil {
			b.Logger().Error("unable to push item on to queue", "error", err)
		}
		// Break out of the for loop
		return false
	}

	// Handle dual-account grace period expiry
	if role.StaticAccount.DualAccountMode && role.StaticAccount.RotationState == "grace_period" {
		if role.StaticAccount.GracePeriodEnd.IsZero() {
			b.Logger().Error("grace period end time is zero, recomputing from last rotation", "role", item.Key)
			role.StaticAccount.GracePeriodEnd = role.StaticAccount.LastVaultRotation.Add(role.StaticAccount.GracePeriod)
		}
		if time.Now().After(role.StaticAccount.GracePeriodEnd) {
			b.Logger().Info("grace period expired, transitioning to active state", "role", item.Key, "active_account", role.StaticAccount.ActiveAccount)

			role.StaticAccount.RotationState = "active"
			role.StaticAccount.GracePeriodEnd = time.Time{}

			entry, err := logical.StorageEntryJSON(staticRolePath+item.Key, role)
			if err != nil {
				b.Logger().Error("unable to persist grace period transition", "role", item.Key, "error", err)
				item.Priority = time.Now().Add(10 * time.Second).Unix()
				if err := b.pushItem(item); err != nil {
					b.Logger().Error("unable to push item on to queue", "error", err)
				}
				return true
			}
			if err := s.Put(ctx, entry); err != nil {
				b.Logger().Error("unable to persist grace period transition", "role", item.Key, "error", err)
				item.Priority = time.Now().Add(10 * time.Second).Unix()
				if err := b.pushItem(item); err != nil {
					b.Logger().Error("unable to push item on to queue", "error", err)
				}
				return true
			}

			// Schedule next rotation
			item.Priority = role.StaticAccount.NextVaultRotation.Unix()
			item.Value = ""
			if err := b.pushItem(item); err != nil {
				b.Logger().Error("unable to push item on to queue", "error", err)
			}
			b.Logger().Info("successfully transitioned from grace period to active", "role", item.Key)
			b.ldapEvent(ctx, "dual-account-grace-period-end", "", item.Key, true)
			return true
		}

		// Grace period not yet expired, re-queue at grace period end
		item.Priority = role.StaticAccount.GracePeriodEnd.Unix()
		if err := b.pushItem(item); err != nil {
			b.Logger().Error("unable to push item on to queue", "error", err)
		}
		return false
	}

	input := &setStaticAccountInput{
		RoleName: item.Key,
		Role:     role,
	}

	// If there is a WAL entry related to this Role, the corresponding WAL ID
	// should be stored in the Item's Value field.
	if walID, ok := item.Value.(string); ok {
		input.WALID = walID
	}

	resp, err := b.setStaticAccountPassword(ctx, s, input)
	if err != nil {
		b.Logger().Error("unable to rotate credentials in periodic function", "name", item.Key, "error", err)
		b.ldapEvent(ctx, "rotate-fail", "", item.Key, false)
		// Increment the priority enough so that the next call to this method
		// likely will not attempt to rotate it, as a back-off of sorts
		item.Priority = time.Now().Add(10 * time.Second).Unix()

		// Preserve the WALID if it was returned
		if resp != nil && resp.WALID != "" {
			item.Value = resp.WALID
		}

		if err := b.pushItem(item); err != nil {
			b.Logger().Error("unable to push item on to queue", "error", err)
		}
		// Go to next item
		return true
	}
	// Clear any stored WAL ID as we must have successfully deleted our WAL to get here.
	item.Value = ""

	lvr := resp.RotationTime
	if lvr.IsZero() {
		lvr = time.Now()
	}

	// For dual-account mode, after a successful rotation we enter grace period.
	// Schedule the queue item for the grace period end instead of the next
	// rotation time.
	if role.StaticAccount.DualAccountMode {
		item.Priority = role.StaticAccount.GracePeriodEnd.Unix()
	} else {
		// Update priority and push updated Item to the queue
		nextRotation := lvr.Add(role.StaticAccount.RotationPeriod)
		item.Priority = nextRotation.Unix()
	}
	if err := b.pushItem(item); err != nil {
		b.Logger().Warn("unable to push item on to queue", "error", err)
	}

	b.Logger().Info("successfully rotated in periodic function", "name", item.Key)
	b.ldapEvent(ctx, "rotate", "", item.Key, true)
	return true
}

// findStaticWAL loads a WAL entry by ID. If found, only return the WAL if it
// is of type staticWALKey, otherwise return nil
func (b *backend) findStaticWAL(ctx context.Context, s logical.Storage, id string) (*setCredentialsWAL, error) {
	wal, err := framework.GetWAL(ctx, s, id)
	if err != nil {
		return nil, err
	}

	if wal == nil || wal.Kind != staticWALKey {
		return nil, nil
	}

	walEntry := setCredentialsWAL{
		walID:        id,
		walCreatedAt: wal.CreatedAt,
	}
	d, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		DecodeHook: mapstructure.StringToTimeHookFunc(time.RFC3339),
		Result:     &walEntry,
	})
	if err != nil {
		return nil, err
	}
	err = d.Decode(wal.Data)
	if err != nil {
		return nil, err
	}

	return &walEntry, nil
}

type setStaticAccountInput struct {
	RoleName string
	Role     *roleEntry
	WALID    string
}

type setStaticAccountOutput struct {
	RotationTime time.Time
	// Optional return field, in the event WAL was created and not destroyed
	// during the operation
	WALID string
}

// setStaticAccountPassword sets the password for a static account associated with a
// Role. This method does many things:
// - verifies role exists and is in the allowed roles list
// - loads an existing WAL entry if WALID input is given, otherwise creates a
// new WAL entry
// - gets a database connection
// - accepts an input password, otherwise generates a new one via gRPC to the
// database plugin
// - sets new password for the static account
// - uses WAL for ensuring passwords are not lost if storage to Vault fails
//
// For dual-account mode, this method rotates the standby account's password
// and transitions the state machine accordingly.
//
// This method does not perform any operations on the priority queue. Those
// tasks must be handled outside of this method.
func (b *backend) setStaticAccountPassword(ctx context.Context, s logical.Storage, input *setStaticAccountInput) (*setStaticAccountOutput, error) {
	if input == nil || input.Role == nil || input.RoleName == "" {
		return nil, errors.New("input was empty when attempting to set credentials for static account")
	}

	if _, hasTimeout := ctx.Deadline(); !hasTimeout {
		var cancel func()
		ctx, cancel = context.WithTimeout(ctx, defaultCtxTimeout)
		defer cancel()
	}

	// Re-use WAL ID if present, otherwise PUT a new WAL
	output := &setStaticAccountOutput{WALID: input.WALID}

	b.Lock()
	defer b.Unlock()

	config, err := readConfig(ctx, s)
	if err != nil {
		return output, err
	}
	if config == nil {
		return output, errors.New("the config is currently unset")
	}

	// For dual-account mode, delegate to the dual-account rotation logic
	if input.Role.StaticAccount.DualAccountMode {
		return b.setDualAccountPassword(ctx, s, input, output, config)
	}

	var newPassword string
	var usedCredentialFromPreviousRotation bool
	if output.WALID != "" {
		wal, err := b.findStaticWAL(ctx, s, output.WALID)
		if err != nil {
			return output, fmt.Errorf("error retrieving WAL entry: %w", err)
		}

		switch {
		case wal == nil:
			b.Logger().Error("expected role to have WAL, but WAL not found in storage", "role", input.RoleName, "WAL ID", output.WALID)

			// Generate a new WAL entry and credential
			output.WALID = ""
		case wal.NewPassword != "" && wal.PasswordPolicy != config.PasswordPolicy:
			b.Logger().Debug("password policy changed, generating new password", "role", input.RoleName, "WAL ID", output.WALID)
			if err := framework.DeleteWAL(ctx, s, output.WALID); err != nil {
				b.Logger().Warn("failed to delete WAL", "error", err, "WAL ID", output.WALID)
			}

			// Generate a new WAL entry and credential
			output.WALID = ""
		default:
			// Reuse the password from the existing WAL entry
			newPassword = wal.NewPassword
			usedCredentialFromPreviousRotation = true
		}
	}

	if output.WALID == "" {
		newPassword, err = b.GeneratePassword(ctx, config)
		if err != nil {
			return output, err
		}
		output.WALID, err = framework.PutWAL(ctx, s, staticWALKey, &setCredentialsWAL{
			RoleName:          input.RoleName,
			Username:          input.Role.StaticAccount.Username,
			DN:                input.Role.StaticAccount.DN,
			NewPassword:       newPassword,
			LastVaultRotation: input.Role.StaticAccount.LastVaultRotation,
			PasswordPolicy:    config.PasswordPolicy,
		})
		b.Logger().Debug("wrote WAL", "role", input.RoleName, "WAL ID", output.WALID)
		if err != nil {
			return output, fmt.Errorf("error writing WAL entry: %w", err)
		}
	}

	if newPassword == "" {
		b.Logger().Error("newPassword was empty, re-generating based on the password policy")
		newPassword, err = b.GeneratePassword(ctx, config)
		if err != nil {
			return output, err
		}
	}

	// Perform the LDAP search with the DN if it's configured. DN-based search
	// targets the object directly. Otherwise, search using the userdn, userattr,
	// and username. UserDN-based search targets the object by searching the whole
	// subtree rooted at the userDN.
	if input.Role.StaticAccount.DN != "" {
		err = b.client.UpdateDNPassword(config.LDAP, input.Role.StaticAccount.DN, newPassword)
	} else {
		err = b.client.UpdateUserPassword(config.LDAP, input.Role.StaticAccount.Username, newPassword)
	}
	if err != nil {
		if usedCredentialFromPreviousRotation {
			b.Logger().Debug("password stored in WAL failed, deleting WAL", "role", input.RoleName, "WAL ID", output.WALID)
			if err := framework.DeleteWAL(ctx, s, output.WALID); err != nil {
				b.Logger().Warn("failed to delete WAL", "error", err, "WAL ID", output.WALID)
			}

			// Generate a new WAL entry and credential for next attempt
			output.WALID = ""
		}

		return output, err
	}

	// Store updated role information
	// lvr is the known LastVaultRotation
	lvr := time.Now()
	input.Role.StaticAccount.LastVaultRotation = lvr
	input.Role.StaticAccount.SetNextVaultRotation(lvr)
	input.Role.StaticAccount.LastPassword = input.Role.StaticAccount.Password
	input.Role.StaticAccount.Password = newPassword
	output.RotationTime = lvr

	entry, err := logical.StorageEntryJSON(staticRolePath+input.RoleName, input.Role)
	if err != nil {
		return output, err
	}
	if err := s.Put(ctx, entry); err != nil {
		return output, err
	}

	// Cleanup WAL after successfully rotating and pushing new item on to queue
	if err := framework.DeleteWAL(ctx, s, output.WALID); err != nil {
		b.Logger().Warn("error deleting WAL", "WAL ID", output.WALID, "error", err)
		return output, err
	}
	b.Logger().Debug("deleted WAL", "WAL ID", output.WALID)

	// The WAL has been deleted, return new setStaticAccountOutput without it
	return &setStaticAccountOutput{RotationTime: lvr}, nil
}

// setDualAccountPassword handles password rotation for dual-account mode roles.
// The rotation state machine works as follows:
//
// State: "active" - One account is active, the other is standby.
//   - On rotation trigger: rotate the standby account's password, then
//     transition to "grace_period" state with the NEW standby becoming the
//     active account.
//
// State: "grace_period" - Both accounts' credentials are returned.
//   - On grace period expiry: transition back to "active" state.
func (b *backend) setDualAccountPassword(ctx context.Context, s logical.Storage, input *setStaticAccountInput, output *setStaticAccountOutput, config *config) (*setStaticAccountOutput, error) {
	sa := input.Role.StaticAccount

	// On initial creation, both accounts need passwords. Check if either
	// account has no password set.
	isInitialSetup := sa.Password == "" || sa.PasswordB == ""

	if isInitialSetup {
		// Generate and set passwords for both accounts
		passwordA, err := b.GeneratePassword(ctx, config)
		if err != nil {
			return output, err
		}
		passwordB, err := b.GeneratePassword(ctx, config)
		if err != nil {
			return output, err
		}

		// Create WAL for initial setup (includes both accounts for crash recovery)
		if output.WALID == "" {
			output.WALID, err = framework.PutWAL(ctx, s, staticWALKey, &setCredentialsWAL{
				RoleName:          input.RoleName,
				Username:          sa.Username,
				DN:                sa.DN,
				NewPassword:       passwordA,
				UsernameB:         sa.UsernameB,
				DNB:               sa.DNB,
				NewPasswordB:      passwordB,
				LastVaultRotation: sa.LastVaultRotation,
				PasswordPolicy:    config.PasswordPolicy,
			})
			if err != nil {
				return output, fmt.Errorf("error writing WAL entry for dual-account initial setup: %w", err)
			}
		}

		// Rotate account A
		if sa.DN != "" {
			err = b.client.UpdateDNPassword(config.LDAP, sa.DN, passwordA)
		} else {
			err = b.client.UpdateUserPassword(config.LDAP, sa.Username, passwordA)
		}
		if err != nil {
			return output, fmt.Errorf("failed to set initial password for account A: %w", err)
		}

		// Rotate account B
		if sa.DNB != "" {
			err = b.client.UpdateDNPassword(config.LDAP, sa.DNB, passwordB)
		} else {
			err = b.client.UpdateUserPassword(config.LDAP, sa.UsernameB, passwordB)
		}
		if err != nil {
			return output, fmt.Errorf("failed to set initial password for account B: %w", err)
		}

		lvr := time.Now()
		sa.Password = passwordA
		sa.PasswordB = passwordB
		sa.LastVaultRotation = lvr
		sa.LastRotationB = lvr
		sa.SetNextVaultRotation(lvr)
		sa.ActiveAccount = "a"
		sa.RotationState = "active"
		output.RotationTime = lvr

		// Persist the updated role
		entry, err := logical.StorageEntryJSON(staticRolePath+input.RoleName, input.Role)
		if err != nil {
			return output, err
		}
		if err := s.Put(ctx, entry); err != nil {
			return output, err
		}

		// Cleanup WAL
		if err := framework.DeleteWAL(ctx, s, output.WALID); err != nil {
			b.Logger().Warn("error deleting WAL for dual-account initial setup", "WAL ID", output.WALID, "error", err)
			return output, err
		}

		return &setStaticAccountOutput{RotationTime: lvr}, nil
	}

	// Normal rotation: rotate the standby account's password
	var standbyDN, standbyUsername string
	if sa.ActiveAccount == "a" {
		standbyDN = sa.DNB
		standbyUsername = sa.UsernameB
	} else {
		standbyDN = sa.DN
		standbyUsername = sa.Username
	}

	// Reuse password from existing WAL if available (crash recovery)
	var newPassword string
	var err error
	if output.WALID != "" {
		wal, walErr := b.findStaticWAL(ctx, s, output.WALID)
		if walErr != nil {
			return output, fmt.Errorf("error retrieving WAL entry for dual-account rotation: %w", walErr)
		}

		switch {
		case wal == nil:
			b.Logger().Error("expected role to have WAL, but WAL not found in storage", "role", input.RoleName, "WAL ID", output.WALID)
			output.WALID = ""
		case wal.NewPassword != "" && wal.PasswordPolicy != config.PasswordPolicy:
			b.Logger().Debug("password policy changed, generating new password for dual-account rotation", "role", input.RoleName, "WAL ID", output.WALID)
			if err := framework.DeleteWAL(ctx, s, output.WALID); err != nil {
				b.Logger().Warn("failed to delete WAL", "error", err, "WAL ID", output.WALID)
			}
			output.WALID = ""
		default:
			newPassword = wal.NewPassword
		}
	}

	if newPassword == "" {
		newPassword, err = b.GeneratePassword(ctx, config)
		if err != nil {
			return output, err
		}
	}

	// Create WAL entry for the dual-account rotation
	if output.WALID == "" {
		output.WALID, err = framework.PutWAL(ctx, s, staticWALKey, &setCredentialsWAL{
			RoleName:          input.RoleName,
			Username:          standbyUsername,
			DN:                standbyDN,
			NewPassword:       newPassword,
			LastVaultRotation: sa.LastVaultRotation,
			PasswordPolicy:    config.PasswordPolicy,
		})
		if err != nil {
			return output, fmt.Errorf("error writing WAL entry for dual-account rotation: %w", err)
		}
		b.Logger().Debug("wrote WAL for dual-account rotation", "role", input.RoleName, "WAL ID", output.WALID, "standby_account", standbyUsername)
	}

	// Rotate the standby account's password in LDAP
	if standbyDN != "" {
		err = b.client.UpdateDNPassword(config.LDAP, standbyDN, newPassword)
	} else {
		err = b.client.UpdateUserPassword(config.LDAP, standbyUsername, newPassword)
	}
	if err != nil {
		return output, fmt.Errorf("failed to rotate standby account password: %w", err)
	}

	// Update the role state
	lvr := time.Now()
	if sa.ActiveAccount == "a" {
		// Rotated account B (standby), now B becomes active
		sa.LastPasswordB = sa.PasswordB
		sa.PasswordB = newPassword
		sa.LastRotationB = lvr
		sa.ActiveAccount = "b"
	} else {
		// Rotated account A (standby), now A becomes active
		sa.LastPassword = sa.Password
		sa.Password = newPassword
		sa.LastRotationB = lvr
		sa.ActiveAccount = "a"
	}

	sa.LastVaultRotation = lvr
	sa.SetNextVaultRotation(lvr)
	sa.RotationState = "grace_period"
	sa.GracePeriodEnd = lvr.Add(sa.GracePeriod)
	output.RotationTime = lvr

	// Persist the updated role
	entry, err := logical.StorageEntryJSON(staticRolePath+input.RoleName, input.Role)
	if err != nil {
		return output, err
	}
	if err := s.Put(ctx, entry); err != nil {
		return output, err
	}

	// Cleanup WAL
	if err := framework.DeleteWAL(ctx, s, output.WALID); err != nil {
		b.Logger().Warn("error deleting WAL for dual-account rotation", "WAL ID", output.WALID, "error", err)
		return output, err
	}
	b.Logger().Debug("deleted WAL for dual-account rotation", "WAL ID", output.WALID)

	return &setStaticAccountOutput{RotationTime: lvr}, nil
}

func (b *backend) GeneratePassword(ctx context.Context, cfg *config) (string, error) {
	if cfg.PasswordPolicy == "" {
		if cfg.PasswordLength == 0 {
			return base62.Random(defaultPasswordLength)
		}
		return base62.Random(cfg.PasswordLength)
	}

	password, err := b.System().GeneratePasswordFromPolicy(ctx, cfg.PasswordPolicy)
	if err != nil {
		return "", fmt.Errorf("unable to generate password: %w", err)
	}
	return password, nil
}

// initQueue preforms the necessary checks and initializations needed to preform
// automatic credential rotation for roles associated with static accounts. This
// method verifies if a queue is needed (primary server or local mount), and if
// so initializes the queue and launches a go-routine to periodically invoke a
// method to preform the rotations.
//
// initQueue is invoked by the Factory method in a go-routine. The Factory does
// not wait for success or failure of it's tasks before continuing. This is to
// avoid blocking the mount process while loading and evaluating existing roles,
// etc.
func (b *backend) initQueue(ctx context.Context, conf *logical.InitializationRequest, staticRoles map[string]*roleEntry) {
	// Verify this mount is on the primary server, or is a local mount. If not, do
	// not create a queue or launch a ticker. Both processing the WAL list and
	// populating the queue are done sequentially and before launching a
	// go-routine to run the periodic ticker.
	replicationState := b.System().ReplicationState()
	if (b.System().LocalMount() || !replicationState.HasState(consts.ReplicationPerformanceSecondary)) &&
		!replicationState.HasState(consts.ReplicationDRSecondary) &&
		!replicationState.HasState(consts.ReplicationPerformanceStandby) {
		b.Logger().Info("initializing database rotation queue")

		// Load roles and populate queue with static accounts
		b.populateQueue(ctx, conf.Storage, staticRoles)

		// Launch ticker
		go b.runTicker(ctx, conf.Storage)
	}
}

// loadStaticWALs reads WAL entries and returns a map of roles and their
// setCredentialsWAL, if found.
func (b *backend) loadStaticWALs(ctx context.Context, s logical.Storage) (map[string]*setCredentialsWAL, error) {
	keys, err := framework.ListWAL(ctx, s)
	if err != nil {
		return nil, err
	}
	if len(keys) == 0 {
		b.Logger().Debug("no WAL entries found")
		return nil, nil
	}

	walMap := make(map[string]*setCredentialsWAL)
	// Loop through WAL keys and process any rotation ones
	for _, walID := range keys {
		walEntry, err := b.findStaticWAL(ctx, s, walID)
		if err != nil {
			b.Logger().Error("error loading static WAL", "id", walID, "error", err)
			continue
		}
		if walEntry == nil {
			continue
		}

		// Verify the static role still exists
		roleName := walEntry.RoleName
		role, err := b.staticRole(ctx, s, roleName)
		if err != nil {
			b.Logger().Warn("unable to read static role", "error", err, "role", roleName)
			continue
		}
		if role == nil || role.StaticAccount == nil {
			b.Logger().Debug("deleting WAL with nil role or static account", "WAL ID", walEntry.walID)
			if err := framework.DeleteWAL(ctx, s, walEntry.walID); err != nil {
				b.Logger().Warn("unable to delete WAL", "error", err, "WAL ID", walEntry.walID)
			}
			continue
		}

		if existingWALEntry, exists := walMap[walEntry.RoleName]; exists {
			b.Logger().Debug("multiple WALs detected for role", "role", walEntry.RoleName,
				"loaded WAL ID", existingWALEntry.walID, "created at", existingWALEntry.walCreatedAt, "last vault rotation", existingWALEntry.LastVaultRotation,
				"candidate WAL ID", walEntry.walID, "created at", walEntry.walCreatedAt, "last vault rotation", walEntry.LastVaultRotation)

			if walEntry.walCreatedAt > existingWALEntry.walCreatedAt {
				// If the existing WAL is older, delete it from storage and fall
				// through to inserting our current WAL into the map.
				b.Logger().Debug("deleting stale loaded WAL", "WAL ID", existingWALEntry.walID)
				err = framework.DeleteWAL(ctx, s, existingWALEntry.walID)
				if err != nil {
					b.Logger().Warn("unable to delete loaded WAL", "error", err, "WAL ID", existingWALEntry.walID)
				}
			} else {
				// If we already have a more recent WAL entry in the map, delete
				// this one and continue onto the next WAL.
				b.Logger().Debug("deleting stale candidate WAL", "WAL ID", walEntry.walID)
				err = framework.DeleteWAL(ctx, s, walID)
				if err != nil {
					b.Logger().Warn("unable to delete candidate WAL", "error", err, "WAL ID", walEntry.walID)
				}
				continue
			}
		}

		b.Logger().Debug("loaded WAL", "WAL ID", walID)
		walMap[walEntry.RoleName] = walEntry
	}
	return walMap, nil
}

// pushItem wraps the internal queue's Push call, to make sure a queue is
// actually available. This is needed because both runTicker and initQueue
// operate in go-routines, and could be accessing the queue concurrently
func (b *backend) pushItem(item *queue.Item) error {
	b.RLock()
	defer b.RUnlock()

	if b.credRotationQueue != nil {
		return b.credRotationQueue.Push(item)
	}

	b.Logger().Warn("no queue found during push item")
	return nil
}

// popFromRotationQueue wraps the internal queue's Pop call, to make sure a queue is
// actually available. This is needed because both runTicker and initQueue
// operate in go-routines, and could be accessing the queue concurrently
func (b *backend) popFromRotationQueue() (*queue.Item, error) {
	b.RLock()
	defer b.RUnlock()
	if b.credRotationQueue != nil {
		return b.credRotationQueue.Pop()
	}
	return nil, queue.ErrEmpty
}

// popFromRotationQueueByKey wraps the internal queue's PopByKey call, to make sure a queue is
// actually available. This is needed because both runTicker and initQueue
// operate in go-routines, and could be accessing the queue concurrently
func (b *backend) popFromRotationQueueByKey(name string) (*queue.Item, error) {
	b.RLock()
	defer b.RUnlock()
	if b.credRotationQueue != nil {
		item, err := b.credRotationQueue.PopByKey(name)
		if err != nil {
			return nil, err
		}
		if item != nil {
			return item, nil
		}
	}
	return nil, queue.ErrEmpty
}
