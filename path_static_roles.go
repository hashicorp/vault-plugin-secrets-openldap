// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: MPL-2.0

package openldap

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/automatedrotationutil"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/hashicorp/vault/sdk/rotation"
)

const (
	staticRolePath = "static-role/"
)

// genericNameWithForwardSlashRegex is a regex which requires a role name. The
// role name can include any number of alphanumeric characters separated by
// forward slashes.
func genericNameWithForwardSlashRegex(name string) string {
	return fmt.Sprintf(`(/(?P<%s>\w(([\w-./]+)?\w)?))`, name)
}

// optionalGenericNameWithForwardSlashListRegex is a regex for optionally
// including a role path in list options. The role path can be used to list
// nested roles at arbitrary depth.
func optionalGenericNameWithForwardSlashListRegex(name string) string {
	return fmt.Sprintf("/?(?P<%s>.+)?", name)
}

func (b *backend) pathListStaticRoles() []*framework.Path {
	return []*framework.Path{
		{
			Pattern: strings.TrimSuffix(staticRolePath, "/") + optionalGenericNameWithForwardSlashListRegex("path"),
			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: operationPrefixLDAP,
				OperationVerb:   "list",
				OperationSuffix: "static-roles",
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{
					Callback: b.pathStaticRoleList,
				},
			},
			Fields: map[string]*framework.FieldSchema{
				"path": {
					Type:        framework.TypeLowerCaseString,
					Description: "Path of roles to list",
				},
			},
			HelpSynopsis:    staticRolesListHelpSynopsis,
			HelpDescription: staticRolesListHelpDescription,
		},
	}
}

func (b *backend) pathStaticRoles() []*framework.Path {
	return []*framework.Path{
		{
			Pattern: strings.TrimSuffix(staticRolePath, "/") + genericNameWithForwardSlashRegex("name"),
			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: operationPrefixLDAP,
				OperationSuffix: "static-role",
			},
			Fields:         fieldsForType(staticRolePath),
			ExistenceCheck: b.pathStaticRoleExistenceCheck,
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.UpdateOperation: &framework.PathOperation{
					Callback:                    b.pathStaticRoleCreateUpdate,
					ForwardPerformanceStandby:   true,
					ForwardPerformanceSecondary: true,
				},
				logical.CreateOperation: &framework.PathOperation{
					Callback:                    b.pathStaticRoleCreateUpdate,
					ForwardPerformanceStandby:   true,
					ForwardPerformanceSecondary: true,
				},
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.pathStaticRoleRead,
				},
				logical.DeleteOperation: &framework.PathOperation{
					Callback:                    b.pathStaticRoleDelete,
					ForwardPerformanceStandby:   true,
					ForwardPerformanceSecondary: true,
				},
			},
			HelpSynopsis:    staticRoleHelpSynopsis,
			HelpDescription: staticRoleHelpDescription,
		},
	}
}

// fieldsForType returns a map of string/FieldSchema items for the given role
// type. The purpose is to keep the shared fields between dynamic and static
// roles consistent, and allow for each type to override or provide their own
// specific fields
func fieldsForType(roleType string) map[string]*framework.FieldSchema {
	fields := map[string]*framework.FieldSchema{
		"name": {
			Type:        framework.TypeLowerCaseString,
			Description: "Name of the role",
		},
		"username": {
			Type:        framework.TypeString,
			Description: "The username/logon name for the entry with which this role will be associated.",
		},
		"dn": {
			Type:        framework.TypeString,
			Description: "The distinguished name of the entry to manage.",
		},
	}

	// Get the fields that are specific to the type of role, and add them to the
	// common fields. In the future we can add additional for dynamic roles.
	var typeFields map[string]*framework.FieldSchema
	switch roleType {
	case staticRolePath:
		typeFields = staticFields()
	}

	for k, v := range typeFields {
		fields[k] = v
	}

	return fields
}

// staticFields returns a map of key and field schema items that are specific
// only to static roles
func staticFields() map[string]*framework.FieldSchema {
	fields := map[string]*framework.FieldSchema{
		"password": {
			Type:        framework.TypeString,
			Description: "Password for the static role. This is required for Vault to manage an existing account and enable rotation.",
			DisplayAttrs: &framework.DisplayAttributes{
				Sensitive: true,
			},
		},
		"skip_import_rotation": {
			Type:        framework.TypeBool,
			Description: "Skip the initial pasword rotation on import (has no effect on updates)",
		},
	}

	automatedrotationutil.AddAutomatedRotationFields(fields)

	return fields
}

func (b *backend) pathStaticRoleExistenceCheck(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
	role, err := b.staticRole(ctx, req.Storage, data.Get("name").(string))
	if err != nil {
		return false, err
	}
	return role != nil, nil
}

func (b *backend) pathStaticRoleDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name := data.Get("name").(string)

	role, err := b.staticRole(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return nil, nil
	}

	err = req.Storage.Delete(ctx, staticRolePath+name)
	if err != nil {
		return nil, err
	}

	b.managedUserLock.Lock()
	defer b.managedUserLock.Unlock()
	delete(b.managedUsers, role.StaticAccount.Username)
	delete(b.managedUsers, role.StaticAccount.DN)

	if role.HasNonzeroRotationValues() {
		deregisterReq := &rotation.RotationJobDeregisterRequest{
			MountPoint: req.MountPoint,
			ReqPath:    req.Path,
		}
		err := b.System().DeregisterRotationJob(ctx, deregisterReq)
		if err != nil {
			b.Logger().Error("static role was deleted but error was encountered when deregistering rotation job: %s", err)
		}
	}

	// Send event notification for static role delete
	b.ldapEvent(ctx, "static-role-delete", req.Path, name, true)

	return nil, err
}

func (b *backend) pathStaticRoleRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)
	role, err := b.staticRole(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return nil, nil
	}

	data := map[string]interface{}{
		"dn":       role.StaticAccount.DN,
		"username": role.StaticAccount.Username,
	}

	role.PopulateAutomatedRotationData(data)

	role.PopulateRotationInfo(data)
	if data["last_vault_rotation"] == nil {
		data["last_vault_rotation"] = time.Time{}
	}

	return &logical.Response{Data: data}, nil
}

func (b *backend) pathStaticRoleCreateUpdate(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	cfg, err := readConfig(ctx, req.Storage)
	if cfg == nil {
		// MountPoint already has a / appended.
		return logical.ErrorResponse("missing plugin configuration for path %s%s", req.MountPoint, req.Path), nil
	}
	if err != nil {
		return nil, err
	}

	name := data.Get("name").(string)

	role, err := b.staticRole(ctx, req.Storage, data.Get("name").(string))
	if err != nil {
		return nil, err
	}

	if role == nil {
		role = &roleEntry{
			StaticAccount: &staticAccount{},
		}
	}

	isCreate := req.Operation == logical.CreateOperation

	b.managedUserLock.Lock()
	defer b.managedUserLock.Unlock()

	// Username is required for static roles in all cases.
	usernameRaw, ok := data.GetOk("username")
	if !ok && isCreate {
		return logical.ErrorResponse("username is a required field to manage a static role"), nil
	}
	if ok {
		username := usernameRaw.(string)
		if username == "" {
			return logical.ErrorResponse("username must not be empty for static roles"), nil
		}
		if _, exists := b.managedUsers[username]; exists && isCreate {
			return logical.ErrorResponse("username %q is already managed by the secrets engine", username), nil
		}
		if !isCreate && username != role.StaticAccount.Username {
			return logical.ErrorResponse("cannot update static role username"), nil
		}

		role.StaticAccount.Username = username
	}

	// For non-self-managed roles: DN is optional unless it is unset via providing the empty string. It
	// cannot be modified after creation. If given, it will take precedence over the username for LDAP
	// searching during a password rotation.
	// For self-managed roles: DN is a required field as search cananot be done with the root account
	// because it may not be configured with a root bindpass. It cannot be modified after creation.
	dnRaw, ok := data.GetOk("dn")
	if !ok && isCreate && role.StaticAccount.SelfManaged {
		return logical.ErrorResponse("dn is a required field for a self-managed static role"), nil
	}
	if ok {
		dn := dnRaw.(string)
		if dn == "" && role.StaticAccount.SelfManaged {
			return logical.ErrorResponse("dn must not be empty for self-managed static roles"), nil
		}
		if _, exists := b.managedUsers[dn]; exists && isCreate {
			return logical.ErrorResponse("dn %q is already managed by the secrets engine", dn), nil
		}
		if !isCreate && dn != role.StaticAccount.DN {
			return logical.ErrorResponse("cannot update static role dn"), nil
		}
		role.StaticAccount.DN = dn
	}

	// For non-self-managed roles: Password is optional. It can be provided as a starting password for users
	// onboarding accounts into Vault.
	// For self-managed roles: Password is required on creation so the role may manage itself.
	// For both: Password can be updated to allow users to fix passwords that may have been changed out of
	// band from Vault.

	passwordRaw, ok := data.GetOk("password")
	if !ok && isCreate && role.StaticAccount.SelfManaged {
		return logical.ErrorResponse("password is a required field for a self-managed static role"), nil
	}
	if ok {
		password := passwordRaw.(string)
		if role.StaticAccount.SelfManaged && password == "" {
			// Don't allow an empty password for self-managed accounts
			return logical.ErrorResponse("password must not be empty for self-managed static roles"), nil
		} else if password != "" {
			role.StaticAccount.Password = password
		}
	}

	if err := role.ParseAutomatedRotationFields(data); err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}

	if !role.HasNonzeroRotationValues() {
		return logical.ErrorResponse("either rotation_period or rotation_schedule must be set for static roles"), nil
	}

	skipImportRotation := false
	skipRotationRaw, ok := data.GetOk("skip_import_rotation")
	if ok {
		// if skip_import_rotation was set, use it (or validation error on an update)
		if !isCreate {
			return logical.ErrorResponse("skip_import_rotation has no effect on updates"), nil
		}
		skipImportRotation = skipRotationRaw.(bool)
	} else if isCreate {
		skipImportRotation = cfg.SkipStaticRoleImportRotation
	}

	var rotOp string
	var info *rotation.RotationInfo
	if role.ShouldDeregisterRotationJob() {
		rotOp = rotation.PerformedDeregistration
		deregisterReq := &rotation.RotationJobDeregisterRequest{
			MountPoint: req.MountPoint,
			ReqPath:    req.Path,
		}
		err := b.System().DeregisterRotationJob(ctx, deregisterReq)
		if err != nil {
			return logical.ErrorResponse("error deregistering rotation job: %s", err), nil
		}
	} else if role.ShouldRegisterRotationJob() {
		rotOp = rotation.PerformedRegistration
		req := &rotation.RotationJobConfigureRequest{
			MountPoint:       req.MountPoint,
			ReqPath:          req.Path,
			RotationSchedule: role.RotationSchedule,
			RotationWindow:   role.RotationWindow,
			RotationPeriod:   role.RotationPeriod,
			RotationPolicy:   role.RotationPolicy,
		}

		resp, err := b.System().RegisterRotationJobWithResponse(ctx, req)
		if err != nil {
			return logical.ErrorResponse("error registering rotation job: %s", err), nil
		}
		role.SetRotationInfo(resp)

		info = resp
	}

	entry, err := logical.StorageEntryJSON(staticRolePath+name, role)
	if err != nil {
		return nil, err
	}

	if err := req.Storage.Put(ctx, entry); err != nil {
		wrappedError := err
		b.Logger().Error("write to storage failed but the rotation manager still succeeded.",
			"operation", rotOp, "mount", req.MountPoint, "path", req.Path)
		wrappedError = fmt.Errorf("write to storage failed but the rotation manager still succeeded; "+
			"operation=%s, mount=%s, path=%s, storageError=%s", rotOp, req.MountPoint, req.Path, err)

		return nil, wrappedError
	}

	b.managedUsers[role.StaticAccount.Username] = struct{}{}
	b.managedUsers[role.StaticAccount.DN] = struct{}{}

	// Send event notification for static role create/update
	b.ldapEvent(ctx, fmt.Sprintf("static-role-%s", req.Operation), req.Path, name, true)

	if !skipImportRotation && isCreate {
		req.RotationInfo = info
		err := b.rotateStaticCredential(ctx, req, name)
		if err != nil {
			b.Logger().Error("successfully created static role but failed to rotate the credential upon import", role, "name", req.MountPoint, "path", req.Path)
		}
	}

	return nil, nil
}

type roleEntry struct {
	StaticAccount *staticAccount `json:"static_account" mapstructure:"static_account"`
	automatedrotationutil.AutomatedRotationParams
	automatedrotationutil.WALHandlingParams
}

type staticAccount struct {
	// DN to create or assume management for static accounts
	DN string `json:"dn"`

	// Username to create or assume management for static accounts
	Username string `json:"username"`

	// Password is the current password for static accounts. As an input, this is
	// used/required when trying to assume management of an existing static
	// account. This is returned on credential requests if it exists.
	Password string `json:"password"`

	// LastPassword is the prior password after a rotation for static accounts.
	// This is returned on credential requests if it exists.
	LastPassword string `json:"last_password"`

	// Internal flag for whether this static account is self-managed. Will be true for all
	// accounts if the mount is configured as self-managed. Remove from reads.
	SelfManaged bool `json:"self_managed,omitempty"`
}

func (b *backend) pathStaticRoleList(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	rolePath := data.Get("path").(string)
	roles, err := req.Storage.List(ctx, staticRolePath+rolePath)
	if err != nil {
		return nil, fmt.Errorf("failed to list roles: %w", err)
	}
	return logical.ListResponse(roles), nil
}

func (b *backend) staticRole(ctx context.Context, s logical.Storage, roleName string) (*roleEntry, error) {
	completeRole := staticRolePath + roleName
	entry, err := s.Get(ctx, completeRole)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}

	var result roleEntry
	if err := entry.DecodeJSON(&result); err != nil {
		return nil, err
	}

	return &result, nil
}

const staticRoleHelpSynopsis = `
Manage the static roles that can be created with this backend.
`

const staticRoleHelpDescription = `
This path lets you manage the static roles that can be created with this
backend. Static Roles are associated with a single LDAP entry, and manage the
password based on a rotation period, automatically rotating the password.

The "username" parameter is required and configures the username for the LDAP entry. 
This is helpful to provide a usable name when distinguished name (DN) isn't used 
directly for authentication. If DN not provided, "username" will be used for LDAP 
subtree search, rooted at the "userdn" configuration value. The name attribute to use 
when searching for the user can be configured with the "userattr" configuration value.

The "dn" parameter is optional for non-self-managed roles and configures the distinguished
name to use when managing the existing entry. If the "dn" parameter is set, it will take 
precedence over the "username" when LDAP searches are performed.
This parameter is required if "self_managed" is true for self-managed static roles.

The "skip_import_rotation" parameter is optional and only has effect during role creation. 
If true, Vault will skip the initial password rotation when creating the role, and will manage
the existing password. If false (the default), Vault will rotate the password when the role is
created. This parameter has no effect during role updates.

The "self_managed" parameter is optional and indicates whether the role manages its own password
rotation. If true, Vault will perform rotations by authenticating as this account using its current
password (no privileged bind DN). This requires the "password" parameter to be set on creation, and
the "dn" parameter to be set as well. This field is immutable after creation. If false (the default),
Vault will use the configured bind DN to perform rotations.

The "password" parameter configures the current password for the entry is required only if the plugin
was configured with the field "self_managed" as true. "Password" is optional when using
non-self-managed roles and can be used to set an initial password for the role. This allows
Vault to assume management of an existing account. The password will be rotated on creation unless 
the "skip_import_rotation" parameter is set to true. The password is not returned in read operations.
`

const staticRolesListHelpDescription = `
List all the static roles being managed by Vault.
`

const staticRolesListHelpSynopsis = `
This path lists all the static roles Vault is currently managing within the LDAP system.
`
