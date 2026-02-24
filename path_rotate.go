// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: MPL-2.0

package openldap

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/vault/sdk/atomicrotationhelpers"
	"github.com/hashicorp/vault/sdk/helper/automatedrotationutil"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/backoff"
	"github.com/hashicorp/vault/sdk/logical"
)

var (
	rollbackAttempts    = 10
	minRollbackDuration = 1 * time.Second
	maxRollbackDuration = 100 * time.Second
)

const (
	rotateRootPath = "rotate-root"
	rotateRolePath = "rotate-role/"
)

func (b *backend) pathRotateCredentials() []*framework.Path {
	return []*framework.Path{
		{
			Pattern: rotateRootPath,
			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: operationPrefixLDAP,
				OperationVerb:   "rotate",
				OperationSuffix: "root-credentials",
			},
			Fields: map[string]*framework.FieldSchema{},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.UpdateOperation: &framework.PathOperation{
					Callback:                    b.pathRotateRootCredentialsUpdate,
					ForwardPerformanceStandby:   true,
					ForwardPerformanceSecondary: true,
				},
			},
			HelpSynopsis: "Request to rotate the root credentials Vault uses for the LDAP administrator account.",
			HelpDescription: "This path attempts to rotate the root credentials of the administrator account " +
				"(binddn) used by Vault to manage LDAP.",
		},
		{
			Pattern: strings.TrimSuffix(rotateRolePath, "/") + genericNameWithForwardSlashRegex("name"),
			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: operationPrefixLDAP,
				OperationVerb:   "rotate",
				OperationSuffix: "static-role",
			},
			Fields: fieldsForType(rotateRolePath),
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.UpdateOperation: &framework.PathOperation{
					Callback:                    b.pathRotateRoleCredentialsUpdate,
					ForwardPerformanceStandby:   true,
					ForwardPerformanceSecondary: true,
				},
			},
			HelpSynopsis:    "Request to rotate the credentials for a static user account.",
			HelpDescription: "This path attempts to rotate the credentials for the given LDAP static user account.",
		},
	}
}

func (b *backend) pathRotateRootCredentialsUpdate(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	err := b.rotateRootCredential(ctx, req)
	if err != nil {
		b.Logger().Error("failed to rotate root credential on user request", "path", req.Path, "error", err.Error())
		b.ldapEvent(ctx, "root-rotate-fail", req.Path, "", false)
	} else {
		b.Logger().Info("succesfully rotated root credential on user request", "path", req.Path)
		b.ldapEvent(ctx, "root-rotate", req.Path, "", true)
	}

	return nil, err
}

func (b *backend) rotateCredentialCallback(ctx context.Context, req *logical.Request) error {
	switch {
	case req.Path == configPath:
		return b.rotateRootCredential(ctx, req)

	case strings.HasPrefix(req.Path, staticRolePath):
		name := strings.TrimPrefix(req.Path, staticRolePath)
		return b.rotateStaticCredential(ctx, req, name)

	default:
		return fmt.Errorf("unrecognized path for rotation manager callback: %s", req.Path)
	}
}

func (b *backend) rotateStaticCredential(ctx context.Context, req *logical.Request, name string) (err error) {
	defer func() {
		if err != nil {
			b.ldapEvent(ctx, "rotate-fail", req.Path, name, false)
		} else {
			b.ldapEvent(ctx, "rotate", req.Path, name, true)
		}
	}()

	cfg, err := readConfig(ctx, req.Storage)
	if err != nil {
		return fmt.Errorf("unable to read root config for credential rotation: %w", err)
	}

	role, err := b.staticRole(ctx, req.Storage, name)
	if err != nil {
		return err
	}
	if role == nil {
		return fmt.Errorf("role doesn't exist: %s", name)
	}

	role.WALHandlingParams = automatedrotationutil.WALHandlingParams{
		RoleName: name,
		RolePath: staticRolePath + name,
		WALID:    role.WALID,
	}

	handler := atomicrotationhelpers.AtomicStaticCredentialRotationHandler{
		PluginBackend:        b.Backend,
		CredentialGenerator:  b.GenerateCredential,
		ExternalSystemClient: b.UpdateExternalCredential,
		ConfigStore:          b.SetCredential,

		Config: cfg,
		Role:   role,
	}

	if req.RotationInfo != nil {
		handler.RotationInfo = req.RotationInfo
	}
	resp, rotateErr := handler.SetStaticAccountCredential(ctx, req.Storage, &role.WALHandlingParams, cfg.PasswordPolicy)
	if rotateErr != nil {
		b.Logger().Error("unable to rotate credentials in periodic function", "name", name, "error", rotateErr)

		// Preserve the WALID if it was returned
		if resp != nil && resp.WALID != "" {
			role.WALID = resp.WALID
		}

		// store updated Role
		entry, err := logical.StorageEntryJSON(role.RolePath, role)
		if err != nil {
			// send error to RM so that the rotation can be re-tried and re-stored, but log the storage error
			b.Logger().Error("unable to create storage entry", "name", name, "error", err)

			return err
		}
		if err := req.Storage.Put(ctx, entry); err != nil {
			// send error to RM so that the rotation can be re-tried and re-stored, but log the storage error
			b.Logger().Error("unable to store updated role with WALID after rotation failure", "name", name, "error", err)

			return err
		}

		return rotateErr
	} else {
		// TODO clear WALID if needed
	}

	return nil
}

func (b *backend) rotateRootCredential(ctx context.Context, req *logical.Request) error {
	if _, hasTimeout := ctx.Deadline(); !hasTimeout {
		var cancel func()
		ctx, cancel = context.WithTimeout(ctx, defaultCtxTimeout)
		defer cancel()
	}

	config, err := readConfig(ctx, req.Storage)
	if err != nil {
		return err
	}
	if config == nil {
		return errors.New("the config is currently unset")
	}

	newPassword, err := b.GeneratePassword(ctx, config)
	if err != nil {
		return err
	}
	oldPassword := config.LDAP.BindPassword

	// Take out the backend lock since we are swapping out the connection
	b.Lock()
	defer b.Unlock()

	// Update the password remotely.
	if err := b.client.UpdateDNPassword(config.LDAP, config.LDAP.BindDN, newPassword); err != nil {
		return err
	}
	config.LDAP.BindPassword = newPassword
	config.LDAP.LastBindPassword = oldPassword
	config.LDAP.LastBindPasswordRotation = time.Now()

	// Update the password locally.
	if pwdStoringErr := storePassword(ctx, req.Storage, config); pwdStoringErr != nil {
		// We were unable to store the new password locally. We can't continue in this state because we won't be able
		// to roll any passwords, including our own to get back into a state of working. So, we need to roll back to
		// the last password we successfully got into storage.
		if rollbackErr := b.rollbackPassword(ctx, config, oldPassword); rollbackErr != nil {
			return fmt.Errorf(`unable to store new password due to %s and unable to return to previous password
due to %s, configure a new binddn and bindpass to restore ldap function`, pwdStoringErr, rollbackErr)
		}
		return fmt.Errorf("unable to update password due to storage err: %s", pwdStoringErr)
	}

	// Respond with a 204.
	return nil
}

func (b *backend) pathRotateRoleCredentialsUpdate(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name := data.Get("name").(string)
	if name == "" {
		return logical.ErrorResponse("empty role name attribute given"), nil
	}

	role, err := b.staticRole(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return logical.ErrorResponse("role doesn't exist: %s", name), nil
	}

	cfg, err := readConfig(ctx, req.Storage)
	if err != nil {
		return nil, fmt.Errorf("unable to read root config for credential rotation: %w", err)
	}

	handler := atomicrotationhelpers.AtomicStaticCredentialRotationHandler{
		PluginBackend:        b.Backend,
		CredentialGenerator:  b.GenerateCredential,
		ExternalSystemClient: b.UpdateExternalCredential,
		ConfigStore:          b.SetCredential,

		Config: cfg,
		Role:   role,
	}

	if req.RotationInfo != nil {
		handler.RotationInfo = req.RotationInfo
	}
	resp, rotateErr := handler.SetStaticAccountCredential(ctx, req.Storage, &role.WALHandlingParams, cfg.PasswordPolicy)
	if rotateErr != nil {
		b.Logger().Error("unable to rotate credentials in periodic function", "name", name, "error", err)

		// Preserve the WALID if it was returned
		if resp != nil && resp.WALID != "" {
			role.WALID = resp.WALID
		}

		// store updated Role
		entry, err := logical.StorageEntryJSON(staticRolePath+name, role)
		if err != nil {
			// send error to RM so that the rotation can be re-tried and re-stored, but log the storage error
			b.Logger().Error("unable to create storage entry", "name", name, "error", err)

			return nil, err
		}
		if err := req.Storage.Put(ctx, entry); err != nil {
			// send error to RM so that the rotation can be re-tried and re-stored, but log the storage error
			b.Logger().Error("unable to store updated role with WALID after rotation failure", "name", name, "error", err)

			return nil, err
		}
	}

	if err != nil {
		b.Logger().Error("unable to rotate credentials in rotate-role on user request", "error", err)
		b.ldapEvent(ctx, "rotate-fail", req.Path, name, false)
		return nil, fmt.Errorf("unable to finish rotating credentials; retries will "+
			"continue in the background but it is also safe to retry manually: %w", err)
	} else {
		b.Logger().Info("successfully rotated credential in rotate-role on user request", "name", name)
		b.ldapEvent(ctx, "rotate", req.Path, name, true)
	}

	// We're not returning creds here because we do not know if its been processed
	// by the queue.
	return nil, nil
}

// rollbackPassword uses exponential backoff to retry updating to an old password,
// because LDAP may still be propagating the previous password change.
func (b *backend) rollbackPassword(ctx context.Context, config *config, oldPassword string) error {
	expbackoff := backoff.NewBackoff(rollbackAttempts, minRollbackDuration, maxRollbackDuration)
	var err error
	for {
		nextsleep, terr := expbackoff.Next()
		if terr != nil {
			// exponential backoff has failed every attempt; return last error
			return err
		}
		timer := time.NewTimer(nextsleep)
		select {
		case <-timer.C:
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C // drain the channel so that it will be garbage collected
			}
			// Outer environment is closing.
			return fmt.Errorf("unable to rollback password because enclosing environment is shutting down")
		}
		err = b.client.UpdateDNPassword(config.LDAP, config.LDAP.BindDN, oldPassword)
		if err == nil {
			return nil
		}
	}
}

func storePassword(ctx context.Context, s logical.Storage, config *config) error {
	entry, err := logical.StorageEntryJSON(configPath, config)
	if err != nil {
		return err
	}
	return s.Put(ctx, entry)
}
