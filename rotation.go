// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: MPL-2.0

package openldap

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/vault/sdk/rotation"

	"github.com/hashicorp/go-secure-stdlib/base62"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/mitchellh/mapstructure"
)

const (
	// WAL storage key used for static account rotations
	staticWALKey = "staticRotationKey"
)

// setCredentialsWAL is used to store information in a WAL that can retry a
// credential setting or rotation in the event of partial failure.
type setCredentialsWAL struct {
	NewPassword       string    `json:"new_password" mapstructure:"new_password"`
	RoleName          string    `json:"role_name" mapstructure:"role_name"`
	Username          string    `json:"username" mapstructure:"username"`
	DN                string    `json:"dn" mapstructure:"dn"`
	PasswordPolicy    string    `json:"password_policy" mapstructure:"password_policy"`
	LastVaultRotation time.Time `json:"last_vault_rotation" mapstructure:"last_vault_rotation"`

	// Private fields which will not be included in json.Marshal/Unmarshal.
	walID        string
	walCreatedAt int64 // Unix time at which the WAL was created.
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

func (b *backend) SetCredential(r any, newPassword string, info *rotation.RotationInfo) (any, error) {
	role, ok := r.(*roleEntry)
	if !ok {
		return nil, fmt.Errorf("expected roleEntry type for SetCredential")
	}

	role.StaticAccount.LastPassword = role.StaticAccount.Password
	role.StaticAccount.Password = newPassword

	if info != nil {
		role.SetRotationInfo(info)
	} else {
		role.SetLastVaultRotation()
	}

	return &role, nil
}

func (b *backend) UpdateExternalCredential(ctx context.Context, s logical.Storage, roleName, newPassword string, cfg any) error {
	cfgRaw, ok := cfg.(*config)
	if !ok {
		return fmt.Errorf("expected cfg to be of type *config")
	}

	role, err := b.staticRole(ctx, s, roleName)
	if err != nil {
		return fmt.Errorf("error reading role during external credential update: %w", err)
	}
	if role.StaticAccount.DN != "" {
		err = b.client.UpdateDNPassword(cfgRaw.LDAP, role.StaticAccount.DN, newPassword)
	} else {
		err = b.client.UpdateUserPassword(cfgRaw.LDAP, role.StaticAccount.Username, newPassword)
	}
	if err != nil {
		return err
	}

	return nil
}

func (b *backend) GenerateCredential(ctx context.Context, rootCfg any) (string, error) {
	rootConfig, ok := rootCfg.(*config)
	if !ok {
		return "", fmt.Errorf("expected rootCfg to be of type *config, got %T", rootCfg)
	}

	if rootConfig.PasswordPolicy == "" {
		if rootConfig.PasswordLength == 0 {
			pwd, err := base62.Random(defaultPasswordLength)
			if err != nil {
				return "", fmt.Errorf("unable to generate password: %w", err)
			}
			return pwd, nil
		}
		pwd, err := base62.Random(rootConfig.PasswordLength)
		if err != nil {
			return "", fmt.Errorf("unable to generate password: %w", err)
		}
		return pwd, nil
	}

	password, err := b.System().GeneratePasswordFromPolicy(ctx, rootConfig.PasswordPolicy)
	if err != nil {
		return "", fmt.Errorf("unable to generate password: %w", err)
	}
	return password, nil
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
