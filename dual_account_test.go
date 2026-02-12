// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: MPL-2.0

package openldap

import (
	"context"
	"testing"
	"time"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/require"
)

func TestDualAccountRole_CreateValidation(t *testing.T) {
	b, storage := getBackend(false)
	defer b.Cleanup(context.Background())
	configureOpenLDAPMount(t, b, storage)

	tests := []struct {
		name    string
		data    map[string]interface{}
		wantErr bool
		errMsg  string
	}{
		{
			name: "missing username_b results in error",
			data: map[string]interface{}{
				"username":          "svc-app-blue",
				"dn":               "uid=svc-app-blue,ou=users,dc=hashicorp,dc=com",
				"rotation_period":   60,
				"dual_account_mode": true,
				"grace_period":      30,
			},
			wantErr: true,
			errMsg:  "username_b is required",
		},
		{
			name: "missing grace_period results in error",
			data: map[string]interface{}{
				"username":          "svc-app-blue",
				"username_b":        "svc-app-green",
				"dn":               "uid=svc-app-blue,ou=users,dc=hashicorp,dc=com",
				"rotation_period":   60,
				"dual_account_mode": true,
			},
			wantErr: true,
			errMsg:  "grace_period is required",
		},
		{
			name: "username_b same as username results in error",
			data: map[string]interface{}{
				"username":          "svc-app-blue",
				"username_b":        "svc-app-blue",
				"rotation_period":   60,
				"dual_account_mode": true,
				"grace_period":      30,
			},
			wantErr: true,
			errMsg:  "must be different from username",
		},
		{
			name: "grace_period greater than rotation_period results in error",
			data: map[string]interface{}{
				"username":          "svc-app-blue",
				"username_b":        "svc-app-green",
				"rotation_period":   60,
				"dual_account_mode": true,
				"grace_period":      120,
			},
			wantErr: true,
			errMsg:  "grace_period must be less than rotation_period",
		},
		{
			name: "grace_period equal to rotation_period results in error",
			data: map[string]interface{}{
				"username":          "svc-app-blue",
				"username_b":        "svc-app-green",
				"rotation_period":   60,
				"dual_account_mode": true,
				"grace_period":      60,
			},
			wantErr: true,
			errMsg:  "grace_period must be less than rotation_period",
		},
		{
			name: "grace_period less than 5 seconds results in error",
			data: map[string]interface{}{
				"username":          "svc-app-blue",
				"username_b":        "svc-app-green",
				"rotation_period":   60,
				"dual_account_mode": true,
				"grace_period":      3,
			},
			wantErr: true,
			errMsg:  "grace_period must be 5 seconds or more",
		},
		{
			name: "empty username_b results in error",
			data: map[string]interface{}{
				"username":          "svc-app-blue",
				"username_b":        "",
				"rotation_period":   60,
				"dual_account_mode": true,
				"grace_period":      30,
			},
			wantErr: true,
			errMsg:  "username_b must not be empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := createStaticRoleWithData(t, b, storage, "test-dual", tt.data)
			if tt.wantErr {
				isErr := err != nil || (resp != nil && resp.IsError())
				require.True(t, isErr, "expected error but got none")
				if resp != nil && resp.IsError() {
					require.Contains(t, resp.Error().Error(), tt.errMsg)
				}
			} else {
				require.NoError(t, err)
				if resp != nil {
					require.False(t, resp.IsError())
				}
			}
		})
	}
}

func TestDualAccountRole_HappyPath(t *testing.T) {
	b, storage := getBackend(false)
	defer b.Cleanup(context.Background())
	configureOpenLDAPMount(t, b, storage)

	roleName := "banking-app"
	data := map[string]interface{}{
		"username":          "svc-banking-blue",
		"username_b":        "svc-banking-green",
		"dn":               "uid=svc-banking-blue,ou=users,dc=bank,dc=com",
		"dn_b":             "uid=svc-banking-green,ou=users,dc=bank,dc=com",
		"rotation_period":   60,
		"dual_account_mode": true,
		"grace_period":      30,
	}

	resp, err := createStaticRoleWithData(t, b, storage, roleName, data)
	require.NoError(t, err)
	if resp != nil {
		require.False(t, resp.IsError(), "unexpected error: %v", resp.Error())
	}

	// Read the role and verify dual-account fields
	readResp, err := readStaticRole(t, b, storage, roleName)
	require.NoError(t, err)
	require.NotNil(t, readResp)
	require.False(t, readResp.IsError())

	require.Equal(t, true, readResp.Data["dual_account_mode"])
	require.Equal(t, "svc-banking-green", readResp.Data["username_b"])
	require.Equal(t, "uid=svc-banking-green,ou=users,dc=bank,dc=com", readResp.Data["dn_b"])
	require.Equal(t, float64(30), readResp.Data["grace_period"])
	// After initial setup, both passwords are set, active_account is "a", state is "active"
	require.Equal(t, "a", readResp.Data["active_account"])
	require.Equal(t, "active", readResp.Data["rotation_state"])
}

func TestDualAccountRole_UsernameOnly(t *testing.T) {
	b, storage := getBackend(false)
	defer b.Cleanup(context.Background())
	configureOpenLDAPMount(t, b, storage)

	roleName := "username-only-dual"
	data := map[string]interface{}{
		"username":          "svc-app-blue",
		"username_b":        "svc-app-green",
		"rotation_period":   60,
		"dual_account_mode": true,
		"grace_period":      10,
	}

	resp, err := createStaticRoleWithData(t, b, storage, roleName, data)
	require.NoError(t, err)
	if resp != nil {
		require.False(t, resp.IsError(), "unexpected error: %v", resp.Error())
	}

	// Read and verify
	readResp, err := readStaticRole(t, b, storage, roleName)
	require.NoError(t, err)
	require.NotNil(t, readResp)
	require.Equal(t, true, readResp.Data["dual_account_mode"])
	require.Equal(t, "svc-app-green", readResp.Data["username_b"])
	require.Equal(t, "", readResp.Data["dn_b"])
}

func TestDualAccountRole_ManagedUserTracking(t *testing.T) {
	b, storage := getBackend(false)
	defer b.Cleanup(context.Background())
	configureOpenLDAPMount(t, b, storage)

	// Create a dual-account role
	data := map[string]interface{}{
		"username":          "svc-tracked-blue",
		"username_b":        "svc-tracked-green",
		"rotation_period":   60,
		"dual_account_mode": true,
		"grace_period":      10,
	}
	resp, err := createStaticRoleWithData(t, b, storage, "tracked-role", data)
	require.NoError(t, err)
	if resp != nil {
		require.False(t, resp.IsError())
	}

	// Verify both usernames are tracked in managedUsers
	b.managedUserLock.Lock()
	_, hasBlue := b.managedUsers["svc-tracked-blue"]
	_, hasGreen := b.managedUsers["svc-tracked-green"]
	b.managedUserLock.Unlock()
	require.True(t, hasBlue, "expected username 'svc-tracked-blue' to be tracked")
	require.True(t, hasGreen, "expected username_b 'svc-tracked-green' to be tracked")

	// Try to create another role using one of the tracked usernames
	data2 := map[string]interface{}{
		"username":        "svc-tracked-green",
		"rotation_period": 60,
	}
	resp2, _ := createStaticRoleWithData(t, b, storage, "conflict-role", data2)
	require.NotNil(t, resp2)
	require.True(t, resp2.IsError(), "expected error when using already-managed username")

	// Delete the dual-account role and verify both usernames are freed
	_, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      staticRolePath + "tracked-role",
		Storage:   storage,
	})
	require.NoError(t, err)

	b.managedUserLock.Lock()
	_, hasBlue = b.managedUsers["svc-tracked-blue"]
	_, hasGreen = b.managedUsers["svc-tracked-green"]
	b.managedUserLock.Unlock()
	require.False(t, hasBlue, "expected username 'svc-tracked-blue' to be removed after delete")
	require.False(t, hasGreen, "expected username_b 'svc-tracked-green' to be removed after delete")
}

func TestDualAccountRole_ImmutableFields(t *testing.T) {
	b, storage := getBackend(false)
	defer b.Cleanup(context.Background())
	configureOpenLDAPMount(t, b, storage)

	// Create a dual-account role
	data := map[string]interface{}{
		"username":          "svc-immutable-blue",
		"username_b":        "svc-immutable-green",
		"dn":               "uid=svc-immutable-blue,ou=users,dc=bank,dc=com",
		"dn_b":             "uid=svc-immutable-green,ou=users,dc=bank,dc=com",
		"rotation_period":   60,
		"dual_account_mode": true,
		"grace_period":      10,
	}
	resp, err := createStaticRoleWithData(t, b, storage, "immutable-role", data)
	require.NoError(t, err)
	if resp != nil {
		require.False(t, resp.IsError())
	}

	// Try to change dual_account_mode on update
	resp, err = updateStaticRoleWithData(t, b, storage, "immutable-role", map[string]interface{}{
		"username":          "svc-immutable-blue",
		"dual_account_mode": false,
	})
	isErr := err != nil || (resp != nil && resp.IsError())
	require.True(t, isErr, "expected error when changing dual_account_mode")

	// Try to change username_b on update
	resp, err = updateStaticRoleWithData(t, b, storage, "immutable-role", map[string]interface{}{
		"username":          "svc-immutable-blue",
		"username_b":        "svc-other-green",
		"dual_account_mode": true,
	})
	isErr = err != nil || (resp != nil && resp.IsError())
	require.True(t, isErr, "expected error when changing username_b")

	// Try to change dn_b on update
	resp, err = updateStaticRoleWithData(t, b, storage, "immutable-role", map[string]interface{}{
		"username":          "svc-immutable-blue",
		"dn_b":             "uid=svc-other-green,ou=users,dc=bank,dc=com",
		"dual_account_mode": true,
	})
	isErr = err != nil || (resp != nil && resp.IsError())
	require.True(t, isErr, "expected error when changing dn_b")
}

func TestDualAccountCreds_Read(t *testing.T) {
	b, storage := getBackend(false)
	defer b.Cleanup(context.Background())
	configureOpenLDAPMount(t, b, storage)

	roleName := "creds-test"
	data := map[string]interface{}{
		"username":          "svc-creds-blue",
		"username_b":        "svc-creds-green",
		"rotation_period":   60,
		"dual_account_mode": true,
		"grace_period":      10,
	}

	resp, err := createStaticRoleWithData(t, b, storage, roleName, data)
	require.NoError(t, err)
	if resp != nil {
		require.False(t, resp.IsError(), "unexpected error: %v", resp.Error())
	}

	// Read creds
	credResp := readStaticCred(t, b, storage, roleName)
	require.NotNil(t, credResp)

	// Should have dual-account metadata
	require.Equal(t, true, credResp.Data["dual_account_mode"])
	require.NotEmpty(t, credResp.Data["active_account"])
	require.NotEmpty(t, credResp.Data["rotation_state"])

	// Should have password for the active account
	require.NotEmpty(t, credResp.Data["password"])
	require.NotEmpty(t, credResp.Data["username"])
}

func TestDualAccountRotation_StateTransition(t *testing.T) {
	b, storage := getBackend(false)
	defer b.Cleanup(context.Background())
	configureOpenLDAPMount(t, b, storage)

	roleName := "rotation-test"
	data := map[string]interface{}{
		"username":          "svc-rotate-blue",
		"username_b":        "svc-rotate-green",
		"rotation_period":   60,
		"dual_account_mode": true,
		"grace_period":      10,
	}

	resp, err := createStaticRoleWithData(t, b, storage, roleName, data)
	require.NoError(t, err)
	if resp != nil {
		require.False(t, resp.IsError(), "unexpected error: %v", resp.Error())
	}

	// Read initial state — after creation with the initial setup path,
	// both passwords are set and the role is in "active" state with account "a" active.
	role, err := b.staticRole(context.Background(), storage, roleName)
	require.NoError(t, err)
	require.NotNil(t, role)
	require.Equal(t, "active", role.StaticAccount.RotationState)
	require.Equal(t, "a", role.StaticAccount.ActiveAccount)
	require.NotEmpty(t, role.StaticAccount.Password, "expected password to be set after initial setup")
	require.NotEmpty(t, role.StaticAccount.PasswordB, "expected password_b to be set after initial setup")

	// Read creds in active state — should return only the active account
	credResp := readStaticCred(t, b, storage, roleName)
	require.Equal(t, "active", credResp.Data["rotation_state"])
	require.Nil(t, credResp.Data["standby_username"], "should not return standby credentials in active state")
	require.Nil(t, credResp.Data["standby_password"], "should not return standby credentials in active state")

	// Manually trigger rotation — this rotates the standby (B) and transitions to grace_period
	_, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "rotate-role/" + roleName,
		Storage:   storage,
	})
	require.NoError(t, err)

	// After manual rotation, the role should be in grace_period with active_account "b"
	role, err = b.staticRole(context.Background(), storage, roleName)
	require.NoError(t, err)
	require.Equal(t, "grace_period", role.StaticAccount.RotationState)
	require.Equal(t, "b", role.StaticAccount.ActiveAccount)
	require.False(t, role.StaticAccount.GracePeriodEnd.IsZero())

	// Read creds during grace period — should return both accounts
	credResp = readStaticCred(t, b, storage, roleName)
	require.Equal(t, "grace_period", credResp.Data["rotation_state"])
	require.NotEmpty(t, credResp.Data["standby_username"])
	require.NotEmpty(t, credResp.Data["standby_password"])
	require.NotNil(t, credResp.Data["grace_period_end"])

	// Manually trigger rotation again — this rotates standby (A) and transitions to grace_period with "a" active
	_, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "rotate-role/" + roleName,
		Storage:   storage,
	})
	require.NoError(t, err)

	// After second rotation, active_account should flip back to "a"
	role, err = b.staticRole(context.Background(), storage, roleName)
	require.NoError(t, err)
	require.Equal(t, "grace_period", role.StaticAccount.RotationState)
	require.Equal(t, "a", role.StaticAccount.ActiveAccount)
}

func TestDualAccountGracePeriodExpiry(t *testing.T) {
	b, storage := getBackend(false)
	defer b.Cleanup(context.Background())
	configureOpenLDAPMount(t, b, storage)

	roleName := "grace-expiry"
	data := map[string]interface{}{
		"username":          "svc-grace-blue",
		"username_b":        "svc-grace-green",
		"rotation_period":   3600,
		"dual_account_mode": true,
		"grace_period":      5,
	}

	resp, err := createStaticRoleWithData(t, b, storage, roleName, data)
	require.NoError(t, err)
	if resp != nil {
		require.False(t, resp.IsError(), "unexpected error: %v", resp.Error())
	}

	// Role should be in "active" state after initial setup (both passwords set)
	role, err := b.staticRole(context.Background(), storage, roleName)
	require.NoError(t, err)
	require.Equal(t, "active", role.StaticAccount.RotationState)

	// Trigger a manual rotation to enter grace_period
	_, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "rotate-role/" + roleName,
		Storage:   storage,
	})
	require.NoError(t, err)

	// Now should be in grace_period
	role, err = b.staticRole(context.Background(), storage, roleName)
	require.NoError(t, err)
	require.Equal(t, "grace_period", role.StaticAccount.RotationState)

	// Simulate grace period expiry by setting GracePeriodEnd to the past
	role.StaticAccount.GracePeriodEnd = time.Now().Add(-1 * time.Second)
	entry, err := logical.StorageEntryJSON(staticRolePath+roleName, role)
	require.NoError(t, err)
	require.NoError(t, storage.Put(context.Background(), entry))

	// Also update the queue item priority to match the expired grace period
	// so the rotation ticker will process it
	item, err := b.popFromRotationQueueByKey(roleName)
	require.NoError(t, err)
	item.Priority = role.StaticAccount.GracePeriodEnd.Unix()
	require.NoError(t, b.pushItem(item))

	// Trigger rotation check — this should detect the expired grace period
	// and transition back to "active" state
	b.rotateCredentials(context.Background(), storage)

	// Verify the role transitioned to "active" state
	role, err = b.staticRole(context.Background(), storage, roleName)
	require.NoError(t, err)
	require.Equal(t, "active", role.StaticAccount.RotationState)
	require.True(t, role.StaticAccount.GracePeriodEnd.IsZero())
}

func TestDualAccountRole_SkipImportRotation(t *testing.T) {
	b, storage := getBackend(false)
	defer b.Cleanup(context.Background())
	configureOpenLDAPMount(t, b, storage)

	roleName := "skip-import-dual"
	data := map[string]interface{}{
		"username":             "svc-skip-blue",
		"username_b":           "svc-skip-green",
		"rotation_period":      60,
		"dual_account_mode":    true,
		"grace_period":         10,
		"skip_import_rotation": true,
	}

	resp, err := createStaticRoleWithData(t, b, storage, roleName, data)
	require.NoError(t, err)
	if resp != nil {
		require.False(t, resp.IsError(), "unexpected error: %v", resp.Error())
	}

	// When skip_import_rotation is set, the role should be in "active" state
	// because no rotation happened at creation time
	role, err := b.staticRole(context.Background(), storage, roleName)
	require.NoError(t, err)
	require.Equal(t, "active", role.StaticAccount.RotationState)
	require.Equal(t, "a", role.StaticAccount.ActiveAccount)
}

func TestDualAccountRole_UsernameB_AlreadyManaged(t *testing.T) {
	b, storage := getBackend(false)
	defer b.Cleanup(context.Background())
	configureOpenLDAPMount(t, b, storage)

	// Create a standard role with a username
	data1 := map[string]interface{}{
		"username":        "svc-existing",
		"rotation_period": 60,
	}
	resp, err := createStaticRoleWithData(t, b, storage, "existing-role", data1)
	require.NoError(t, err)
	if resp != nil {
		require.False(t, resp.IsError())
	}

	// Try to create a dual-account role with username_b matching the existing role
	data2 := map[string]interface{}{
		"username":          "svc-new-blue",
		"username_b":        "svc-existing",
		"rotation_period":   60,
		"dual_account_mode": true,
		"grace_period":      10,
	}
	resp2, _ := createStaticRoleWithData(t, b, storage, "conflict-dual", data2)
	require.NotNil(t, resp2)
	require.True(t, resp2.IsError(), "expected error when username_b is already managed")
}

// TestDualAccountRole_LibrarySetConflict verifies that dual-account roles and
// library sets correctly prevent username conflicts in both directions.
func TestDualAccountRole_LibrarySetConflict(t *testing.T) {
	ctx := context.Background()

	t.Run("library_user_blocks_dual_account_username_b", func(t *testing.T) {
		b, storage := getBackend(false)
		defer b.Cleanup(ctx)
		configureOpenLDAPMount(t, b, storage)

		// Create a library set with a service account
		resp, err := b.HandleRequest(ctx, &logical.Request{
			Operation: logical.CreateOperation,
			Path:      "library/test-lib",
			Storage:   storage,
			Data: map[string]interface{}{
				"service_account_names": []string{"svc-lib-account"},
				"ttl":                   "10h",
				"max_ttl":               "11h",
			},
		})
		require.NoError(t, err)
		require.Nil(t, resp, "library set creation should succeed")

		// Try creating a dual-account role with username_b matching the library user
		data := map[string]interface{}{
			"username":          "svc-blue",
			"username_b":        "svc-lib-account",
			"rotation_period":   60,
			"dual_account_mode": true,
			"grace_period":      10,
		}
		resp, err = createStaticRoleWithData(t, b, storage, "conflict-role", data)
		require.NoError(t, err)
		require.NotNil(t, resp)
		require.True(t, resp.IsError(), "username_b conflicting with library set should be rejected")
		require.Contains(t, resp.Data["error"], "already managed")
	})

	t.Run("library_user_blocks_dual_account_primary_username", func(t *testing.T) {
		b, storage := getBackend(false)
		defer b.Cleanup(ctx)
		configureOpenLDAPMount(t, b, storage)

		// Create a library set
		resp, err := b.HandleRequest(ctx, &logical.Request{
			Operation: logical.CreateOperation,
			Path:      "library/test-lib",
			Storage:   storage,
			Data: map[string]interface{}{
				"service_account_names": []string{"svc-lib-account"},
				"ttl":                   "10h",
				"max_ttl":               "11h",
			},
		})
		require.NoError(t, err)
		require.Nil(t, resp)

		// Try creating a dual-account role with primary username matching library user
		data := map[string]interface{}{
			"username":          "svc-lib-account",
			"username_b":        "svc-green",
			"rotation_period":   60,
			"dual_account_mode": true,
			"grace_period":      10,
		}
		resp, err = createStaticRoleWithData(t, b, storage, "conflict-role", data)
		require.NoError(t, err)
		require.NotNil(t, resp)
		require.True(t, resp.IsError(), "primary username conflicting with library set should be rejected")
		require.Contains(t, resp.Data["error"], "already managed")
	})

	t.Run("dual_account_blocks_library_set_username_b", func(t *testing.T) {
		b, storage := getBackend(false)
		defer b.Cleanup(ctx)
		configureOpenLDAPMount(t, b, storage)

		// Create a dual-account role first
		data := map[string]interface{}{
			"username":          "svc-blue",
			"username_b":        "svc-green",
			"rotation_period":   60,
			"dual_account_mode": true,
			"grace_period":      10,
		}
		resp, err := createStaticRoleWithData(t, b, storage, "dual-role", data)
		require.NoError(t, err)
		if resp != nil {
			require.False(t, resp.IsError(), "dual-account role creation should succeed: %v", resp)
		}

		// Try creating a library set with username_b
		resp, err = b.HandleRequest(ctx, &logical.Request{
			Operation: logical.CreateOperation,
			Path:      "library/conflict-lib",
			Storage:   storage,
			Data: map[string]interface{}{
				"service_account_names": []string{"svc-green"},
				"ttl":                   "10h",
				"max_ttl":               "11h",
			},
		})
		require.NoError(t, err)
		require.NotNil(t, resp)
		require.True(t, resp.IsError(), "library set conflicting with dual-account username_b should be rejected")
		require.Contains(t, resp.Data["error"], "already managed")
	})

	t.Run("dual_account_blocks_library_set_primary_username", func(t *testing.T) {
		b, storage := getBackend(false)
		defer b.Cleanup(ctx)
		configureOpenLDAPMount(t, b, storage)

		// Create a dual-account role first
		data := map[string]interface{}{
			"username":          "svc-blue",
			"username_b":        "svc-green",
			"rotation_period":   60,
			"dual_account_mode": true,
			"grace_period":      10,
		}
		resp, err := createStaticRoleWithData(t, b, storage, "dual-role", data)
		require.NoError(t, err)
		if resp != nil {
			require.False(t, resp.IsError(), "dual-account role creation should succeed: %v", resp)
		}

		// Try creating a library set with the primary username
		resp, err = b.HandleRequest(ctx, &logical.Request{
			Operation: logical.CreateOperation,
			Path:      "library/conflict-lib",
			Storage:   storage,
			Data: map[string]interface{}{
				"service_account_names": []string{"svc-blue"},
				"ttl":                   "10h",
				"max_ttl":               "11h",
			},
		})
		require.NoError(t, err)
		require.NotNil(t, resp)
		require.True(t, resp.IsError(), "library set conflicting with dual-account primary username should be rejected")
		require.Contains(t, resp.Data["error"], "already managed")
	})

	t.Run("delete_dual_account_frees_both_usernames_for_library", func(t *testing.T) {
		b, storage := getBackend(false)
		defer b.Cleanup(ctx)
		configureOpenLDAPMount(t, b, storage)

		// Create a dual-account role
		data := map[string]interface{}{
			"username":          "svc-blue",
			"username_b":        "svc-green",
			"rotation_period":   60,
			"dual_account_mode": true,
			"grace_period":      10,
		}
		resp, err := createStaticRoleWithData(t, b, storage, "dual-role", data)
		require.NoError(t, err)
		if resp != nil {
			require.False(t, resp.IsError(), "dual-account role creation should succeed: %v", resp)
		}

		// Delete the dual-account role
		resp, err = b.HandleRequest(ctx, &logical.Request{
			Operation: logical.DeleteOperation,
			Path:      staticRolePath + "dual-role",
			Storage:   storage,
		})
		require.NoError(t, err)

		// Now both usernames should be available for a library set
		resp, err = b.HandleRequest(ctx, &logical.Request{
			Operation: logical.CreateOperation,
			Path:      "library/reclaim-lib",
			Storage:   storage,
			Data: map[string]interface{}{
				"service_account_names": []string{"svc-blue", "svc-green"},
				"ttl":                   "10h",
				"max_ttl":               "11h",
			},
		})
		require.NoError(t, err)
		require.Nil(t, resp, "library set should succeed after dual-account role is deleted")
	})
}
