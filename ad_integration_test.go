// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: MPL-2.0

package openldap

import (
	"context"
	"crypto/tls"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/hashicorp/vault-plugin-secrets-openldap/client"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/require"
)

// AD integration tests require the following environment variables:
//
//	AD_URL      - LDAPS URL of the Active Directory server (e.g., ldaps://1.2.3.4)
//	AD_BIND_DN  - Bind DN for admin access (e.g., CN=Administrator,CN=Users,DC=mydomain,DC=local)
//	AD_BIND_PW  - Admin password
//	AD_USER_DN  - Base DN for users (e.g., CN=Users,DC=mydomain,DC=local)
//	AD_DOMAIN   - Domain suffix (e.g., DC=mydomain,DC=local)
//
// Test users must exist in AD before running:
//
//	svc-rotate-a, svc-rotate-b - paired dual-account service accounts
//	svc-single                 - single-account service account
func adTestConfig(t *testing.T) (url, bindDN, bindPW, userDN, domain string) {
	t.Helper()
	url = os.Getenv("AD_URL")
	bindDN = os.Getenv("AD_BIND_DN")
	bindPW = os.Getenv("AD_BIND_PW")
	userDN = os.Getenv("AD_USER_DN")
	domain = os.Getenv("AD_DOMAIN")

	if url == "" || bindDN == "" || bindPW == "" || userDN == "" || domain == "" {
		t.Skip("AD integration tests require AD_URL, AD_BIND_DN, AD_BIND_PW, AD_USER_DN, AD_DOMAIN")
	}
	return
}

// getADBackend creates a backend wired to a real LDAP client for AD tests.
func getADBackend(t *testing.T) (*backend, logical.Storage) {
	t.Helper()
	b, storage := getBackend(false)
	// Replace fake client with real one
	b.client = NewClient(b.Logger())
	return b, storage
}

func configureADMount(t *testing.T, b *backend, storage logical.Storage, url, bindDN, bindPW string) {
	t.Helper()
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      configPath,
		Storage:   storage,
		Data: map[string]interface{}{
			"binddn":       bindDN,
			"bindpass":     bindPW,
			"url":          url,
			"schema":       client.SchemaAD,
			"insecure_tls": true,
			"userdn":       os.Getenv("AD_USER_DN"),
			"userattr":     "sAMAccountName",
		},
	})
	require.NoError(t, err)
	require.Nil(t, resp)
}

// ldapBind verifies that a user can bind (authenticate) to AD with the given credentials.
func ldapBind(t *testing.T, url, dn, password string) error {
	t.Helper()
	conn, err := ldap.DialURL(url, ldap.DialWithTLSConfig(
		&tls.Config{InsecureSkipVerify: true},
	))
	if err != nil {
		return fmt.Errorf("dial failed: %w", err)
	}
	defer conn.Close()

	return conn.Bind(dn, password)
}

// TestAD_SingleAccountRotation tests standard single-account static role rotation against real AD.
func TestAD_SingleAccountRotation(t *testing.T) {
	url, bindDN, bindPW, _, domain := adTestConfig(t)
	b, storage := getADBackend(t)
	defer b.Cleanup(context.Background())

	configureADMount(t, b, storage, url, bindDN, bindPW)

	userDN := fmt.Sprintf("CN=svc-single,CN=Users,%s", domain)

	// Create a single-account static role
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      staticRolePath + "test-single",
		Storage:   storage,
		Data: map[string]interface{}{
			"username":        "svc-single",
			"dn":              userDN,
			"rotation_period": "86400s",
		},
	})
	require.NoError(t, err)
	require.False(t, resp != nil && resp.IsError(), "unexpected error: %v", resp)

	// Read credentials
	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      staticCredPath + "test-single",
		Storage:   storage,
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.NotEmpty(t, resp.Data["password"])

	password := resp.Data["password"].(string)
	t.Logf("Single-account password set: %s (length=%d)", password[:4]+"...", len(password))

	// Verify we can bind with the new password
	err = ldapBind(t, url, userDN, password)
	require.NoError(t, err, "should be able to bind with rotated password")

	// Trigger manual rotation
	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "rotate-role/test-single",
		Storage:   storage,
	})
	require.NoError(t, err)

	// Wait for rotation to process
	time.Sleep(1 * time.Second)

	// Read new credentials
	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      staticCredPath + "test-single",
		Storage:   storage,
	})
	require.NoError(t, err)
	require.NotNil(t, resp)

	newPassword := resp.Data["password"].(string)
	require.NotEqual(t, password, newPassword, "password should change after rotation")
	t.Logf("Single-account rotated password: %s (length=%d)", newPassword[:4]+"...", len(newPassword))

	// Verify new password works
	err = ldapBind(t, url, userDN, newPassword)
	require.NoError(t, err, "should be able to bind with new rotated password")

	// Note: AD has an OldPasswordAllowedPeriod (default ~60 min) during which
	// old passwords may still work. This is AD behavior, not a plugin issue.
	// We just verify the new password works — the old password test is skipped.
	t.Log("Skipping old-password-invalidation check (AD OldPasswordAllowedPeriod allows old passwords temporarily)")
}

// TestAD_DualAccountRotation tests dual-account (blue/green) rotation against real AD.
func TestAD_DualAccountRotation(t *testing.T) {
	url, bindDN, bindPW, _, domain := adTestConfig(t)
	b, storage := getADBackend(t)
	defer b.Cleanup(context.Background())

	configureADMount(t, b, storage, url, bindDN, bindPW)

	dnA := fmt.Sprintf("CN=svc-rotate-a,CN=Users,%s", domain)
	dnB := fmt.Sprintf("CN=svc-rotate-b,CN=Users,%s", domain)

	// Create a dual-account static role
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      staticRolePath + "test-dual",
		Storage:   storage,
		Data: map[string]interface{}{
			"username":          "svc-rotate-a",
			"dn":                dnA,
			"username_b":        "svc-rotate-b",
			"dn_b":              dnB,
			"rotation_period":   "3600s",
			"dual_account_mode": true,
			"grace_period":      "1800s",
		},
	})
	require.NoError(t, err)
	require.False(t, resp != nil && resp.IsError(), "unexpected error creating dual-account role: %v", resp)

	// Read credentials — should be in "active" state after initial setup
	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      staticCredPath + "test-dual",
		Storage:   storage,
	})
	require.NoError(t, err)
	require.NotNil(t, resp)

	// Verify initial state
	require.Equal(t, true, resp.Data["dual_account_mode"])
	require.Equal(t, "a", resp.Data["active_account"])
	require.Equal(t, "active", resp.Data["rotation_state"])
	passwordA := resp.Data["password"].(string)
	require.NotEmpty(t, passwordA)

	t.Logf("Initial state: active_account=a, state=active")
	t.Logf("Account A password: %s... (len=%d)", passwordA[:4], len(passwordA))

	// Verify account A can bind
	err = ldapBind(t, url, dnA, passwordA)
	require.NoError(t, err, "account A should be able to bind with initial password")

	// Read the role directly to get account B's password
	role, err := b.staticRole(context.Background(), storage, "test-dual")
	require.NoError(t, err)
	require.NotNil(t, role)
	passwordB := role.StaticAccount.PasswordB
	require.NotEmpty(t, passwordB)
	t.Logf("Account B password: %s... (len=%d)", passwordB[:4], len(passwordB))

	// Verify account B can bind
	err = ldapBind(t, url, dnB, passwordB)
	require.NoError(t, err, "account B should be able to bind with initial password")

	// Trigger manual rotation — this should:
	// 1. Rotate the standby account (B) password
	// 2. Flip active account from A to B
	// 3. Enter grace_period state
	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "rotate-role/test-dual",
		Storage:   storage,
	})
	require.NoError(t, err)

	// Wait for rotation to process
	time.Sleep(1 * time.Second)

	// Read credentials after rotation
	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      staticCredPath + "test-dual",
		Storage:   storage,
	})
	require.NoError(t, err)
	require.NotNil(t, resp)

	// After rotation: B should be active, state should be grace_period
	require.Equal(t, "b", resp.Data["active_account"], "active account should flip to B")
	require.Equal(t, "grace_period", resp.Data["rotation_state"], "should be in grace_period")

	// During grace period, primary creds are the NEW active (B)
	newPasswordB := resp.Data["password"].(string)
	require.NotEqual(t, passwordB, newPasswordB, "account B password should have changed")
	t.Logf("After rotation: active=B, state=grace_period")
	t.Logf("New B password: %s... (len=%d)", newPasswordB[:4], len(newPasswordB))

	// Verify standby credentials are returned during grace period
	standbyUser, ok := resp.Data["standby_username"].(string)
	require.True(t, ok, "standby_username should be present during grace period")
	require.Equal(t, "svc-rotate-a", standbyUser)
	standbyPwd, ok := resp.Data["standby_password"].(string)
	require.True(t, ok, "standby_password should be present during grace period")

	// Verify both accounts can bind during grace period
	err = ldapBind(t, url, dnB, newPasswordB)
	require.NoError(t, err, "new active account (B) should bind with new password")

	err = ldapBind(t, url, dnA, standbyPwd)
	require.NoError(t, err, "standby account (A) should still bind during grace period")

	// Note: AD OldPasswordAllowedPeriod means old passwords may still bind temporarily.
	// We verify the new password works which is sufficient.
	t.Log("Skipping old B password invalidation check (AD OldPasswordAllowedPeriod)")

	t.Logf("Dual-account rotation verified: both accounts bindable during grace period")
}

// TestAD_DualAccountRotation_SecondRotation performs two rotations to verify
// the full A→B→A cycle.
func TestAD_DualAccountRotation_SecondRotation(t *testing.T) {
	url, bindDN, bindPW, _, domain := adTestConfig(t)
	b, storage := getADBackend(t)
	defer b.Cleanup(context.Background())

	configureADMount(t, b, storage, url, bindDN, bindPW)

	dnA := fmt.Sprintf("CN=svc-rotate-a,CN=Users,%s", domain)
	dnB := fmt.Sprintf("CN=svc-rotate-b,CN=Users,%s", domain)

	// Create dual-account role with short grace period for testing
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      staticRolePath + "test-dual-cycle",
		Storage:   storage,
		Data: map[string]interface{}{
			"username":          "svc-rotate-a",
			"dn":                dnA,
			"username_b":        "svc-rotate-b",
			"dn_b":              dnB,
			"rotation_period":   "3600s",
			"dual_account_mode": true,
			"grace_period":      "10s",
		},
	})
	require.NoError(t, err)
	require.False(t, resp != nil && resp.IsError(), "unexpected error: %v", resp)

	// Read initial state
	role, err := b.staticRole(context.Background(), storage, "test-dual-cycle")
	require.NoError(t, err)
	initialPwdA := role.StaticAccount.Password
	initialPwdB := role.StaticAccount.PasswordB
	require.Equal(t, "a", role.StaticAccount.ActiveAccount)
	require.Equal(t, "active", role.StaticAccount.RotationState)

	t.Logf("Initial: A active, A pwd=%s..., B pwd=%s...", initialPwdA[:4], initialPwdB[:4])

	// First rotation: A→B active, B gets new password, grace_period
	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "rotate-role/test-dual-cycle",
		Storage:   storage,
	})
	require.NoError(t, err)
	time.Sleep(1 * time.Second)

	role, err = b.staticRole(context.Background(), storage, "test-dual-cycle")
	require.NoError(t, err)
	require.Equal(t, "b", role.StaticAccount.ActiveAccount)
	require.Equal(t, "grace_period", role.StaticAccount.RotationState)
	firstRotPwdB := role.StaticAccount.PasswordB
	require.NotEqual(t, initialPwdB, firstRotPwdB, "B password should change after first rotation")

	t.Logf("After 1st rotation: B active, B pwd=%s...", firstRotPwdB[:4])

	// Verify B binds with new password
	err = ldapBind(t, url, dnB, firstRotPwdB)
	require.NoError(t, err, "B should bind with new password")

	// Wait for grace period to expire (10s + buffer)
	t.Log("Waiting for grace period to expire...")
	time.Sleep(15 * time.Second)

	// Manually expire grace period by simulating queue tick
	// The role should transition back to "active" state when processed
	role, err = b.staticRole(context.Background(), storage, "test-dual-cycle")
	require.NoError(t, err)

	// If queue hasn't processed yet, manually update the state
	if role.StaticAccount.RotationState == "grace_period" && time.Now().After(role.StaticAccount.GracePeriodEnd) {
		role.StaticAccount.RotationState = "active"
		entry, err := logical.StorageEntryJSON(staticRolePath+"test-dual-cycle", role)
		require.NoError(t, err)
		require.NoError(t, storage.Put(context.Background(), entry))
		t.Log("Manually expired grace period")
	}

	// Second rotation: B→A active, A gets new password, grace_period
	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "rotate-role/test-dual-cycle",
		Storage:   storage,
	})
	require.NoError(t, err)
	time.Sleep(1 * time.Second)

	role, err = b.staticRole(context.Background(), storage, "test-dual-cycle")
	require.NoError(t, err)
	require.Equal(t, "a", role.StaticAccount.ActiveAccount, "active should flip back to A")
	require.Equal(t, "grace_period", role.StaticAccount.RotationState)

	secondRotPwdA := role.StaticAccount.Password
	require.NotEqual(t, initialPwdA, secondRotPwdA, "A password should change after second rotation")

	t.Logf("After 2nd rotation: A active, A pwd=%s...", secondRotPwdA[:4])

	// Verify A binds with new password
	err = ldapBind(t, url, dnA, secondRotPwdA)
	require.NoError(t, err, "A should bind with new password after second rotation")

	// Verify B still binds (it should — its password wasn't rotated this time)
	err = ldapBind(t, url, dnB, firstRotPwdB)
	require.NoError(t, err, "B should still bind with its password")

	t.Log("Full A→B→A rotation cycle verified successfully")
}

// TestAD_DualAccountUsernameOnlyMode tests dual-account rotation using
// sAMAccountName (username) instead of full DN for password changes.
func TestAD_DualAccountUsernameOnlyMode(t *testing.T) {
	url, bindDN, bindPW, _, _ := adTestConfig(t)
	b, storage := getADBackend(t)
	defer b.Cleanup(context.Background())

	configureADMount(t, b, storage, url, bindDN, bindPW)

	// Create dual-account role using username only (no DN)
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      staticRolePath + "test-dual-username",
		Storage:   storage,
		Data: map[string]interface{}{
			"username":          "svc-rotate-a",
			"username_b":        "svc-rotate-b",
			"rotation_period":   "3600s",
			"dual_account_mode": true,
			"grace_period":      "1800s",
		},
	})
	require.NoError(t, err)
	require.False(t, resp != nil && resp.IsError(), "unexpected error: %v", resp)

	// Read credentials
	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      staticCredPath + "test-dual-username",
		Storage:   storage,
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.Equal(t, "a", resp.Data["active_account"])
	require.Equal(t, "active", resp.Data["rotation_state"])
	require.NotEmpty(t, resp.Data["password"])

	t.Logf("Username-only dual-account mode works: active=%s, state=%s",
		resp.Data["active_account"], resp.Data["rotation_state"])
}

// TestAD_LibrarySetConflict verifies that dual-account roles and library sets
// correctly prevent username conflicts against a real AD backend.
func TestAD_LibrarySetConflict(t *testing.T) {
	url, bindDN, bindPW, _, _ := adTestConfig(t)
	ctx := context.Background()

	t.Run("library_blocks_dual_account_username_b", func(t *testing.T) {
		b, storage := getADBackend(t)
		defer b.Cleanup(ctx)
		configureADMount(t, b, storage, url, bindDN, bindPW)

		// Create a library set with svc-single
		resp, err := b.HandleRequest(ctx, &logical.Request{
			Operation: logical.CreateOperation,
			Path:      "library/ad-lib-test",
			Storage:   storage,
			Data: map[string]interface{}{
				"service_account_names": []string{"svc-single"},
				"ttl":                   "10h",
				"max_ttl":               "11h",
			},
		})
		require.NoError(t, err)
		require.Nil(t, resp, "library set creation should succeed")

		// Try creating a dual-account role with username_b matching the library user
		resp, err = b.HandleRequest(ctx, &logical.Request{
			Operation: logical.CreateOperation,
			Path:      staticRolePath + "conflict-dual",
			Storage:   storage,
			Data: map[string]interface{}{
				"username":          "svc-rotate-a",
				"username_b":        "svc-single",
				"rotation_period":   "3600s",
				"dual_account_mode": true,
				"grace_period":      "1800s",
			},
		})
		require.NoError(t, err)
		require.NotNil(t, resp)
		require.True(t, resp.IsError(), "username_b conflicting with library set should be rejected")
		require.Contains(t, resp.Data["error"], "already managed")
		t.Logf("Correctly rejected: %s", resp.Data["error"])
	})

	t.Run("dual_account_blocks_library_set", func(t *testing.T) {
		b, storage := getADBackend(t)
		defer b.Cleanup(ctx)
		configureADMount(t, b, storage, url, bindDN, bindPW)

		// Create a dual-account role first
		resp, err := b.HandleRequest(ctx, &logical.Request{
			Operation: logical.CreateOperation,
			Path:      staticRolePath + "dual-first",
			Storage:   storage,
			Data: map[string]interface{}{
				"username":          "svc-rotate-a",
				"username_b":        "svc-rotate-b",
				"rotation_period":   "3600s",
				"dual_account_mode": true,
				"grace_period":      "1800s",
			},
		})
		require.NoError(t, err)
		require.False(t, resp != nil && resp.IsError(), "dual-account role should succeed: %v", resp)

		// Try creating a library set with username_b
		resp, err = b.HandleRequest(ctx, &logical.Request{
			Operation: logical.CreateOperation,
			Path:      "library/conflict-lib",
			Storage:   storage,
			Data: map[string]interface{}{
				"service_account_names": []string{"svc-rotate-b"},
				"ttl":                   "10h",
				"max_ttl":               "11h",
			},
		})
		require.NoError(t, err)
		require.NotNil(t, resp)
		require.True(t, resp.IsError(), "library set conflicting with dual-account username_b should be rejected")
		require.Contains(t, resp.Data["error"], "already managed")
		t.Logf("Correctly rejected: %s", resp.Data["error"])
	})
}
