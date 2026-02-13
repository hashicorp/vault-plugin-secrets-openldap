// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: MPL-2.0

package openldap

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/hashicorp/vault-plugin-secrets-openldap/client"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/ory/dockertest/v3"
	"github.com/ory/dockertest/v3/docker"
	"github.com/stretchr/testify/require"

	"github.com/go-ldap/ldap/v3"
)

const libraryConflictLDIF = `dn: cn=svc-blue,dc=example,dc=org
changetype: add
objectClass: inetOrgPerson
cn: svc-blue
sn: Blue
givenName: ServiceBlue
userPassword: password1

dn: cn=svc-green,dc=example,dc=org
changetype: add
objectClass: inetOrgPerson
cn: svc-green
sn: Green
givenName: ServiceGreen
userPassword: password2

dn: cn=svc-lib,dc=example,dc=org
changetype: add
objectClass: inetOrgPerson
cn: svc-lib
sn: Library
givenName: ServiceLib
userPassword: password3
`

// setupOpenLDAPForLibraryTest starts an OpenLDAP Docker container with three
// test users and returns the LDAP URL. The container is cleaned up when the
// test finishes.
func setupOpenLDAPForLibraryTest(t *testing.T) string {
	t.Helper()

	pool, err := dockertest.NewPool("")
	require.NoError(t, err)
	require.NoError(t, pool.Client.Ping())

	tempDir, err := os.MkdirTemp("", "ldif-lib")
	require.NoError(t, err)
	t.Cleanup(func() { os.RemoveAll(tempDir) })

	ldifFile := filepath.Join(tempDir, "custom.ldif")
	require.NoError(t, os.WriteFile(ldifFile, []byte(libraryConflictLDIF), 0o644))

	opts := dockertest.RunOptions{
		Repository: "osixia/openldap",
		Tag:        "1.5.0",
		PortBindings: map[docker.Port][]docker.PortBinding{
			"389/tcp": {{HostIP: "", HostPort: ""}},
		},
		Mounts: []string{ldifFile + ":/container/service/slapd/assets/config/bootstrap/ldif/custom.ldif"},
		Cmd:    []string{"--copy-service"},
	}

	resource, err := pool.RunWithOptions(&opts)
	require.NoError(t, err)
	t.Cleanup(func() {
		resource.Close()
		pool.Purge(resource)
	})

	hostPort := resource.GetHostPort("389/tcp")
	ldapURL := "ldap://" + hostPort

	// Wait for OpenLDAP to be ready
	err = pool.Retry(func() error {
		conn, err := ldap.DialURL(ldapURL)
		if err != nil {
			return err
		}
		defer conn.Close()
		if err := conn.Bind("cn=admin,dc=example,dc=org", "admin"); err != nil {
			return err
		}
		results, err := conn.Search(&ldap.SearchRequest{
			BaseDN: "dc=example,dc=org",
			Scope:  ldap.ScopeWholeSubtree,
			Filter: "(objectclass=inetOrgPerson)",
		})
		if err != nil {
			return err
		}
		if len(results.Entries) != 3 {
			return fmt.Errorf("expected 3 entries, got %d", len(results.Entries))
		}
		return nil
	})
	require.NoError(t, err)
	return ldapURL
}

// getOpenLDAPIntegrationBackend creates a backend with a real LDAP client.
func getOpenLDAPIntegrationBackend(t *testing.T) (*backend, logical.Storage) {
	t.Helper()
	b, storage := getBackend(false)
	b.client = NewClient(b.Logger())
	return b, storage
}

// TestOpenLDAP_LibrarySetConflict runs library set ↔ dual-account conflict
// tests against a real OpenLDAP Docker container.
func TestOpenLDAP_LibrarySetConflict(t *testing.T) {
	ldapURL := setupOpenLDAPForLibraryTest(t)
	ctx := context.Background()

	configureMount := func(t *testing.T, b *backend, storage logical.Storage) {
		t.Helper()
		resp, err := b.HandleRequest(ctx, &logical.Request{
			Operation: logical.CreateOperation,
			Path:      configPath,
			Storage:   storage,
			Data: map[string]interface{}{
				"binddn":   "cn=admin,dc=example,dc=org",
				"bindpass": "admin",
				"url":      ldapURL,
				"schema":   client.SchemaOpenLDAP,
				"userdn":   "dc=example,dc=org",
				"userattr": "cn",
			},
		})
		require.NoError(t, err)
		require.Nil(t, resp)
	}

	t.Run("library_blocks_dual_account_username_b", func(t *testing.T) {
		b, storage := getOpenLDAPIntegrationBackend(t)
		defer b.Cleanup(ctx)
		configureMount(t, b, storage)

		// Create library set with svc-lib
		resp, err := b.HandleRequest(ctx, &logical.Request{
			Operation: logical.CreateOperation,
			Path:      "library/test-lib",
			Storage:   storage,
			Data: map[string]interface{}{
				"service_account_names": []string{"svc-lib"},
				"ttl":                   "10h",
				"max_ttl":               "11h",
			},
		})
		require.NoError(t, err)
		require.Nil(t, resp)

		// Try dual-account role with username_b matching library user
		resp, err = b.HandleRequest(ctx, &logical.Request{
			Operation: logical.CreateOperation,
			Path:      staticRolePath + "conflict-role",
			Storage:   storage,
			Data: map[string]interface{}{
				"username":          "svc-blue",
				"dn":                "cn=svc-blue,dc=example,dc=org",
				"username_b":        "svc-lib",
				"dn_b":              "cn=svc-lib,dc=example,dc=org",
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
		b, storage := getOpenLDAPIntegrationBackend(t)
		defer b.Cleanup(ctx)
		configureMount(t, b, storage)

		// Create dual-account role first
		resp, err := b.HandleRequest(ctx, &logical.Request{
			Operation: logical.CreateOperation,
			Path:      staticRolePath + "dual-role",
			Storage:   storage,
			Data: map[string]interface{}{
				"username":          "svc-blue",
				"dn":                "cn=svc-blue,dc=example,dc=org",
				"username_b":        "svc-green",
				"dn_b":              "cn=svc-green,dc=example,dc=org",
				"rotation_period":   "3600s",
				"dual_account_mode": true,
				"grace_period":      "1800s",
			},
		})
		require.NoError(t, err)
		require.False(t, resp != nil && resp.IsError(), "dual-account role should succeed: %v", resp)

		// Try library set with username_b
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
		t.Logf("Correctly rejected: %s", resp.Data["error"])
	})

	t.Run("delete_dual_account_frees_usernames_for_library", func(t *testing.T) {
		b, storage := getOpenLDAPIntegrationBackend(t)
		defer b.Cleanup(ctx)
		configureMount(t, b, storage)

		// Create dual-account role
		resp, err := b.HandleRequest(ctx, &logical.Request{
			Operation: logical.CreateOperation,
			Path:      staticRolePath + "dual-role",
			Storage:   storage,
			Data: map[string]interface{}{
				"username":          "svc-blue",
				"dn":                "cn=svc-blue,dc=example,dc=org",
				"username_b":        "svc-green",
				"dn_b":              "cn=svc-green,dc=example,dc=org",
				"rotation_period":   "3600s",
				"dual_account_mode": true,
				"grace_period":      "1800s",
			},
		})
		require.NoError(t, err)
		require.False(t, resp != nil && resp.IsError(), "dual-account role should succeed: %v", resp)

		// Delete dual-account role
		resp, err = b.HandleRequest(ctx, &logical.Request{
			Operation: logical.DeleteOperation,
			Path:      staticRolePath + "dual-role",
			Storage:   storage,
		})
		require.NoError(t, err)

		// Both usernames should now be available for library set
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
		t.Log("Successfully reclaimed both usernames for library set after dual-account role deletion")
	})
}
