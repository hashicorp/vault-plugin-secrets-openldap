// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package openldap

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/hashicorp/vault/sdk/queue"
	"github.com/stretchr/testify/require"
)

func Test_backend_pathStaticRoleLifecycle(t *testing.T) {
	b, storage := getBackend(false)
	defer b.Cleanup(context.Background())
	ctx := context.Background()
	configureOpenLDAPMount(t, b, storage)

	tests := []struct {
		name          string
		createData    map[string]interface{}
		updateData    map[string]interface{}
		wantCreateErr bool
		wantUpdateErr bool
	}{
		{
			name: "missing required username results in create error",
			createData: map[string]interface{}{
				"rotation_period": float64(5),
			},
			wantCreateErr: true,
		},
		{
			name: "empty required username results in create error",
			createData: map[string]interface{}{
				"username":        "",
				"rotation_period": float64(5),
			},
			wantCreateErr: true,
		},
		{
			name: "missing required rotation_period results in create error",
			createData: map[string]interface{}{
				"username": "bob",
				"dn":       "uid=bob,ou=users,dc=hashicorp,dc=com",
			},
			wantCreateErr: true,
		},
		{
			name: "rotation_period less than 5 seconds results in create error",
			createData: map[string]interface{}{
				"username":        "bob",
				"dn":              "uid=bob,ou=users,dc=hashicorp,dc=com",
				"rotation_period": float64(2),
			},
			wantCreateErr: true,
		},
		{
			name: "modified username results in update error",
			createData: map[string]interface{}{
				"username":        "bob",
				"rotation_period": float64(5),
			},
			updateData: map[string]interface{}{
				"username": "alice",
			},
			wantUpdateErr: true,
		},
		{
			name: "including skip_import_rotation is an update error",
			createData: map[string]interface{}{
				"username":        "bob",
				"rotation_period": float64(5),
			},
			updateData: map[string]interface{}{
				"username":             "bob",
				"skip_import_rotation": false,
			},
			wantUpdateErr: true,
		},
		{
			name: "modified dn results in update error",
			createData: map[string]interface{}{
				"username":        "bob",
				"dn":              "uid=bob,ou=users,dc=hashicorp,dc=com",
				"rotation_period": float64(5),
			},
			updateData: map[string]interface{}{
				"username": "bob",
				"dn":       "uid=alice,ou=users,dc=hashicorp,dc=com",
			},
			wantUpdateErr: true,
		},
		{
			name: "successful static role update with only username",
			createData: map[string]interface{}{
				"username":        "bob",
				"rotation_period": float64(5),
			},
			updateData: map[string]interface{}{
				"username": "bob",
			},
		},
		{
			name: "successful static role update with missing dn",
			createData: map[string]interface{}{
				"username":        "bob",
				"dn":              "uid=bob,ou=users,dc=hashicorp,dc=com",
				"rotation_period": float64(5),
			},
			updateData: map[string]interface{}{
				"username":        "bob",
				"rotation_period": float64(20),
			},
		},
		{
			name: "successful static role update with empty dn",
			createData: map[string]interface{}{
				"username":        "bob",
				"dn":              "uid=bob,ou=users,dc=hashicorp,dc=com",
				"rotation_period": float64(5),
			},
			updateData: map[string]interface{}{
				"username": "bob",
				"dn":       "",
			},
		},
		{
			name: "successful static role update with new rotation_period",
			createData: map[string]interface{}{
				"username":        "bob",
				"dn":              "uid=bob,ou=users,dc=hashicorp,dc=com",
				"rotation_period": float64(5),
			},
			updateData: map[string]interface{}{
				"username":        "bob",
				"dn":              "uid=bob,ou=users,dc=hashicorp,dc=com",
				"rotation_period": float64(25),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// create the static role
			resp, err := createStaticRoleWithData(t, b, storage, "hashicorp", tt.createData)
			if tt.wantCreateErr {
				isErr := err != nil || (resp != nil && resp.IsError())
				require.True(t, isErr)
				return
			}

			t.Cleanup(func() {
				_, err = b.HandleRequest(ctx, &logical.Request{
					Operation: logical.DeleteOperation,
					Path:      staticRolePath + "hashicorp",
					Storage:   storage,
				})
				require.NoError(t, err)
			})

			// read the static role
			readReq := &logical.Request{
				Operation: logical.ReadOperation,
				Path:      staticRolePath + "hashicorp",
				Storage:   storage,
				Data:      nil,
			}
			resp, err = b.HandleRequest(ctx, readReq)
			require.NoError(t, err)
			require.NotNil(t, resp)
			require.False(t, resp.IsError())

			// assert response has expected fields
			for key, expected := range tt.createData {
				actual := resp.Data[key]
				if actual != expected {
					t.Fatalf("expected %v to be %v, got %v", key, expected, actual)
				}
			}
			require.NotEmpty(t, resp.Data["last_vault_rotation"])

			// update the static role
			req := &logical.Request{
				Operation: logical.UpdateOperation,
				Path:      staticRolePath + "hashicorp",
				Storage:   storage,
				Data:      tt.updateData,
			}
			resp, err = b.HandleRequest(ctx, req)
			if tt.wantUpdateErr {
				isErr := err != nil || (resp != nil && resp.IsError())
				require.True(t, isErr)
				return
			}

			// read the static role again
			resp, err = b.HandleRequest(ctx, readReq)
			require.NoError(t, err)
			require.NotNil(t, resp)
			require.False(t, resp.IsError())

			// assert response has expected fields
			for key, expected := range tt.updateData {
				actual := resp.Data[key]
				if actual != expected {
					t.Fatalf("expected %v to be %v, got %v", key, expected, actual)
				}
			}
			require.NotEmpty(t, resp.Data["last_vault_rotation"])
		})
	}
}

func TestRoles(t *testing.T) {
	t.Run("happy path with role using DN search", func(t *testing.T) {
		b, storage := getBackend(false)
		defer b.Cleanup(context.Background())

		configureOpenLDAPMount(t, b, storage)

		roleName := "hashicorp"
		data := map[string]interface{}{
			"username":        roleName,
			"dn":              "uid=hashicorp,ou=users,dc=hashicorp,dc=com",
			"rotation_period": float64(5),
		}

		resp, err := createStaticRoleWithData(t, b, storage, roleName, data)
		if err != nil || (resp != nil && resp.IsError()) {
			t.Fatalf("err:%s resp:%#v\n", err, resp)
		}

		assertReadStaticRole(t, b, storage, roleName, data)
	})
	t.Run("happy path with role using username search", func(t *testing.T) {
		b, storage := getBackend(false)
		defer b.Cleanup(context.Background())

		data := map[string]interface{}{
			"binddn":      "tester",
			"bindpass":    "pa$$w0rd",
			"url":         "ldap://138.91.247.105",
			"certificate": validCertificate,
			"userdn":      "ou=users,dc=hashicorp,dc=com",
		}

		req := &logical.Request{
			Operation: logical.CreateOperation,
			Path:      configPath,
			Storage:   storage,
			Data:      data,
		}

		resp, err := b.HandleRequest(context.Background(), req)
		if err != nil || (resp != nil && resp.IsError()) {
			t.Fatalf("err:%s resp:%#v\n", err, resp)
		}

		roleName := "hashicorp"
		data = map[string]interface{}{
			"username":        roleName,
			"dn":              "",
			"rotation_period": float64(5),
		}

		resp, err = createStaticRoleWithData(t, b, storage, roleName, data)
		if err != nil || (resp != nil && resp.IsError()) {
			t.Fatalf("err:%s resp:%#v\n", err, resp)
		}

		assertReadStaticRole(t, b, storage, roleName, data)
	})

	t.Run("happy path with skip_rotate set", func(t *testing.T) {
		b, storage := getBackend(false)
		defer b.Cleanup(context.Background())

		configureOpenLDAPMount(t, b, storage)

		data := map[string]interface{}{
			"username":             "hashicorp",
			"dn":                   "uid=hashicorp,ou=users,dc=hashicorp,dc=com",
			"rotation_period":      "10m",
			"skip_import_rotation": true,
		}

		resp, err := createStaticRoleWithData(t, b, storage, "hashicorp", data)
		if err != nil || (resp != nil && resp.IsError()) {
			t.Fatalf("err:%s resp:%#v\n", err, resp)
		}

		req := &logical.Request{
			Operation: logical.ReadOperation,
			Path:      staticRolePath + "hashicorp",
			Storage:   storage,
			Data:      nil,
		}

		resp, err = b.HandleRequest(context.Background(), req)
		if err != nil || (resp != nil && resp.IsError()) {
			t.Fatalf("err:%s resp:%#v\n", err, resp)
		}

		if resp.Data["dn"] != data["dn"] {
			t.Fatalf("expected dn to be %s but got %s", data["dn"], resp.Data["dn"])
		}

		if resp.Data["username"] != data["username"] {
			t.Fatalf("expected username to be %s but got %s", data["username"], resp.Data["username"])
		}

		if resp.Data["rotation_period"] != float64(600) {
			t.Fatalf("expected rotation_period to be %d but got %s", 5, resp.Data["rotation_period"])
		}

		if resp.Data["password"] != nil {
			t.Fatalf("expected password to be empty, but got %s", resp.Data["password"])
		}
	})

	t.Run("missing username", func(t *testing.T) {
		b, storage := getBackend(false)
		defer b.Cleanup(context.Background())

		configureOpenLDAPMount(t, b, storage)

		data := map[string]interface{}{
			"dn":              "uid=hashicorp,ou=users,dc=hashicorp,dc=com",
			"rotation_period": "5s",
		}

		resp, _ := createStaticRoleWithData(t, b, storage, "hashicorp", data)
		if resp == nil || !resp.IsError() {
			t.Fatal("expected error")
		}
	})

	t.Run("missing rotation_period", func(t *testing.T) {
		b, storage := getBackend(false)
		defer b.Cleanup(context.Background())

		configureOpenLDAPMount(t, b, storage)

		data := map[string]interface{}{
			"username": "hashicorp",
			"dn":       "uid=hashicorp,ou=users,dc=hashicorp,dc=com",
		}

		resp, _ := createStaticRoleWithData(t, b, storage, "hashicorp", data)
		if resp == nil || !resp.IsError() {
			t.Fatal("expected error")
		}
	})

	t.Run("rotation_period lower than 5s", func(t *testing.T) {
		b, storage := getBackend(false)
		defer b.Cleanup(context.Background())

		configureOpenLDAPMount(t, b, storage)

		data := map[string]interface{}{
			"username":        "hashicorp",
			"dn":              "uid=hashicorp,ou=users,dc=hashicorp,dc=com",
			"rotation_period": "4s",
		}

		resp, _ := createStaticRoleWithData(t, b, storage, "hashicorp", data)
		if resp == nil || !resp.IsError() {
			t.Fatal("expected error")
		}
	})

	t.Run("user doesn't exist (ldap error)", func(t *testing.T) {
		b, storage := getBackend(true)
		defer b.Cleanup(context.Background())

		configureOpenLDAPMount(t, b, storage)

		data := map[string]interface{}{
			"username":        "hashicorp",
			"dn":              "uid=hashicorp,ou=users,dc=hashicorp,dc=com",
			"rotation_period": "5s",
		}

		_, err := createStaticRoleWithData(t, b, storage, "hashicorp", data)
		if err == nil {
			t.Fatal("expected error, got none")
		}
	})

	t.Run("role doesn't exist", func(t *testing.T) {
		b, storage := getBackend(false)
		defer b.Cleanup(context.Background())

		req := &logical.Request{
			Operation: logical.ReadOperation,
			Path:      staticRolePath + "hashicorp",
			Storage:   storage,
			Data:      nil,
		}

		resp, err := b.HandleRequest(context.Background(), req)
		if err != nil {
			t.Fatalf("error reading role: %s", err)
		}
		if resp != nil {
			t.Fatal("expected error")
		}
	})

	t.Run("happy path with hierarchical role path", func(t *testing.T) {
		b, storage := getBackend(false)
		defer b.Cleanup(context.Background())

		configureOpenLDAPMount(t, b, storage)

		roles := []string{"org/secure", "org/platform/dev", "org/platform/support"}

		// create all the roles
		for _, role := range roles {
			data := getTestStaticRoleConfig(role)
			resp, err := createStaticRoleWithData(t, b, storage, role, data)
			if err != nil || (resp != nil && resp.IsError()) {
				t.Fatalf("err:%s resp:%#v\n", err, resp)
			}
		}

		// read all the roles
		for _, role := range roles {
			data := getTestStaticRoleConfig(role)
			assertReadStaticRole(t, b, storage, role, data)
		}
	})
}

func TestRoles_NewPasswordGeneration(t *testing.T) {
	ctx := context.Background()
	b, storage := getBackend(false)
	defer b.Cleanup(ctx)
	configureOpenLDAPMount(t, b, storage)

	// Create the role
	roleName := "hashicorp"
	createRole(t, b, storage, roleName)

	t.Run("rotation failures should generate new password on retry", func(t *testing.T) {
		// Fail to rotate the role
		generateWALFromFailedRotation(t, b, storage, roleName)

		// Get WAL
		walIDs := requireWALs(t, storage, 1)
		wal, err := b.findStaticWAL(ctx, storage, walIDs[0])
		if err != nil || wal == nil {
			t.Fatal(err)
		}

		// Store password
		initialPassword := wal.NewPassword

		// Rotate role manually and fail again with same password
		generateWALFromFailedRotation(t, b, storage, roleName)

		// Ensure WAL is deleted since retrying initial password failed
		requireWALs(t, storage, 0)

		// Successfully rotate the role
		_, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "rotate-role/" + roleName,
			Storage:   storage,
		})
		if err != nil {
			t.Fatal(err)
		}

		// Ensure WAL is flushed since request was successful
		requireWALs(t, storage, 0)

		// Read the credential
		resp := readStaticCred(t, b, storage, roleName)

		// Confirm successful rotation used new credential
		// Assert previous failing credential is not being used
		if resp.Data["password"] == initialPassword {
			t.Fatalf("expected password to be different after second retry")
		}
	})

	t.Run("updating password policy should generate new password", func(t *testing.T) {
		// Fail to rotate the role
		generateWALFromFailedRotation(t, b, storage, roleName)

		// Get WAL
		walIDs := requireWALs(t, storage, 1)
		wal, err := b.findStaticWAL(ctx, storage, walIDs[0])
		if err != nil || wal == nil {
			t.Fatal(err)
		}

		expectedPassword := wal.NewPassword

		// Update Password Policy
		configureOpenLDAPMountWithPasswordPolicy(t, b, storage, testPasswordPolicy1, true)

		// Rotate role manually and fail again
		generateWALFromFailedRotation(t, b, storage, roleName)
		// Get WAL
		walIDs = requireWALs(t, storage, 1)
		wal, err = b.findStaticWAL(ctx, storage, walIDs[0])
		if err != nil || wal == nil {
			t.Fatal(err)
		}

		// confirm new password is generated and is different from previous password
		newPassword := wal.NewPassword
		if expectedPassword == newPassword {
			t.Fatalf("expected password to be different on second retry")
		}

		// confirm new password uses policy
		if newPassword != testPasswordFromPolicy1 {
			t.Fatalf("expected password %s, got %s", testPasswordFromPolicy1, newPassword)
		}

		// Successfully rotate the role
		_, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "rotate-role/" + roleName,
			Storage:   storage,
		})
		if err != nil {
			t.Fatal(err)
		}

		// Ensure WAL is flushed
		walIDs = requireWALs(t, storage, 0)
	})
}

func TestListRoles(t *testing.T) {
	t.Run("list roles", func(t *testing.T) {
		b, storage := getBackend(false)
		defer b.Cleanup(context.Background())

		configureOpenLDAPMount(t, b, storage)

		data := map[string]interface{}{
			"username":        "hashicorp",
			"dn":              "uid=hashicorp,ou=users,dc=hashicorp,dc=com",
			"rotation_period": "5s",
		}

		resp, err := createStaticRoleWithData(t, b, storage, "hashicorp", data)
		if err != nil || (resp != nil && resp.IsError()) {
			t.Fatalf("err:%s resp:%#v\n", err, resp)
		}

		data = map[string]interface{}{
			"username":        "vault",
			"dn":              "uid=vault,ou=users,dc=hashicorp,dc=com",
			"rotation_period": "5s",
		}

		resp, err = createStaticRoleWithData(t, b, storage, "vault", data)
		if err != nil || (resp != nil && resp.IsError()) {
			t.Fatalf("err:%s resp:%#v\n", err, resp)
		}

		req := &logical.Request{
			Operation: logical.ListOperation,
			Path:      staticRolePath,
			Storage:   storage,
			Data:      nil,
		}

		resp, err = b.HandleRequest(context.Background(), req)
		if err != nil || (resp != nil && resp.IsError()) {
			t.Fatalf("err:%s resp:%#v\n", err, resp)
		}

		if len(resp.Data["keys"].([]string)) != 2 {
			t.Fatalf("expected list with %d keys, got %d", 2, len(resp.Data["keys"].([]string)))
		}
	})

	t.Run("list roles with hierarchical role path", func(t *testing.T) {
		b, storage := getBackend(false)
		defer b.Cleanup(context.Background())

		configureOpenLDAPMount(t, b, storage)

		roles := []string{"org/secure", "org/platform/dev", "org/platform/support"}

		// create all the roles
		for _, role := range roles {
			data := getTestStaticRoleConfig(role)
			resp, err := createStaticRoleWithData(t, b, storage, role, data)
			if err != nil || (resp != nil && resp.IsError()) {
				t.Fatalf("err:%s resp:%#v\n", err, resp)
			}
		}

		rolePaths := []string{"org/", "org/platform/"}
		for _, rolePath := range rolePaths {
			req := &logical.Request{
				Operation: logical.ListOperation,
				Path:      staticRolePath + rolePath,
				Storage:   storage,
				Data:      nil,
			}
			resp, err := b.HandleRequest(context.Background(), req)
			if err != nil || (resp != nil && resp.IsError()) {
				t.Fatalf("path: %s, err:%s resp:%#v\n", rolePath, err, resp)
			}

			keys := resp.Data["keys"].([]string)
			if len(keys) != 2 {
				t.Fatalf("expected list with %d keys, got %d", 2, len(keys))
			}
		}
	})
}

func TestWALsStillTrackedAfterUpdate(t *testing.T) {
	ctx := context.Background()
	b, storage := getBackend(false)
	defer b.Cleanup(ctx)
	configureOpenLDAPMount(t, b, storage)

	createRole(t, b, storage, "hashicorp")

	generateWALFromFailedRotation(t, b, storage, "hashicorp")
	requireWALs(t, storage, 1)

	_, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      staticRolePath + "hashicorp",
		Storage:   storage,
		Data: map[string]interface{}{
			"username":        "hashicorp",
			"dn":              "uid=hashicorp,ou=users,dc=hashicorp,dc=com",
			"rotation_period": "600s",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	walIDs := requireWALs(t, storage, 1)

	// Now when we trigger a manual rotate, it should use the WAL's new password
	// which will tell us that the in-memory structure still kept track of the
	// WAL in addition to it still being in storage.
	wal, err := b.findStaticWAL(ctx, storage, walIDs[0])
	if err != nil {
		t.Fatal(err)
	}
	_, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "rotate-role/hashicorp",
		Storage:   storage,
	})
	if err != nil {
		t.Fatal(err)
	}
	role, err := b.staticRole(ctx, storage, "hashicorp")
	if err != nil {
		t.Fatal(err)
	}
	if role.StaticAccount.Password != wal.NewPassword {
		t.Fatal()
	}
	requireWALs(t, storage, 0)
}

func TestWALsDeletedOnRoleCreationFailed(t *testing.T) {
	ctx := context.Background()
	b, storage := getBackend(true)
	defer b.Cleanup(ctx)
	configureOpenLDAPMount(t, b, storage)

	for i := 0; i < 3; i++ {
		data := map[string]interface{}{
			"username":        "hashicorp",
			"dn":              "uid=hashicorp,ou=users,dc=hashicorp,dc=com",
			"rotation_period": "5s",
		}
		resp, err := createStaticRoleWithData(t, b, storage, "hashicorp", data)
		if err == nil {
			t.Fatal("expected error from OpenLDAP")
		}
		if !strings.Contains(err.Error(), "forced error") {
			t.Fatal("expected forced error message", resp, err)
		}
	}

	requireWALs(t, storage, 0)
}

func TestWALsDeletedOnRoleDeletion(t *testing.T) {
	ctx := context.Background()
	b, storage := getBackend(false)
	defer b.Cleanup(ctx)
	configureOpenLDAPMount(t, b, storage)

	// Create the roles
	roleNames := []string{"hashicorp", "2"}
	for _, roleName := range roleNames {
		createRole(t, b, storage, roleName)
	}

	// Fail to rotate the roles
	for _, roleName := range roleNames {
		generateWALFromFailedRotation(t, b, storage, roleName)
	}

	// Should have 2 WALs hanging around
	requireWALs(t, storage, 2)

	// Delete one of the static roles
	_, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      "static-role/hashicorp",
		Storage:   storage,
	})
	if err != nil {
		t.Fatal(err)
	}

	// 1 WAL should be cleared by the delete
	requireWALs(t, storage, 1)
}

func configureOpenLDAPMount(t *testing.T, b *backend, storage logical.Storage) {
	t.Helper()

	configureOpenLDAPMountWithPasswordPolicy(t, b, storage, "", false)
}

func configureOpenLDAPMountWithPasswordPolicy(t *testing.T, b *backend, storage logical.Storage, policy string, isUpdate bool) {
	t.Helper()

	data := map[string]interface{}{
		"binddn":      "tester",
		"bindpass":    "pa$$w0rd",
		"url":         "ldap://138.91.247.105",
		"certificate": validCertificate,
	}

	if policy != "" {
		data["password_policy"] = policy
	}

	operation := logical.CreateOperation
	if isUpdate {
		operation = logical.UpdateOperation
	}
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: operation,
		Path:      configPath,
		Storage:   storage,
		Data:      data,
	})
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}
}

func createRole(t *testing.T, b *backend, storage logical.Storage, roleName string) {
	t.Helper()
	data := map[string]interface{}{
		"username":        roleName,
		"dn":              "uid=hashicorp,ou=users,dc=hashicorp,dc=com",
		"rotation_period": "86400s",
	}
	_, err := createStaticRoleWithData(t, b, storage, roleName, data)
	if err != nil {
		t.Fatal(err)
	}
}

func createStaticRoleWithData(t *testing.T, b *backend, s logical.Storage, name string, d map[string]interface{}) (*logical.Response, error) {
	t.Helper()
	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      staticRolePath + name,
		Storage:   s,
		Data:      d,
	}

	return b.HandleRequest(context.Background(), req)
}

func updateStaticRoleWithData(t *testing.T, b *backend, s logical.Storage, name string, d map[string]interface{}) (*logical.Response, error) {
	t.Helper()

	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      staticRolePath + name,
		Storage:   s,
		Data:      d,
	}

	return b.HandleRequest(context.Background(), req)
}

func readStaticRole(t *testing.T, b *backend, storage logical.Storage, roleName string) (*logical.Response, error) {
	req := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      staticRolePath + roleName,
		Storage:   storage,
		Data:      nil,
	}

	return b.HandleRequest(context.Background(), req)
}

func assertReadStaticRole(t *testing.T, b *backend, storage logical.Storage, roleName string, data map[string]interface{}) {
	t.Helper()
	resp, err := readStaticRole(t, b, storage, roleName)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	if resp.Data["dn"] != data["dn"] {
		t.Fatalf("expected dn to be %s but got %s", data["dn"], resp.Data["dn"])
	}

	if resp.Data["username"] != data["username"] {
		t.Fatalf("expected username to be %s but got %s", data["username"], resp.Data["username"])
	}

	expected := data["rotation_period"].(float64)
	if resp.Data["rotation_period"] != expected {
		t.Fatalf("expected rotation_period to be %f but got %s", expected, resp.Data["rotation_period"])
	}

	if resp.Data["last_vault_rotation"] == nil {
		t.Fatal("expected last_vault_rotation to not be empty")
	}
}

func getTestStaticRoleConfig(name string) map[string]interface{} {
	return map[string]interface{}{
		"username":        name,
		"dn":              "uid=hashicorp,ou=users,dc=hashicorp,dc=com",
		"rotation_period": float64(5),
	}
}

func TestStaticRole_NextVaultRotation(t *testing.T) {
	t.Run("creating/updating static role properly sets queue and storage values", func(t *testing.T) {
		ctx := context.Background()
		b, storage := getBackend(false)
		defer b.Cleanup(ctx)
		configureOpenLDAPMount(t, b, storage)
		start := time.Now()

		// Create static role
		roleName := "hashicorp"
		data1 := map[string]interface{}{
			"username":        "hashicorp",
			"db_name":         "mockv5",
			"rotation_period": "10m",
		}
		createStaticRoleWithData(t, b, storage, roleName, data1)

		// Check role's storage values
		role1, _ := b.staticRole(ctx, storage, roleName)
		require.True(t, role1.StaticAccount.LastVaultRotation.After(start), "LastVaultRotation should be set on role create")
		require.True(t, role1.StaticAccount.NextVaultRotation.After(role1.StaticAccount.LastVaultRotation), "NextVaultRotation should be after LastVaultRotation")

		// Check role's priority queue value is the same as what is in storage
		item1, err := b.credRotationQueue.Pop()
		require.NoError(t, err)
		require.Equal(t, item1.Priority, role1.StaticAccount.NextVaultRotation.Unix(), "queue's priority should be the same as NextVaultRotation in storage")
		err = b.credRotationQueue.Push(item1)
		require.NoError(t, err)

		// Update static role
		data2 := map[string]interface{}{
			"rotation_period": "2h",
			"username":        "hashicorp",
		}
		_, err = updateStaticRoleWithData(t, b, storage, roleName, data2)
		require.NoError(t, err)

		// Check role's storage values
		role2, err := b.staticRole(ctx, storage, roleName)
		require.NoError(t, err)
		require.Equal(t, role1.StaticAccount.LastVaultRotation, role2.StaticAccount.LastVaultRotation, "static role's LastVaultRotation should not change on update")
		require.True(t, role2.StaticAccount.NextVaultRotation.After(role1.StaticAccount.NextVaultRotation), "NextVaultRotation should be adjusted because rotation period changed")

		// Check priority queue value is the same as what is in storage
		item2, err := b.credRotationQueue.Pop()
		require.Equal(t, 0, b.credRotationQueue.Len(), "queue should be empty after pop")
		require.NoError(t, err)
		require.Greater(t, item2.Priority, item1.Priority, "priority queue's priority should be adjusted because rotation period changed")
		require.Equal(t, item2.Priority, role2.StaticAccount.NextVaultRotation.Unix(), "queue's priority should be the same as NextVaultRotation in storage")
	})

	t.Run("creating/updating static role properly sets queue and storage values when skip_import_rotation is true", func(t *testing.T) {
		ctx := context.Background()
		b, storage := getBackend(false)
		defer b.Cleanup(ctx)
		configureOpenLDAPMount(t, b, storage)
		start := time.Now()

		// Create static role
		roleName := "hashicorp"
		data1 := map[string]interface{}{
			"username":             "hashicorp",
			"db_name":              "mockv5",
			"rotation_period":      "10m",
			"skip_import_rotation": true,
		}
		createStaticRoleWithData(t, b, storage, roleName, data1)

		// Check role's storage values
		role1, err := b.staticRole(ctx, storage, roleName)
		require.NoError(t, err)

		// Check that LastVaultRotation is zero value
		require.Equal(t, role1.StaticAccount.LastVaultRotation, time.Time{}, "LastVaultRotation should be 0 on role create when skip_import_rotation is true")
		require.True(t, role1.StaticAccount.NextVaultRotation.After(start), "NextVaultRotation should be set on role create")

		// Check role's priority queue value is the same as what is in storage
		require.Equal(t, b.credRotationQueue.Len(), 1)
		item1, err := b.credRotationQueue.Pop()
		require.NoError(t, err)
		require.Equal(t, item1.Priority, role1.StaticAccount.NextVaultRotation.Unix(), "queue's priority should be the same as NextVaultRotation in storage")

		// Push item back onto queue
		err = b.credRotationQueue.Push(item1)
		require.NoError(t, err)

		// Update static role
		data2 := map[string]interface{}{
			"rotation_period": "2h",
			"username":        "hashicorp",
		}
		_, err = updateStaticRoleWithData(t, b, storage, roleName, data2)
		require.NoError(t, err)

		// Check role's storage values
		role2, err := b.staticRole(ctx, storage, roleName)
		require.NoError(t, err)
		require.Equal(t, role2.StaticAccount.LastVaultRotation, time.Time{}, "updating should not change LastVaultRotation")
		require.Equal(t, role1.StaticAccount.LastVaultRotation, role2.StaticAccount.LastVaultRotation)
		require.True(t, role2.StaticAccount.NextVaultRotation.After(role1.StaticAccount.NextVaultRotation), "updating rotation_period should increase NextVaultRotation")

		// Check priority queue value is the same as what is in storage
		require.Equal(t, b.credRotationQueue.Len(), 1)
		item2, err := b.credRotationQueue.Pop()
		require.NoError(t, err)
		require.Greater(t, item2.Priority, item1.Priority, "priority should increase after updating rotation_period")
		require.Equal(t, item2.Priority, role2.StaticAccount.NextVaultRotation.Unix(), "queue's priority should be the same as NextVaultRotation in storage")
	})

	t.Run("automatic rotation of static role properly sets queue and storage values", func(t *testing.T) {
		ctx := context.Background()
		b, storage := getBackend(false)
		defer b.Cleanup(ctx)
		configureOpenLDAPMount(t, b, storage)
		start := time.Now()

		// Create static role
		roleName := "hashicorp"

		data1 := map[string]interface{}{
			"username":        "hashicorp",
			"db_name":         "mockv5",
			"rotation_period": "5s",
		}
		createStaticRoleWithData(t, b, storage, roleName, data1)

		// Check role's storage values
		role1, err := b.staticRole(ctx, storage, roleName)
		require.NoError(t, err)
		require.True(t, role1.StaticAccount.LastVaultRotation.After(start))
		require.True(t, role1.StaticAccount.NextVaultRotation.After(role1.StaticAccount.LastVaultRotation))

		// Check role's priority queue value is the same as what is in storage
		require.Equal(t, b.credRotationQueue.Len(), 1)
		item1, err := b.credRotationQueue.Pop()
		require.NoError(t, err)
		require.Equal(t, item1.Priority, role1.StaticAccount.NextVaultRotation.Unix())
		// Push item back onto queue
		err = b.credRotationQueue.Push(item1)

		// Wait until ticker has run
		time.Sleep(6 * time.Second)

		// Ensure the item's priority has changed indicating an autorotation
		item2, err := b.credRotationQueue.Pop()
		require.NoError(t, err)
		require.Greater(t, item2.Priority, item1.Priority)

		// Check role's storage values
		role2, err := b.staticRole(ctx, storage, roleName)
		require.NoError(t, err)
		require.Greater(t, role2.StaticAccount.LastVaultRotation, role1.StaticAccount.LastVaultRotation, "LastVaultRotation should be greater after auto rotation")
		require.True(t, role2.StaticAccount.NextVaultRotation.After(role1.StaticAccount.NextVaultRotation), "NextVaultRotation should be greater after auto rotation")

		// Check priority queue value is the same as what is in storage
		require.Greater(t, item2.Priority, item1.Priority, "items priority should be greater after auto rotation")
		require.Equal(t, item2.Priority, role2.StaticAccount.NextVaultRotation.Unix(), "queue's priority should be the same as NextVaultRotation in storage")
	})

	t.Run("automatic rotation of static role properly sets queue and storage values when skip_import_rotation is true", func(t *testing.T) {
		ctx := context.Background()
		b, storage := getBackend(false)
		defer b.Cleanup(ctx)
		configureOpenLDAPMount(t, b, storage)
		start := time.Now()

		// Create static role
		roleName := "hashicorp"

		data1 := map[string]interface{}{
			"username":             "hashicorp",
			"db_name":              "mockv5",
			"rotation_period":      "5s",
			"skip_import_rotation": true,
		}
		createStaticRoleWithData(t, b, storage, roleName, data1)

		// Check role's storage values
		role1, err := b.staticRole(ctx, storage, roleName)
		require.NoError(t, err)
		require.Equal(t, role1.StaticAccount.LastVaultRotation, time.Time{})
		require.True(t, role1.StaticAccount.NextVaultRotation.After(start))

		// Check role's priority queue value is the same as what is in storage
		require.Equal(t, b.credRotationQueue.Len(), 1)
		item1, err := b.credRotationQueue.Pop()
		require.NoError(t, err)
		require.Equal(t, item1.Priority, role1.StaticAccount.NextVaultRotation.Unix())
		// Push item back onto queue
		err = b.credRotationQueue.Push(item1)

		// Wait until ticker has run
		time.Sleep(6 * time.Second)

		// Check role's storage values
		role2, err := b.staticRole(ctx, storage, roleName)
		require.NoError(t, err)
		require.NotEqual(t, role2.StaticAccount.LastVaultRotation, time.Time{}, "LastVaultRotation should be set after auto rotation")
		require.True(t, role2.StaticAccount.NextVaultRotation.After(role1.StaticAccount.NextVaultRotation), "NextVaultRotation should be increased after auto rotation")

		// Check priority queue value is the same as what is in storage
		item2, err := b.credRotationQueue.Pop()
		require.NoError(t, err)
		require.Greater(t, item2.Priority, item1.Priority, "item's priority should be greater after auto rotation")
		require.Equal(t, item2.Priority, role2.StaticAccount.NextVaultRotation.Unix(), "")
	})

	t.Run("manual rotation of static role properly sets queue and storage values", func(t *testing.T) {
		ctx := context.Background()
		b, storage := getBackend(false)
		defer b.Cleanup(ctx)
		configureOpenLDAPMount(t, b, storage)
		start := time.Now()

		// Create static role
		roleName := "hashicorp"

		data1 := map[string]interface{}{
			"username":        "hashicorp",
			"db_name":         "mockv5",
			"rotation_period": "10m",
		}
		createStaticRoleWithData(t, b, storage, roleName, data1)

		// Check role's storage values
		role1, err := b.staticRole(ctx, storage, roleName)
		require.NoError(t, err)
		require.True(t, role1.StaticAccount.LastVaultRotation.After(start))
		require.True(t, role1.StaticAccount.NextVaultRotation.After(role1.StaticAccount.LastVaultRotation))

		// Check role's priority queue value is the same as what is in storage
		require.Equal(t, b.credRotationQueue.Len(), 1)
		item1, err := b.credRotationQueue.Pop()
		require.NoError(t, err)
		require.Equal(t, item1.Priority, role1.StaticAccount.NextVaultRotation.Unix())

		// Add sleep so that we can see the difference in priority timestamps (measured in seconds)
		time.Sleep(1 * time.Second)

		data := map[string]interface{}{"name": roleName}

		_, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "rotate-role/" + roleName,
			Storage:   storage,
			Data:      data,
		})
		require.NoError(t, err)
		// Check role's storage values

		role2, err := b.staticRole(ctx, storage, roleName)
		require.NoError(t, err)
		require.True(t, role2.StaticAccount.LastVaultRotation.After(role1.StaticAccount.LastVaultRotation))
		require.True(t, role2.StaticAccount.NextVaultRotation.After(role1.StaticAccount.NextVaultRotation))

		// Check priority queue value is the same as what is in storage
		require.Equal(t, b.credRotationQueue.Len(), 1)
		item2, err := b.credRotationQueue.Pop()
		require.NoError(t, err)
		require.Greater(t, item2.Priority, item1.Priority)
		require.Equal(t, item2.Priority, role2.StaticAccount.NextVaultRotation.Unix())
	})

	t.Run("manual rotation of static role properly sets queue and storage values when skip_import_rotation is true", func(t *testing.T) {
		ctx := context.Background()
		b, storage := getBackend(false)
		defer b.Cleanup(ctx)
		configureOpenLDAPMount(t, b, storage)
		start := time.Now()

		// Create static role
		roleName := "hashicorp"

		data1 := map[string]interface{}{
			"username":             "hashicorp",
			"db_name":              "mockv5",
			"rotation_period":      "10m",
			"skip_import_rotation": true,
		}
		createStaticRoleWithData(t, b, storage, roleName, data1)

		// Check role's storage values
		role1, err := b.staticRole(ctx, storage, roleName)
		require.NoError(t, err)
		require.Equal(t, role1.StaticAccount.LastVaultRotation, time.Time{})
		require.True(t, role1.StaticAccount.NextVaultRotation.After(start))

		// Check role's priority queue value is the same as what is in storage
		require.Equal(t, b.credRotationQueue.Len(), 1)
		item1, err := b.credRotationQueue.Pop()
		require.NoError(t, err)
		require.Equal(t, item1.Priority, role1.StaticAccount.NextVaultRotation.Unix())
		err = b.credRotationQueue.Push(item1)

		// Add sleep so that we can see the difference in priority timestamps (measured in seconds)
		time.Sleep(1 * time.Second)

		data := map[string]interface{}{"name": roleName}

		_, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "rotate-role/" + roleName,
			Storage:   storage,
			Data:      data,
		})
		require.NoError(t, err)

		// Check role's storage values
		role2, err := b.staticRole(ctx, storage, roleName)
		require.NoError(t, err)
		require.NotEqual(t, role2.StaticAccount.LastVaultRotation, time.Time{}, "LastVaultRotation should be set after auto rotation")
		require.True(t, role2.StaticAccount.NextVaultRotation.After(role1.StaticAccount.NextVaultRotation), "NextVaultRotation should increase after auto rotation")

		// Check priority queue value is the same as what is in storage
		require.Equal(t, b.credRotationQueue.Len(), 1)
		item2, err := b.credRotationQueue.Pop()
		require.NoError(t, err)
		require.Greater(t, item2.Priority, item1.Priority, "item's priority should be greater after auto rotation")
		require.Equal(t, item2.Priority, role2.StaticAccount.NextVaultRotation.Unix(), "queue's priority should be the same as NextVaultRotation in storage")
	})
}

func Test_staticRolesUpdateRotationPeriod(t *testing.T) {
	tests := []struct {
		name               string
		skipImportRotation bool
	}{
		{
			name:               "skip_import_rotation is true",
			skipImportRotation: true,
		},
		{
			name:               "skip_import_rotation is false",
			skipImportRotation: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			b, storage := getBackend(false)
			defer b.Cleanup(ctx)
			configureOpenLDAPMount(t, b, storage)
			var start time.Time
			if !tt.skipImportRotation {
				start = time.Now()
			}
			// Create static role
			roleName := "hashicorp"

			d1 := map[string]interface{}{
				"username":        "hashicorp",
				"db_name":         "mockv5",
				"rotation_period": "5s",
			}
			createStaticRoleWithData(t, b, storage, roleName, d1)

			role1, err := b.staticRole(ctx, storage, roleName)
			require.NoError(t, err)
			checkLVRandNVRAfterCreate(t, role1, start)
			item1, err := b.credRotationQueue.Pop()
			require.NoError(t, err)
			checkPriority(t, item1, role1.StaticAccount.NextVaultRotation)
			b.credRotationQueue.Push(item1)

			d2 := map[string]interface{}{
				"rotation_period": "2h",
				"username":        "hashicorp",
			}
			_, err = updateStaticRoleWithData(t, b, storage, roleName, d2)

			role2, err := b.staticRole(ctx, storage, roleName)
			require.NoError(t, err)
			compareLVRandNVRAfterUpdate(t, role1, role2, false)
			item2, err := b.credRotationQueue.Pop()
			require.NoError(t, err)
			checkPriority(t, item2, role2.StaticAccount.NextVaultRotation)
		})
	}
}

func checkLVRandNVRAfterCreate(t *testing.T, role *roleEntry, start time.Time) {
	require.NotNil(t, role)
	require.True(t, role.StaticAccount.LastVaultRotation.After(start))
	require.True(t, role.StaticAccount.NextVaultRotation.After(role.StaticAccount.LastVaultRotation))
}

func compareLVRandNVRAfterUpdate(t *testing.T, role1 *roleEntry, role2 *roleEntry, lvrChange bool) {
	require.NotNil(t, role2)
	if lvrChange {
		require.True(t, role2.StaticAccount.LastVaultRotation.After(role1.StaticAccount.LastVaultRotation))
	} else {
		require.Equal(t, role1.StaticAccount.LastVaultRotation, role2.StaticAccount.LastVaultRotation)
	}
	require.True(t, role2.StaticAccount.NextVaultRotation.After(role1.StaticAccount.LastVaultRotation))
}

func checkPriority(t *testing.T, item *queue.Item, nvr time.Time) {
	require.NotNil(t, item)
	require.Equal(t, item.Priority, nvr.Unix())
}
