package openldap

import (
	"context"
	"testing"
	"time"

	"github.com/hashicorp/vault/sdk/logical"
)

func TestAutoRotate(t *testing.T) {
	t.Run("auto rotate role", func(t *testing.T) {
		b, storage := getBackend(false)
		defer b.Cleanup(context.Background())

		data := map[string]interface{}{
			"binddn":      "tester",
			"bindpass":    "pa$$w0rd",
			"url":         "ldap://138.91.247.105",
			"certificate": validCertificate,
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

		req = &logical.Request{
			Operation: logical.CreateOperation,
			Path:      rotateRootPath,
			Storage:   storage,
			Data:      nil,
		}

		resp, err = b.HandleRequest(context.Background(), req)
		if err != nil || (resp != nil && resp.IsError()) {
			t.Fatalf("err:%s resp:%#v\n", err, resp)
		}

		data = map[string]interface{}{
			"username":        "hashicorp",
			"dn":              "uid=hashicorp,ou=users,dc=hashicorp,dc=com",
			"rotation_period": "5s",
		}

		req = &logical.Request{
			Operation: logical.CreateOperation,
			Path:      staticRolePath + "hashicorp",
			Storage:   storage,
			Data:      data,
		}

		resp, err = b.HandleRequest(context.Background(), req)
		if err != nil || (resp != nil && resp.IsError()) {
			t.Fatalf("err:%s resp:%#v\n", err, resp)
		}

		req = &logical.Request{
			Operation: logical.ReadOperation,
			Path:      staticCredPath + "hashicorp",
			Storage:   storage,
			Data:      nil,
		}

		resp, err = b.HandleRequest(context.Background(), req)
		if err != nil || (resp != nil && resp.IsError()) {
			t.Fatalf("err:%s resp:%#v\n", err, resp)
		}

		if resp.Data["password"] == "" {
			t.Fatal("expected password to be set, it wasn't")
		}
		oldPassword := resp.Data["password"]

		// Wait for auto rotation (5s) + 1 second for breathing room
		time.Sleep(time.Second * 6)

		req = &logical.Request{
			Operation: logical.ReadOperation,
			Path:      staticCredPath + "hashicorp",
			Storage:   storage,
			Data:      nil,
		}

		resp, err = b.HandleRequest(context.Background(), req)
		if err != nil || (resp != nil && resp.IsError()) {
			t.Fatalf("err:%s resp:%#v\n", err, resp)
		}

		if resp.Data["password"] == "" {
			t.Fatal("expected password to be set after auto rotation, it wasn't")
		}

		if oldPassword == resp.Data["password"] {
			t.Fatal("expected passwords to be different after auto rotation, they weren't")
		}
	})
}

func TestRollsPasswordForwards(t *testing.T) {
	ctx := context.Background()
	b, storage := getBackend(false)
	defer b.Cleanup(ctx)
	configureOpenLDAPMount(t, b, storage)

	// Create the role
	_, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "static-role/hashicorp",
		Storage:   storage,
		Data: map[string]interface{}{
			"username":        "hashicorp",
			"dn":              "uid=hashicorp,ou=users,dc=hashicorp,dc=com",
			"rotation_period": "86400s",
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	generateWALFromFailedRotation(t, b, storage, "hashicorp")
	walIDs, err := storage.List(context.Background(), "wal/")
	if err != nil {
		t.Fatal(err)
	}
	if len(walIDs) != 1 {
		t.Fatal("expected 1 WAL, got", len(walIDs))
	}
	wal, err := b.findStaticWAL(ctx, storage, walIDs[0])
	if err != nil {
		t.Fatal(err)
	}
	role, err := b.staticRole(ctx, storage, "hashicorp")
	if err != nil {
		t.Fatal(err)
	}
	// Role's password should still be the WAL's old password
	if role.StaticAccount.Password != wal.OldPassword {
		t.Fatal(role.StaticAccount.Password, wal.OldPassword)
	}

	// Trigger a retry on the rotation, it should use WAL's new password
	_, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "rotate-role/hashicorp",
		Storage:   storage,
	})
	if err != nil {
		t.Fatal(err)
	}

	role, err = b.staticRole(ctx, storage, "hashicorp")
	if err != nil {
		t.Fatal(err)
	}
	if role.StaticAccount.Password != wal.NewPassword {
		t.Fatal(role.StaticAccount.Password, wal.NewPassword)
	}
	// WAL should be cleared by the successful rotate
	requireWALs(t, storage, 0)
}

func generateWALFromFailedRotation(t *testing.T, b *backend, storage logical.Storage, roleName string) {
	t.Helper()
	// Fail to rotate the roles
	ldapClient := b.client.(*fakeLdapClient)
	originalValue := ldapClient.throwErrs
	ldapClient.throwErrs = true
	defer func() {
		ldapClient.throwErrs = originalValue
	}()

	_, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "rotate-role/" + roleName,
		Storage:   storage,
	})
	if err == nil {
		t.Fatal("expected error")
	}
}

func requireWALs(t *testing.T, storage logical.Storage, expectedCount int) {
	t.Helper()
	wals, err := storage.List(context.Background(), "wal/")
	if err != nil {
		t.Fatal(err)
	}
	if len(wals) != expectedCount {
		t.Fatal("expected WALs", expectedCount, "got", len(wals))
	}
}
