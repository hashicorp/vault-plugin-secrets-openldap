// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package openldap

import (
	"context"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
)

func TestCreds(t *testing.T) {
	t.Run("happy path with creds", func(t *testing.T) {
		b, storage := getBackend(false)
		defer b.Cleanup(context.Background())
		configureOpenLDAPMount(t, b, storage)

		roleName := "hashicorp"
		data := getTestStaticRoleConfig(roleName)
		createStaticRoleWithData(t, b, storage, roleName, data)
		assertReadStaticCred(t, b, storage, roleName, data)
	})

	t.Run("happy path with hierarchical cred path", func(t *testing.T) {
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

		// read all the creds
		for _, role := range roles {
			data := getTestStaticRoleConfig(role)
			assertReadStaticCred(t, b, storage, role, data)
		}
	})

	t.Run("cred doesn't exist", func(t *testing.T) {
		b, storage := getBackend(false)
		defer b.Cleanup(context.Background())

		req := &logical.Request{
			Operation: logical.ReadOperation,
			Path:      staticCredPath + "hashicorp",
			Storage:   storage,
		}

		resp, err := b.HandleRequest(context.Background(), req)
		if err != nil {
			t.Fatalf("error reading cred: %s", err)
		}
		if resp == nil || !resp.IsError() {
			t.Fatal("expected error")
		}
	})
}

func readStaticCred(t *testing.T, b *backend, storage logical.Storage, roleName string) *logical.Response {
	t.Helper()
	req := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      staticCredPath + roleName,
		Storage:   storage,
	}

	resp, err := b.HandleRequest(context.Background(), req)
	if resp == nil || err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}
	return resp
}

func assertReadStaticCred(t *testing.T, b *backend, storage logical.Storage, roleName string, data map[string]interface{}) {
	t.Helper()
	resp := readStaticCred(t, b, storage, roleName)

	if resp.Data["dn"] != data["dn"] {
		t.Fatalf("expected dn to be %s but got %s", data["dn"], resp.Data["dn"])
	}

	if resp.Data["password"] == "" {
		t.Fatal("expected password to be set, it wasn't")
	}

	if resp.Data["username"] != data["username"] {
		t.Fatalf("expected username to be %s but got %s", data["username"], resp.Data["username"])
	}

	if resp.Data["last_vault_rotation"] == nil {
		t.Fatal("expected last_vault_rotation to be set, it wasn't")
	}

	if resp.Data["rotation_period"] != float64(5) {
		t.Fatalf("expected rotation_period to be %f but got %s", float64(5), resp.Data["rotation_period"])
	}

	if resp.Data["ttl"] == nil {
		t.Fatal("expected ttl to be set, it wasn't")
	}
}
