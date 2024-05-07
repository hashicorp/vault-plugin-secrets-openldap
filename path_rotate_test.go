// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package openldap

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/go-ldap/ldif"
	"github.com/hashicorp/go-secure-stdlib/strutil"
	"github.com/hashicorp/vault-plugin-secrets-openldap/client"
	"github.com/hashicorp/vault/sdk/helper/ldaputil"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/assert"
)

func TestManualRotateRoot(t *testing.T) {
	t.Run("happy path rotate root", func(t *testing.T) {
		b, storage := getBackend(false)
		defer b.Cleanup(context.Background())

		originalBindPass := "pa$$w0rd"

		data := map[string]interface{}{
			"binddn":      "tester",
			"bindpass":    originalBindPass,
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
			Operation: logical.UpdateOperation,
			Path:      rotateRootPath,
			Storage:   storage,
			Data:      nil,
		}

		resp, err = b.HandleRequest(context.Background(), req)
		if err != nil || (resp != nil && resp.IsError()) {
			t.Fatalf("err:%s resp:%#v\n", err, resp)
		}

		config, err := readConfig(context.Background(), storage)
		if err != nil {
			t.Fatalf("expected nil error, got %v", err)
		}
		if config.LDAP.LastBindPassword != originalBindPass {
			t.Fatalf("expected last_bind_password %q, got %q", originalBindPass,
				config.LDAP.LastBindPassword)
		}
		if config.LDAP.LastBindPasswordRotation.IsZero() {
			t.Fatal("expected last_bind_password_rotation to not be the zero time instant")
		}
	})

	t.Run("rotate root that doesn't exist", func(t *testing.T) {
		b, storage := getBackend(false)
		defer b.Cleanup(context.Background())

		req := &logical.Request{
			Operation: logical.CreateOperation,
			Path:      rotateRootPath,
			Storage:   storage,
			Data:      nil,
		}

		_, err := b.HandleRequest(context.Background(), req)
		if err == nil {
			t.Fatal("should have got error, didn't")
		}
	})
}

func TestManualRotateRole(t *testing.T) {
	t.Run("happy path rotate role", func(t *testing.T) {
		b, storage := getBackend(false)
		defer b.Cleanup(context.Background())

		roleName := "hashicorp"
		configureOpenLDAPMount(t, b, storage)
		createRole(t, b, storage, roleName)

		resp := readStaticCred(t, b, storage, roleName)

		if resp.Data["password"] == "" {
			t.Fatal("expected password to be set, it wasn't")
		}
		oldPassword := resp.Data["password"]

		req := &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      rotateRolePath + roleName,
			Storage:   storage,
			Data:      nil,
		}

		resp, err := b.HandleRequest(context.Background(), req)
		if err != nil || (resp != nil && resp.IsError()) {
			t.Fatalf("err:%s resp:%#v\n", err, resp)
		}

		resp = readStaticCred(t, b, storage, roleName)

		if resp.Data["password"] == "" {
			t.Fatal("expected password to be set after rotate, it wasn't")
		}

		if oldPassword == resp.Data["password"] {
			t.Fatal("expected passwords to be different after rotation, they weren't")
		}
	})

	t.Run("happy path rotate role with hierarchical path", func(t *testing.T) {
		b, storage := getBackend(false)
		defer b.Cleanup(context.Background())

		configureOpenLDAPMount(t, b, storage)

		roles := []string{"org/secure", "org/platform/dev", "org/platform/support"}

		// create all the roles
		for _, role := range roles {
			data := getTestStaticRoleConfig(role)
			createStaticRoleWithData(t, b, storage, role, data)
		}

		passwords := make([]string, 0)
		// rotate all the creds
		for _, role := range roles {
			resp := readStaticCred(t, b, storage, role)

			if resp.Data["password"] == "" {
				t.Fatal("expected password to be set, it wasn't")
			}
			oldPassword := resp.Data["password"]

			req := &logical.Request{
				Operation: logical.UpdateOperation,
				Path:      rotateRolePath + role,
				Storage:   storage,
				Data:      nil,
			}

			resp, err := b.HandleRequest(context.Background(), req)
			if err != nil || (resp != nil && resp.IsError()) {
				t.Fatalf("err:%s resp:%#v\n", err, resp)
			}

			resp = readStaticCred(t, b, storage, role)

			newPassword := resp.Data["password"]
			if newPassword == "" {
				t.Fatal("expected password to be set after rotate, it wasn't")
			}

			if oldPassword == newPassword {
				t.Fatal("expected passwords to be different after rotation, they weren't")
			}
			passwords = append(passwords, newPassword.(string))
		}

		// extra pendantic check that the hierarchical paths don't return the same data
		if len(passwords) != len(strutil.RemoveDuplicates(passwords, false)) {
			t.Fatal("expected unique static-role paths to return unique passwords")
		}
	})

	t.Run("rotate role that doesn't exist", func(t *testing.T) {
		b, storage := getBackend(false)
		defer b.Cleanup(context.Background())

		req := &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      rotateRolePath + "hashicorp",
			Storage:   storage,
			Data:      nil,
		}

		resp, _ := b.HandleRequest(context.Background(), req)
		if resp == nil || !resp.IsError() {
			t.Fatal("expected error")
		}
	})
}

type failingRollbackClient struct {
	count    int
	maxCount int
	password string
}

func (f *failingRollbackClient) UpdateDNPassword(conf *client.Config, dn string, newPassword string) error {
	f.count += 1
	if f.count >= f.maxCount {
		f.password = newPassword
		return nil
	}
	return fmt.Errorf("some error")
}

func (f *failingRollbackClient) UpdateUserPassword(conf *client.Config, user, newPassword string) error {
	panic("nope")
}

func (f *failingRollbackClient) Execute(conf *client.Config, entries []*ldif.Entry, continueOnError bool) error {
	panic("nope")
}

var _ ldapClient = (*failingRollbackClient)(nil)

func TestRollbackPassword(t *testing.T) {
	oldRollbackAttempts, oldMinRollbackDuration, oldMaxRollbackDuration := rollbackAttempts, minRollbackDuration, maxRollbackDuration
	t.Cleanup(func() {
		rollbackAttempts = oldRollbackAttempts
		minRollbackDuration = oldMinRollbackDuration
		maxRollbackDuration = oldMaxRollbackDuration
	})
	rollbackAttempts = 5
	minRollbackDuration = 1 * time.Millisecond
	maxRollbackDuration = 10 * time.Millisecond
	oldPassword := "old"
	newPassword := "new"

	testCases := []struct {
		name                  string
		cancelContext         bool
		rollbackSucceedsAfter int
		expectedRollbackCalls int
		expectedPassword      string
		expectErr             bool
	}{
		{"works if client always succeeds", false, 0, 1, oldPassword, false},
		{"work if client eventually succeeds", false, 3, 3, oldPassword, false},
		{"fails if the client errors too many times", false, 20, 5, newPassword, true},
		{"fails if context is canceled", true, 0, 0, newPassword, true},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			ctx := context.Background()
			if testCase.cancelContext {
				canceledCtx, cancelFunc := context.WithCancel(ctx)
				cancelFunc()
				ctx = canceledCtx
			}
			fclient := &failingRollbackClient{}
			b := &backend{
				client: fclient,
			}
			cfg := &config{
				LDAP: &client.Config{
					ConfigEntry: &ldaputil.ConfigEntry{},
				},
			}
			fclient.maxCount = testCase.rollbackSucceedsAfter
			fclient.password = newPassword
			err := b.rollbackPassword(ctx, cfg, oldPassword)
			if testCase.expectErr {
				assert.NotNil(t, err)
			} else {
				assert.Nil(t, err)
			}
			assert.Equal(t, testCase.expectedPassword, fclient.password)
			assert.Equal(t, testCase.expectedRollbackCalls, fclient.count)
		})
	}
}
