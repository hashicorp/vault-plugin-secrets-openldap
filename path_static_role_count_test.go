// Copyright IBM Corp. 2020, 2026
// SPDX-License-Identifier: MPL-2.0

package openldap

import (
	"context"
	"fmt"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// Read the static role count from API endpoint
func readStaticRoleCount(t *testing.T, b logical.Backend, s logical.Storage) int {
	t.Helper()
	req := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      staticRoleCountPath,
		Storage:   s,
	}
	resp, err := b.HandleRequest(context.Background(), req)
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.NotNil(t, resp.Data)

	count, ok := resp.Data["count"].(int)
	require.True(t, ok, "count should be an int")
	return count
}

// Create a static role with the given name
// 'ViaAPI' for consistency with other helpers and clarity re 'createStaticRoleWithData'
func createStaticRoleViaAPI(t *testing.T, b logical.Backend, s logical.Storage, name string) {
	t.Helper()
	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      staticRolePath + name,
		Storage:   s,
		Data: map[string]interface{}{
			"username":             name,
			"rotation_period":      "24h",
			"skip_import_rotation": true,
		},
	}
	resp, err := b.HandleRequest(context.Background(), req)
	require.NoError(t, err)
	if resp != nil && resp.IsError() {
		t.Fatalf("failed to create static role: %v", resp.Error())
	}
}

// Delete a static role with the given name
// 'ViaAPI' for clarity re 'deleteStaticRoleWithData'
func deleteStaticRoleViaAPI(t *testing.T, b logical.Backend, s logical.Storage, name string) {
	t.Helper()
	req := &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      staticRolePath + name,
		Storage:   s,
	}
	resp, err := b.HandleRequest(context.Background(), req)
	require.NoError(t, err)
	if resp != nil && resp.IsError() {
		t.Fatalf("failed to delete static role: %v", resp.Error())
	}
}

// Assert the static role count is equal to the expected value
func assertStaticRoleCount(t *testing.T, b logical.Backend, s logical.Storage, expected int) {
	t.Helper()
	actual := readStaticRoleCount(t, b, s)
	require.Equal(t, expected, actual, "Static role count mismatch")
}

// Update an existing static role
// 'ViaAPI' for clarity re 'updateStaticRoleWithData'
func updateStaticRoleViaAPI(t *testing.T, b logical.Backend, s logical.Storage, name string) {
	t.Helper()
	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      staticRolePath + name,
		Storage:   s,
		Data: map[string]interface{}{
			"username":        name,
			"rotation_period": "48h",
		},
	}
	resp, err := b.HandleRequest(context.Background(), req)
	require.NoError(t, err)
	if resp != nil && resp.IsError() {
		t.Fatalf("failed to update static role: %v", resp.Error())
	}
}

func TestStaticRoleCount(t *testing.T) {
	ctx := context.Background()
	b, s := getBackend(false)
	defer b.Cleanup(ctx)
	configureBackend(t, b, s)

	t.Run("initial state", func(t *testing.T) {
		assertStaticRoleCount(t, b, s, 0)
	})
	t.Run("count after create", func(t *testing.T) {
		createStaticRoleViaAPI(t, b, s, "role1")
		assertStaticRoleCount(t, b, s, 1)
		createStaticRoleViaAPI(t, b, s, "role2")
		assertStaticRoleCount(t, b, s, 2)
	})
	t.Run("count after delete", func(t *testing.T) {
		deleteStaticRoleViaAPI(t, b, s, "role1")
		assertStaticRoleCount(t, b, s, 1)
	})
	t.Run("update does not change count", func(t *testing.T) {
		updateStaticRoleViaAPI(t, b, s, "role2")
		assertStaticRoleCount(t, b, s, 1)
	})
}

func TestStaticRoleCount_Hierarchical(t *testing.T) {
	ctx := context.Background()
	b, s := getBackend(false)
	defer b.Cleanup(ctx)
	configureBackend(t, b, s)

	t.Run("create nested paths", func(t *testing.T) {
		createStaticRoleViaAPI(t, b, s, "foo")
		assertStaticRoleCount(t, b, s, 1)
		createStaticRoleViaAPI(t, b, s, "org/secure")
		assertStaticRoleCount(t, b, s, 2)
		createStaticRoleViaAPI(t, b, s, "org/platform/dev")
		assertStaticRoleCount(t, b, s, 3)
	})
	t.Run("delete nested paths", func(t *testing.T) {
		deleteStaticRoleViaAPI(t, b, s, "org/platform/dev")
		assertStaticRoleCount(t, b, s, 2)
		deleteStaticRoleViaAPI(t, b, s, "org/secure")
		assertStaticRoleCount(t, b, s, 1)
		deleteStaticRoleViaAPI(t, b, s, "foo")
		assertStaticRoleCount(t, b, s, 0)
	})
}

func TestStaticRoleCount_MixedOperations(t *testing.T) {
	ctx := context.Background()
	b, s := getBackend(false)
	defer b.Cleanup(ctx)
	configureBackend(t, b, s)

	assertStaticRoleCount(t, b, s, 0)
	for i := 1; i <= 5; i++ {
		createStaticRoleViaAPI(t, b, s, fmt.Sprintf("role%d", i))
	}
	assertStaticRoleCount(t, b, s, 5)
	deleteStaticRoleViaAPI(t, b, s, "role2")
	deleteStaticRoleViaAPI(t, b, s, "role4")
	assertStaticRoleCount(t, b, s, 3)
	createStaticRoleViaAPI(t, b, s, "org/role6")
	assertStaticRoleCount(t, b, s, 4)
	deleteStaticRoleViaAPI(t, b, s, "role1")
	deleteStaticRoleViaAPI(t, b, s, "role3")
	deleteStaticRoleViaAPI(t, b, s, "role5")
	deleteStaticRoleViaAPI(t, b, s, "org/role6")
	assertStaticRoleCount(t, b, s, 0)
}

func TestStaticRoleCount_StorageError(t *testing.T) {
	ctx := context.Background()
	b := Backend(&fakeLdapClient{})
	storage := new(mockStorage)
	storage.On("List", mock.Anything, staticRolePath).Return([]string{}, fmt.Errorf("storage failure"))

	req := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      staticRoleCountPath,
		Storage:   storage,
	}
	resp, err := b.operationStaticRoleCountRead(ctx, req, nil)
	require.Nil(t, resp)
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to count static roles")
}

func TestStaticRoleCount_SetAndDirectoryPrefixHaveSameName(t *testing.T) {
	ctx := context.Background()
	b, s := getBackend(false)
	defer b.Cleanup(ctx)
	configureBackend(t, b, s)

	createStaticRoleViaAPI(t, b, s, "org")
	assertStaticRoleCount(t, b, s, 1)
	createStaticRoleViaAPI(t, b, s, "org/team")
	assertStaticRoleCount(t, b, s, 2)
	deleteStaticRoleViaAPI(t, b, s, "org")
	assertStaticRoleCount(t, b, s, 1)
	deleteStaticRoleViaAPI(t, b, s, "org/team")
	assertStaticRoleCount(t, b, s, 0)
}
