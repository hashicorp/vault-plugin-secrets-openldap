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

// read the dynamic role count from API endpoint
func readDynamicRoleCount(t *testing.T, b logical.Backend, s logical.Storage) int {
	t.Helper()
	req := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      dynamicRoleCountPath,
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

// Create a dynamic role with the given name
// 'ViaAPI' for consistency with other helpers and clarity re 'createDynamicRoleWithData'
func createDynamicRoleViaAPI(t *testing.T, b logical.Backend, s logical.Storage, name string) {
	t.Helper()
	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      dynamicRolePath + name,
		Storage:   s,
		Data:      getTestDynamicRoleConfig(name),
	}
	resp, err := b.HandleRequest(context.Background(), req)
	require.NoError(t, err)
	if resp != nil && resp.IsError() {
		t.Fatalf("failed to create dynamic role: %v", resp.Error())
	}
}

// Delete a dynamic role with the given name
// 'ViaAPI' for clarity re 'deleteDynamicRole' in dynamic_role.go
func deleteDynamicRoleViaAPI(t *testing.T, b logical.Backend, s logical.Storage, name string) {
	t.Helper()
	req := &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      dynamicRolePath + name,
		Storage:   s,
	}
	resp, err := b.HandleRequest(context.Background(), req)
	require.NoError(t, err)
	if resp != nil && resp.IsError() {
		t.Fatalf("failed to delete dynamic role: %v", resp.Error())
	}
}

// Assert the dynamic role count is equal to the expected value
func assertDynamicRoleCount(t *testing.T, b logical.Backend, s logical.Storage, expected int) {
	t.Helper()
	actual := readDynamicRoleCount(t, b, s)
	require.Equal(t, expected, actual, "Dynamic role count mismatch")
}

// Update an existing dynamic role
// 'ViaAPI' for clarity re 'updateDynamicRoleWithData'
func updateDynamicRoleViaAPI(t *testing.T, b logical.Backend, s logical.Storage, name string) {
	t.Helper()
	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      dynamicRolePath + name,
		Storage:   s,
		Data:      getTestDynamicRoleConfig(name),
	}
	resp, err := b.HandleRequest(context.Background(), req)
	require.NoError(t, err)
	if resp != nil && resp.IsError() {
		t.Fatalf("failed to update dynamic role: %v", resp.Error())
	}
}

func TestDynamicRoleCount(t *testing.T) {
	ctx := context.Background()
	b, s := getBackend(false)
	defer b.Cleanup(ctx)
	configureBackend(t, b, s)

	t.Run("initial state", func(t *testing.T) {
		assertDynamicRoleCount(t, b, s, 0)

	})
	t.Run("count after create", func(t *testing.T) {
		createDynamicRoleViaAPI(t, b, s, "role1")
		assertDynamicRoleCount(t, b, s, 1)
		createDynamicRoleViaAPI(t, b, s, "role2")
		assertDynamicRoleCount(t, b, s, 2)
	})
	t.Run("count after delete", func(t *testing.T) {
		deleteDynamicRoleViaAPI(t, b, s, "role1")
		assertDynamicRoleCount(t, b, s, 1)
	})
	t.Run("update does not change count", func(t *testing.T) {
		updateDynamicRoleViaAPI(t, b, s, "role2")
		assertDynamicRoleCount(t, b, s, 1)
	})
}

func TestDynamicRoleCount_Hierarchical(t *testing.T) {
	ctx := context.Background()
	b, s := getBackend(false)
	defer b.Cleanup(ctx)
	configureBackend(t, b, s)

	t.Run("create nested paths", func(t *testing.T) {
		createDynamicRoleViaAPI(t, b, s, "foo")
		assertDynamicRoleCount(t, b, s, 1)
		createDynamicRoleViaAPI(t, b, s, "org/secure")
		assertDynamicRoleCount(t, b, s, 2)
		createDynamicRoleViaAPI(t, b, s, "org/platform/dev")
		assertDynamicRoleCount(t, b, s, 3)
	})
	t.Run("delete nested paths", func(t *testing.T) {
		deleteDynamicRoleViaAPI(t, b, s, "org/platform/dev")
		assertDynamicRoleCount(t, b, s, 2)
		deleteDynamicRoleViaAPI(t, b, s, "org/secure")
		assertDynamicRoleCount(t, b, s, 1)
		deleteDynamicRoleViaAPI(t, b, s, "foo")
		assertDynamicRoleCount(t, b, s, 0)
	})
}

func TestDynamicRoleCount_MixedOperations(t *testing.T) {
	ctx := context.Background()
	b, s := getBackend(false)
	defer b.Cleanup(ctx)
	configureBackend(t, b, s)

	assertDynamicRoleCount(t, b, s, 0)
	for i := 1; i <= 5; i++ {
		createDynamicRoleViaAPI(t, b, s, fmt.Sprintf("role%d", i))
	}
	assertDynamicRoleCount(t, b, s, 5)
	deleteDynamicRoleViaAPI(t, b, s, "role2")
	deleteDynamicRoleViaAPI(t, b, s, "role4")
	assertDynamicRoleCount(t, b, s, 3)
	createDynamicRoleViaAPI(t, b, s, "org/role6")
	assertDynamicRoleCount(t, b, s, 4)
	deleteDynamicRoleViaAPI(t, b, s, "role1")
	deleteDynamicRoleViaAPI(t, b, s, "role3")
	deleteDynamicRoleViaAPI(t, b, s, "role5")
	deleteDynamicRoleViaAPI(t, b, s, "org/role6")
	assertDynamicRoleCount(t, b, s, 0)
}

func TestDynamicRoleCount_StorageError(t *testing.T) {
	ctx := context.Background()
	b := Backend(&fakeLdapClient{})
	storage := new(mockStorage)
	storage.On("List", mock.Anything, dynamicRolePath).Return([]string{}, fmt.Errorf("storage failure"))

	req := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      dynamicRoleCountPath,
		Storage:   storage,
	}
	resp, err := b.operationDynamicRoleCountRead(ctx, req, nil)
	require.Nil(t, resp)
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to count dynamic roles")
}

func TestDynamicRoleCount_SetAndDirectoryPrefixHaveSameNames(t *testing.T) {
	ctx := context.Background()
	b, s := getBackend(false)
	defer b.Cleanup(ctx)
	configureBackend(t, b, s)

	createDynamicRoleViaAPI(t, b, s, "org")
	assertDynamicRoleCount(t, b, s, 1)
	createDynamicRoleViaAPI(t, b, s, "org/team1")
	assertDynamicRoleCount(t, b, s, 2)
	deleteDynamicRoleViaAPI(t, b, s, "org")
	assertDynamicRoleCount(t, b, s, 1)
	deleteDynamicRoleViaAPI(t, b, s, "org/team1")
	assertDynamicRoleCount(t, b, s, 0)

}
