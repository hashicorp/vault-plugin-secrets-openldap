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

// Read the library count from API endpoint
func readLibraryCount(t *testing.T, b logical.Backend, s logical.Storage) int {
	t.Helper()
	req := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      libraryCountPath,
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

// Create a library with the given name and service accounts
func createLibrary(t *testing.T, b logical.Backend, s logical.Storage, name string, serviceAccounts []string) {
	t.Helper()
	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      libraryPrefix + name,
		Storage:   s,
		Data: map[string]interface{}{
			"service_account_names": serviceAccounts,
			"ttl":                   "10h",
			"max_ttl":               "11h",
		},
	}
	resp, err := b.HandleRequest(context.Background(), req)
	require.NoError(t, err)
	if resp != nil && resp.IsError() {
		t.Fatalf("failed to create library: %v", resp.Error())
	}
}

// Delete a library with the given name
func deleteLibrary(t *testing.T, b logical.Backend, s logical.Storage, name string) {
	t.Helper()
	req := &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      libraryPrefix + name,
		Storage:   s,
	}
	resp, err := b.HandleRequest(context.Background(), req)
	require.NoError(t, err)
	if resp != nil && resp.IsError() {
		t.Fatalf("failed to delete library: %v", resp.Error())
	}
}

// Assert that the library count is equal to the expected value
func assertLibraryCount(t *testing.T, b logical.Backend, s logical.Storage, expected int) {
	t.Helper()
	actual := readLibraryCount(t, b, s)
	require.Equal(t, expected, actual, "Library count mismatch")
}

// Update an existing library
func updateLibrary(t *testing.T, b logical.Backend, s logical.Storage, name string, serviceAccounts []string) {
	t.Helper()
	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      libraryPrefix + name,
		Storage:   s,
		Data: map[string]interface{}{
			"service_account_names": serviceAccounts,
			"ttl":                   "9h",
		},
	}
	resp, err := b.HandleRequest(context.Background(), req)
	require.NoError(t, err)
	if resp != nil && resp.IsError() {
		t.Fatalf("failed to update library: %v", resp.Error())
	}
}

// Configure the LDAP backend with test settings
func configureBackend(t *testing.T, b logical.Backend, s logical.Storage) {
	t.Helper()
	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      configPath,
		Storage:   s,
		Data: map[string]interface{}{
			"binddn":   "euclid",
			"password": "password",
			"url":      "ldap://ldap.forumsys.com:389",
			"userdn":   "cn=read-only-admin, dc=example,dc=com",
		},
	}
	resp, err := b.HandleRequest(context.Background(), req)
	require.NoError(t, err)
	if resp != nil && resp.IsError() {
		t.Fatalf("failed to configure LDAP backend: %v", resp.Error())
	}
}

func TestLibraryCount(t *testing.T) {
	ctx := context.Background()
	b, s := getBackend(false)
	defer b.Cleanup(ctx)
	configureBackend(t, b, s)

	t.Run("initial state", func(t *testing.T) {
		assertLibraryCount(t, b, s, 0)
	})
	t.Run("count after create", func(t *testing.T) {
		createLibrary(t, b, s, "accounting-team", []string{"acct1", "acct2"})
		assertLibraryCount(t, b, s, 1)
		createLibrary(t, b, s, "dev-team", []string{"dev1", "dev2"})
		assertLibraryCount(t, b, s, 2)
	})

	t.Run("count after delete", func(t *testing.T) {
		deleteLibrary(t, b, s, "accounting-team")
		assertLibraryCount(t, b, s, 1)
	})

	t.Run("update does not change count", func(t *testing.T) {
		updateLibrary(t, b, s, "dev-team", []string{"dev1", "dev2", "dev3"})
		assertLibraryCount(t, b, s, 1)
	})
}

func TestLibraryCount_Hierarchical(t *testing.T) {
	ctx := context.Background()
	b, s := getBackend(false)
	defer b.Cleanup(ctx)
	configureBackend(t, b, s)

	t.Run("create nested paths", func(t *testing.T) {
		createLibrary(t, b, s, "foo", []string{"user1"})
		assertLibraryCount(t, b, s, 1)
		createLibrary(t, b, s, "org/secure", []string{"user2"})
		assertLibraryCount(t, b, s, 2)
		createLibrary(t, b, s, "org/platform/dev", []string{"user3"})
		assertLibraryCount(t, b, s, 3)
		createLibrary(t, b, s, "org/platform/prod/api", []string{"user4"})
		assertLibraryCount(t, b, s, 4)
	})
	t.Run("delete nested paths", func(t *testing.T) {
		deleteLibrary(t, b, s, "org/platform/prod/api")
		assertLibraryCount(t, b, s, 3)
		deleteLibrary(t, b, s, "org/platform/dev")
		assertLibraryCount(t, b, s, 2)
		deleteLibrary(t, b, s, "foo")
		assertLibraryCount(t, b, s, 1)
	})
}

func TestLibraryCount_MixedOperations(t *testing.T) {
	ctx := context.Background()
	b, s := getBackend(false)
	defer b.Cleanup(ctx)
	configureBackend(t, b, s)

	assertLibraryCount(t, b, s, 0)
	for i := 1; i <= 5; i++ {
		createLibrary(t, b, s, fmt.Sprintf("lib%d", i), []string{fmt.Sprintf("user%d", i)})
	}
	assertLibraryCount(t, b, s, 5)

	updateLibrary(t, b, s, "lib1", []string{"user1", "user1b"})
	updateLibrary(t, b, s, "lib3", []string{"user3", "user3b"})
	assertLibraryCount(t, b, s, 5)

	deleteLibrary(t, b, s, "lib2")
	deleteLibrary(t, b, s, "lib4")
	assertLibraryCount(t, b, s, 3)

	createLibrary(t, b, s, "lib6", []string{"user6"})
	createLibrary(t, b, s, "lib7", []string{"user7"})
	createLibrary(t, b, s, "org/lib8", []string{"user8"})
	assertLibraryCount(t, b, s, 6)

	updateLibrary(t, b, s, "lib5", []string{"user5-updated"})
	assertLibraryCount(t, b, s, 6)

	deleteLibrary(t, b, s, "lib1")
	deleteLibrary(t, b, s, "lib3")
	deleteLibrary(t, b, s, "lib5")
	deleteLibrary(t, b, s, "lib6")
	deleteLibrary(t, b, s, "lib7")
	deleteLibrary(t, b, s, "org/lib8")
	assertLibraryCount(t, b, s, 0)
}

func TestLibraryCount_StorageError(t *testing.T) {
	ctx := context.Background()
	b := Backend(&fakeLdapClient{})
	storage := new(mockStorage)
	storage.On("List", mock.Anything, libraryPrefix).Return([]string{}, fmt.Errorf("storage failure"))

	req := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      libraryCountPath,
		Storage:   storage,
	}
	resp, err := b.operationLibraryCountRead(ctx, req, nil)
	require.Nil(t, resp)
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to count library sets")
}

func TestLibraryCount_SetAndDirectoryPrefixHaveSameName(t *testing.T) {
	ctx := context.Background()
	b, s := getBackend(false)
	defer b.Cleanup(ctx)
	configureBackend(t, b, s)

	createLibrary(t, b, s, "org", []string{"user1"})
	assertLibraryCount(t, b, s, 1)
	createLibrary(t, b, s, "org/team", []string{"user2"})
	assertLibraryCount(t, b, s, 2)
	deleteLibrary(t, b, s, "org")
	assertLibraryCount(t, b, s, 1)
	deleteLibrary(t, b, s, "org/team")
	assertLibraryCount(t, b, s, 0)
}
