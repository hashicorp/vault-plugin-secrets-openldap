// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package openldap

import (
	"context"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/require"
)

func assertNoError(t *testing.T, resp *logical.Response, err error) {
	t.Helper()
	require.NoError(t, err)
	require.Nil(t, resp.Error())
}

func pathOperation(t *testing.T, b *backend, s logical.Storage, path string, d map[string]interface{}, o logical.Operation) (*logical.Response, error) {
	t.Helper()
	req := &logical.Request{
		Operation: o,
		Path:      path,
		Storage:   s,
		Data:      d,
	}

	return b.HandleRequest(context.Background(), req)
}

func testCreateConfigWithData(t *testing.T, b *backend, s logical.Storage, d map[string]interface{}) (*logical.Response, error) {
	t.Helper()
	return pathOperation(t, b, s, configPath, d, logical.CreateOperation)
}

func testUpdateConfigWithData(t *testing.T, b *backend, s logical.Storage, d map[string]interface{}) (*logical.Response, error) {
	t.Helper()
	return pathOperation(t, b, s, configPath, d, logical.UpdateOperation)
}

func testReadConfig(t *testing.T, b *backend, s logical.Storage) (*logical.Response, error) {
	t.Helper()
	return pathOperation(t, b, s, configPath, nil, logical.ReadOperation)
}

func testDeleteConfig(t *testing.T, b *backend, s logical.Storage) (*logical.Response, error) {
	t.Helper()
	return pathOperation(t, b, s, configPath, nil, logical.DeleteOperation)
}
