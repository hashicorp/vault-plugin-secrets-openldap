// Copyright IBM Corp. 2020, 2026
// SPDX-License-Identifier: MPL-2.0

package openldap

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const libraryCountPath = "library-count"

func (b *backend) pathLibraryCount() []*framework.Path {
	return []*framework.Path{
		{
			Pattern: libraryCountPath,
			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: operationPrefixLDAPLibrary,
				OperationVerb:   "read",
				OperationSuffix: "count",
			},
			Fields: map[string]*framework.FieldSchema{},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{
					Callback:    b.operationLibraryCountRead,
					Summary:     "Read the total count of library sets",
					Description: "Returns the current count of LDAP service account library sets across all hierarchical paths.",
				},
			},
			HelpSynopsis:    "Read the total count of library sets",
			HelpDescription: "This endpoint returns the current count of LDAP service account library sets.",
		},
	}
}
func (b *backend) operationLibraryCountRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	// Get the library set count
	count := 0
	countFunc := func(setName string) (bool, error) {
		if strings.HasSuffix(setName, "/") {
			return false, nil
		}
		entry, err := readSet(ctx, req.Storage, setName)
		if err != nil {
			return false, err
		}
		entryExists := entry != nil
		if entryExists {
			count++
		}
		return entryExists, nil
	}
	err := walkStoragePath(ctx, req.Storage, libraryPrefix, countFunc)
	if err != nil {
		return nil, fmt.Errorf("failed to count library sets: %w", err)
	}
	return &logical.Response{
		Data: map[string]interface{}{
			"count": count,
		},
	}, nil
}
