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

const dynamicRoleCountPath = "role-count"

func (b *backend) pathDynamicRoleCount() []*framework.Path {
	return []*framework.Path{
		{
			Pattern: dynamicRoleCountPath,
			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: operationPrefixLDAP,
				OperationVerb:   "read",
				OperationSuffix: "role-count",
			},
			Fields: map[string]*framework.FieldSchema{},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{
					Callback:    b.operationDynamicRoleCountRead,
					Summary:     "Read the total count of dynamic roles",
					Description: "Returns the current count of LDAP dynamic roles across all hierarchical paths.",
				},
			},
			HelpSynopsis:    "Read the total count of dynamic roles",
			HelpDescription: "This endpoint returns the current count of LDAP dynamic roles.",
		},
	}
}

func (b *backend) operationDynamicRoleCountRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	// Get the role count
	count := 0
	countFunc := func(roleName string) (bool, error) {
		if strings.HasSuffix(roleName, "/") {
			return false, nil
		}
		entry, err := retrieveDynamicRole(ctx, req.Storage, roleName)
		if err != nil {
			return false, err
		}
		entryExists := entry != nil
		if entryExists {
			count++
		}
		return entryExists, nil
	}
	err := walkStoragePath(ctx, req.Storage, dynamicRolePath, countFunc)
	if err != nil {
		return nil, fmt.Errorf("failed to count dynamic roles: %w", err)
	}
	return &logical.Response{
		Data: map[string]interface{}{
			"count": count,
		},
	}, nil
}
