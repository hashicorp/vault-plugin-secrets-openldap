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

const staticRoleCountPath = "static-role-count"

func (b *backend) pathStaticRoleCount() []*framework.Path {
	return []*framework.Path{
		{
			Pattern: staticRoleCountPath,
			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: operationPrefixLDAP,
				OperationVerb:   "read",
				OperationSuffix: "static-role-count",
			},
			Fields: map[string]*framework.FieldSchema{},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{
					Callback:    b.operationStaticRoleCountRead,
					Summary:     "Read the total count of static roles",
					Description: "Returns the current count of LDAP static roles across all hierarchical paths.",
				},
			},
			HelpSynopsis:    "Read the total count of static roles",
			HelpDescription: "This endpoint returns the current count of LDAP static roles",
		},
	}
}

func (b *backend) operationStaticRoleCountRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	// Get the static role count
	count := 0
	countFunc := func(roleName string) (bool, error) {
		if strings.HasSuffix(roleName, "/") {
			return false, nil
		}
		entry, err := b.staticRole(ctx, req.Storage, roleName)
		if err != nil {
			return false, err
		}
		entryExists := entry != nil
		if entryExists {
			count++
		}
		return entryExists, nil
	}
	err := walkStoragePath(ctx, req.Storage, staticRolePath, countFunc)
	if err != nil {
		return nil, fmt.Errorf("failed to count static roles: %w", err)
	}
	return &logical.Response{
		Data: map[string]interface{}{
			"count": count,
		},
	}, nil
}
