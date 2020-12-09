package openldap

import (
	"context"
	"encoding/base64"
	"fmt"
	"path"
	"time"

	"github.com/go-ldap/ldif"
	"github.com/hashicorp/go-multierror"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/mitchellh/mapstructure"
)

const (
	secretCredsType = "creds"

	dynamicRolePath = "role/"
	dynamicCredPath = "cred/"
)

func (b *backend) pathDynamicRoles() []*framework.Path {
	return []*framework.Path{
		// POST/GET/DELETE role/:name
		{
			// Pattern: path.Join(dynamicRolePath, framework.GenericNameRegex("name")),
			Pattern: path.Join(dynamicRolePath, framework.GenericNameRegex("name")),
			Fields: map[string]*framework.FieldSchema{
				"name": {
					Type:        framework.TypeLowerCaseString,
					Description: "Name of the role (lowercase)",
					Required:    true,
				},
				"creation_ldif": {
					Type:        framework.TypeString,
					Description: "LDIF string used to create new entities within OpenLDAP. This LDIF can be templated.",
					Required:    true,
				},
				"username_template": {
					Type:        framework.TypeString,
					Description: "The template used to create a username",
				},
				"default_ttl": {
					Type:        framework.TypeDurationSecond,
					Description: "Default TTL for dynamic credentials",
				},
				"max_ttl": {
					Type:        framework.TypeDurationSecond,
					Description: "Max TTL a dynamic credential can be extended to",
				},
			},
			ExistenceCheck: b.pathDynamicRoleExistenceCheck,
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.pathDynamicRoleCreateUpdate,
				},
				logical.CreateOperation: &framework.PathOperation{
					Callback: b.pathDynamicRoleCreateUpdate,
				},
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.pathDynamicRoleRead,
				},
				logical.DeleteOperation: &framework.PathOperation{
					Callback:                    b.pathDynamicRoleDelete,
					ForwardPerformanceStandby:   true,
					ForwardPerformanceSecondary: true,
				},
			},
			HelpSynopsis:    staticRoleHelpSynopsis,
			HelpDescription: staticRoleHelpDescription,
		},
		// LIST role
		{
			Pattern: dynamicRolePath + "?$",
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{
					Callback: b.pathDynamicRoleList,
				},
			},
			HelpSynopsis:    "List all the dynamic roles Vault is currently managing in OpenLDAP.",
			HelpDescription: "List all the dynamic roles being managed by Vault.",
		},
		{
			// Pattern: dynamicCredPath + framework.GenericNameRegex("name"),
			Pattern: path.Join(dynamicCredPath, framework.MatchAllRegex("name")),
			Fields: map[string]*framework.FieldSchema{
				"name": {
					Type:        framework.TypeLowerCaseString,
					Description: "Name of the dynamic role.",
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.pathDynamicCredsRead,
				},
			},
			HelpSynopsis: "Request LDAP credentials for a dynamic role. These credentials are " +
				"created within OpenLDAP when querying this endpoint.",
			HelpDescription: "This path requests new LDAP credentials for a certain dynamic role. " +
				"The credentials are created within OpenLDAP based on the creation_ldif specified " +
				"within the dynamic role configuration.",
		},
	}
}

func secretCreds(b *backend) *framework.Secret {
	return &framework.Secret{
		Type: secretCredsType,
		Fields: map[string]*framework.FieldSchema{
			"username": {
				Type:        framework.TypeString,
				Description: "Username of the generated account",
			},
			"password": {
				Type:        framework.TypeString,
				Description: "Password to access the generated account",
			},
			"DNs": {
				Type:        framework.TypeStringSlice,
				Description: "List of the DNs created",
			},
		},

		Renew:  b.secretCredsRenew(),
		Revoke: b.secretCredsRevoke(),
	}
}

func (b *backend) pathDynamicRoleCreateUpdate(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roleName := data.Get("name").(string)

	rawData := data.Raw
	err := convertToDuration(rawData, "default_ttl", "max_ttl")
	if err != nil {
		return nil, fmt.Errorf("failed to convert TTLs to duration: %w", err)
	}

	dRole := &dynamicRole{}
	err = mapstructure.WeakDecode(rawData, dRole)
	if err != nil {
		return nil, fmt.Errorf("failed to decode request: %w", err)
	}

	if dRole.CreationLDIF == "" {
		return nil, fmt.Errorf("missing creation_ldif")
	}

	dRole.CreationLDIF = decodeBase64(dRole.CreationLDIF)

	err = assertValidLDIFTemplate(dRole.CreationLDIF)
	if err != nil {
		return nil, err
	}

	err = storeDynamicRole(ctx, req.Storage, roleName, dRole)
	if err != nil {
		return nil, fmt.Errorf("failed to save dynamic role: %w", err)
	}

	return nil, nil
}

// convertToDuration all keys in the data map into time.Duration objects. Keys not found in the map will be ignored
func convertToDuration(data map[string]interface{}, keys ...string) error {
	merr := new(multierror.Error)
	for _, key := range keys {
		val, exists := data[key]
		if !exists {
			continue
		}

		switch v := val.(type) {
		case time.Duration:
			continue
		case int:
			dur := time.Duration(v)
			data[key] = dur
		case int8:
			dur := time.Duration(v)
			data[key] = dur
		case int16:
			dur := time.Duration(v)
			data[key] = dur
		case int32:
			dur := time.Duration(v)
			data[key] = dur
		case int64:
			dur := time.Duration(v)
			data[key] = dur
		case string:
			dur, err := time.ParseDuration(v)
			if err != nil {
				merr = multierror.Append(merr, fmt.Errorf("failed to parse key %s: %w", key, err))
				continue
			}
			data[key] = dur
		default:
			merr = multierror.Append(merr, fmt.Errorf("key %s cannot be coerced to a duration", key))
		}
	}
	return merr.ErrorOrNil()
}

func decodeBase64(creationLDIF string) string {
	decoded, err := base64.StdEncoding.DecodeString(creationLDIF)
	if err != nil {
		return creationLDIF
	}
	return string(decoded)
}

func assertValidLDIFTemplate(rawTemplate string) error {
	// Test the template to ensure there aren't any errors in the template syntax
	testTemplateData := dynamicTemplateData{
		Username:    "testuser",
		Password:    "testpass",
		DisplayName: "testdisplayname",
		RoleName:    "testrolename",
	}
	testLDIF, err := applyTemplate(rawTemplate, testTemplateData)
	if err != nil {
		return fmt.Errorf("invalid createion_ldif template: %w", err)
	}

	// Test the LDIF to ensure there aren't any errors in the syntax
	entries, err := ldif.Parse(testLDIF)
	if err != nil {
		return fmt.Errorf("creation_ldif is invalid: %w", err)
	}

	// Only allow for a single LDIF record
	if len(entries.Entries) > 1 {
		return fmt.Errorf("cannot specify more than one LDIF record in `creation_ldif`")
	}

	entry := entries.Entries[0]

	// Only creation operations are allowed
	if entry.Modify != nil || entry.Del != nil {
		return fmt.Errorf("invalid `creation_ldif`: cannot specify modify or delete createtype")
	}
	return nil
}

func (b *backend) pathDynamicRoleRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roleName := data.Get("name").(string)

	dRole, err := retrieveDynamicRole(ctx, req.Storage, roleName)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve dynamic role: %w", err)
	}
	if dRole == nil {
		return nil, nil
	}

	resp := &logical.Response{
		Data: map[string]interface{}{
			"creation_ldif":     dRole.CreationLDIF,
			"username_template": dRole.UsernameTemplate,
			"default_ttl":       dRole.DefaultTTL.Seconds(),
			"max_ttl":           dRole.MaxTTL.Seconds(),
		},
	}
	return resp, nil
}

func (b *backend) pathDynamicRoleList(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roles, err := req.Storage.List(ctx, dynamicRolePath)
	if err != nil {
		return nil, fmt.Errorf("failed to list roles: %w", err)
	}

	return logical.ListResponse(roles), nil
}

func (b *backend) pathDynamicRoleExistenceCheck(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
	roleName := data.Get("name").(string)
	role, err := retrieveDynamicRole(ctx, req.Storage, roleName)
	if err != nil {
		return false, fmt.Errorf("error finding role: %w", err)
	}
	return role != nil, nil
}

func (b *backend) pathDynamicRoleDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roleName := data.Get("name").(string)

	err := deleteDynamicRole(ctx, req.Storage, roleName)
	if err != nil {
		return nil, fmt.Errorf("failed to delete role: %w", err)
	}
	return nil, nil
}
