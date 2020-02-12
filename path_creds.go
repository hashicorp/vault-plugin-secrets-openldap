package openldap

import (
	"context"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func (b *backend) pathCredsCreate() []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "static-cred/" + framework.GenericNameRegex("name"),
			Fields: map[string]*framework.FieldSchema{
				"name": {
					Type:        framework.TypeString,
					Description: "Name of the static role.",
				},
			},

			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.ReadOperation: b.pathStaticCredsRead(),
			},

			HelpSynopsis:    pathStaticCredsReadHelpSyn,
			HelpDescription: pathStaticCredsReadHelpDesc,
		},
	}
}

func (b *backend) pathStaticCredsRead() framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		name := data.Get("name").(string)

		role, err := b.StaticRole(ctx, req.Storage, name)
		if err != nil {
			return nil, err
		}
		if role == nil {
			return logical.ErrorResponse("unknown role: %s", name), nil
		}

		return &logical.Response{
			Data: map[string]interface{}{
				"dn":                  role.StaticAccount.DN,
				"username":            role.StaticAccount.Username,
				"password":            role.StaticAccount.Password,
				"ttl":                 role.StaticAccount.PasswordTTL().Seconds(),
				"rotation_period":     role.StaticAccount.RotationPeriod.Seconds(),
				"last_vault_rotation": role.StaticAccount.LastVaultRotation,
			},
		}, nil
	}
}

const pathStaticCredsReadHelpSyn = `
Request LDAP credentials for a certain static role. These credentials are
rotated periodically.`

const pathStaticCredsReadHelpDesc = `
This path reads LDAP credentials for a certain static role. The LDAPs 
credentials are rotated periodically according to their configuration, and will
return the same password until they are rotated.
`
