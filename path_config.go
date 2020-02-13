package openldap

import (
	"context"
	"errors"

	"github.com/hashicorp/vault-plugin-secrets-openldap/client"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/ldaputil"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	configPath            = "config"
	defaultPasswordLength = 64
	defaultTLSVersion     = "tls12"
)

func readConfig(ctx context.Context, storage logical.Storage) (*config, error) {
	entry, err := storage.Get(ctx, configPath)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}
	config := &config{}
	if err := entry.DecodeJSON(config); err != nil {
		return nil, err
	}
	return config, nil
}

func (b *backend) pathConfig() []*framework.Path {
	return []*framework.Path{
		{
			Pattern: configPath,
			Fields:  b.configFields(),
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.CreateOperation: &framework.PathOperation{
					Callback:                    b.configCreateUpdateOperation,
					ForwardPerformanceSecondary: true,
					ForwardPerformanceStandby:   true,
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback:                    b.configCreateUpdateOperation,
					ForwardPerformanceSecondary: true,
					ForwardPerformanceStandby:   true,
				},
				logical.ReadOperation: &framework.PathOperation{
					Callback:                    b.configReadOperation,
					ForwardPerformanceSecondary: false,
					ForwardPerformanceStandby:   false,
				},
				logical.DeleteOperation: &framework.PathOperation{
					Callback:                    b.configDeleteOperation,
					ForwardPerformanceSecondary: true,
					ForwardPerformanceStandby:   true,
				},
			},
			HelpSynopsis:    configHelpSynopsis,
			HelpDescription: configHelpDescription,
		},
	}
}

func (b *backend) configFields() map[string]*framework.FieldSchema {
	fields := ldaputil.ConfigFields()
	fields["ttl"] = &framework.FieldSchema{
		Type:        framework.TypeDurationSecond,
		Description: "In seconds, the default password time-to-live.",
	}
	fields["max_ttl"] = &framework.FieldSchema{
		Type:        framework.TypeDurationSecond,
		Description: "In seconds, the maximum password time-to-live.",
	}
	fields["length"] = &framework.FieldSchema{
		Type:        framework.TypeInt,
		Default:     defaultPasswordLength,
		Description: "The desired length of passwords that Vault generates.",
	}
	fields["formatter"] = &framework.FieldSchema{
		Type:        framework.TypeString,
		Description: `Text to insert the password into, ex. "customPrefix{{PASSWORD}}customSuffix".`,
	}
	return fields
}

func (b *backend) configCreateUpdateOperation(ctx context.Context, req *logical.Request, fieldData *framework.FieldData) (*logical.Response, error) {
	// Build and validate the ldap conf.
	ldapConf, err := ldaputil.NewConfigEntry(nil, fieldData)
	if err != nil {
		return nil, err
	}

	if err := ldapConf.Validate(); err != nil {
		return nil, err
	}

	// Build the password conf.
	ttl := fieldData.Get("ttl").(int)
	maxTTL := fieldData.Get("max_ttl").(int)
	length := fieldData.Get("length").(int)
	formatter := fieldData.Get("formatter").(string)
	url := fieldData.Get("url").(string)

	if ttl == 0 {
		ttl = int(b.System().DefaultLeaseTTL().Seconds())
	}
	if maxTTL == 0 {
		maxTTL = int(b.System().MaxLeaseTTL().Seconds())
	}
	if ttl > maxTTL {
		return nil, errors.New("ttl must be smaller than or equal to max_ttl")
	}
	if ttl < 1 {
		return nil, errors.New("ttl must be positive")
	}
	if maxTTL < 1 {
		return nil, errors.New("max_ttl must be positive")
	}
	if url == "" {
		return nil, errors.New("url is required")
	}
	if err := validatePwdSettings(formatter, length); err != nil {
		return nil, err
	}

	config := &config{
		LDAP: &client.Config{
			ConfigEntry: ldapConf,
		},
		Password: &passwordConf{
			TTL:       ttl,
			MaxTTL:    maxTTL,
			Length:    length,
			Formatter: formatter,
		},
	}

	entry, err := logical.StorageEntryJSON(configPath, config)
	if err != nil {
		return nil, err
	}
	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}

	// Respond with a 204.
	return nil, nil
}

func (b *backend) configReadOperation(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	config, err := readConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if config == nil {
		return nil, nil
	}

	// "password" is intentionally not returned by this endpoint
	configMap := config.LDAP.PasswordlessMap()

	for k, v := range config.Password.Map() {
		configMap[k] = v
	}

	resp := &logical.Response{
		Data: configMap,
	}
	return resp, nil
}

func (b *backend) configDeleteOperation(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	if err := req.Storage.Delete(ctx, configPath); err != nil {
		return nil, err
	}
	return nil, nil
}

type config struct {
	LDAP     *client.Config
	Password *passwordConf
}

const configHelpSynopsis = `
Configure the OpenLDAP secret engine plugin.
`

const configHelpDescription = `
This path configures the OpenLDAP secret engine plugin. See the documentation for the plugin specified
for a full list of accepted connection details.
`
