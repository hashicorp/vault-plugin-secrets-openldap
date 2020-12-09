package openldap

import (
	"context"
	"fmt"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/go-ldap/ldif"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/base62"
	"github.com/hashicorp/vault/sdk/helper/template"
	"github.com/hashicorp/vault/sdk/logical"
)

func (b *backend) pathDynamicCredsRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roleName := data.Get("name").(string)

	// Get the role and LDAP configs
	dRole, err := retrieveDynamicRole(ctx, req.Storage, roleName)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve dynamic role: %w", err)
	}
	if dRole == nil {
		return nil, nil
	}

	config, err := readConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if config == nil {
		return nil, fmt.Errorf("missing OpenLDAP configuration")
	}

	// Generate dynamic data
	username, err := generateUsername(req, dRole)
	if err != nil {
		return nil, fmt.Errorf("failed to generate username: %w", err)
	}
	password, err := b.GeneratePassword(ctx, config)
	if err != nil {
		return nil, err
	}

	// Apply the template
	now := time.Now()
	exp := now.Add(dRole.DefaultTTL)
	templateData := dynamicTemplateData{
		Username:              username,
		Password:              password,
		DisplayName:           req.DisplayName,
		RoleName:              roleName,
		IssueTime:             now.Format(time.RFC3339),
		IssueTimeSeconds:      now.Unix(),
		ExpirationTime:        exp.Format(time.RFC3339),
		ExpirationTimeSeconds: exp.Unix(),
	}
	createLDIF, err := applyTemplate(dRole.CreationLDIF, templateData)
	if err != nil {
		return nil, fmt.Errorf("failed to apply creation_ldif template: %w", err)
	}

	// Parse the raw LDIF & run it against the LDAP client
	entries, err := ldif.Parse(createLDIF)
	if err != nil {
		return nil, fmt.Errorf("failed to parse generated LDIF: %w", err)
	}

	addReq := getAddRequest(entries.Entries[0])

	err = b.client.Add(config.LDAP, addReq)
	if err != nil {
		return nil, fmt.Errorf("failed to create LDAP entry: %w", err)
	}
	respData := map[string]interface{}{
		"username": username,
		"password": password,
		"dn":       addReq.DN,
	}
	internal := map[string]interface{}{
		"name":     roleName,
		"username": username,
		"password": password,
		"dn":       addReq.DN,
	}
	resp := b.Secret(secretCredsType).Response(respData, internal)
	resp.Secret.TTL = dRole.DefaultTTL
	resp.Secret.MaxTTL = dRole.MaxTTL

	return resp, nil
}

func getAddRequest(req *ldif.Entry) *ldap.AddRequest {
	if req.Add != nil {
		return req.Add
	}

	if req.Entry == nil {
		return nil
	}

	// Attempt to convert the Entry to an AddRequest
	attributes := make([]ldap.Attribute, 0, len(req.Entry.Attributes))
	for _, entryAttribute := range req.Entry.Attributes {
		attribute := ldap.Attribute{
			Type: entryAttribute.Name,
			Vals: entryAttribute.Values,
		}
		attributes = append(attributes, attribute)
	}
	addReq := &ldap.AddRequest{
		DN:         req.Entry.DN,
		Attributes: attributes,
		Controls:   nil,
	}
	return addReq
}

func (b *backend) secretCredsRenew() framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		// Retrieve the role to ensure it still exists. If it doesn't, this will reject the renewal request.
		roleNameRaw, ok := req.Secret.InternalData["name"]
		if !ok {
			return nil, fmt.Errorf("missing role name")
		}

		roleName := roleNameRaw.(string)
		dRole, err := retrieveDynamicRole(ctx, req.Storage, roleName)
		if err != nil {
			return nil, fmt.Errorf("failed to retrieve dynamic role: %w", err)
		}
		if dRole == nil {
			return nil, fmt.Errorf("unable to renew: role does not exist")
		}

		resp := &logical.Response{
			Secret: req.Secret,
		}
		return resp, nil
	}
}

func (b *backend) secretCredsRevoke() framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		config, err := readConfig(ctx, req.Storage)
		if err != nil {
			return nil, err
		}
		if config == nil {
			return nil, fmt.Errorf("missing OpenLDAP configuration")
		}

		dn, err := getString(req.Secret.InternalData, "dn")
		if err != nil {
			return nil, fmt.Errorf("failed to retrieve dn from revocation data: %w", err)
		}
		if dn == "" {
			return nil, fmt.Errorf("no DN found in revocation data")
		}

		delReq := &ldap.DelRequest{
			DN: dn,
		}

		err = b.client.Del(config.LDAP, delReq)
		if err != nil {
			return nil, fmt.Errorf("failed to revoke OpenLDAP credentials: %w", err)
		}
		return nil, nil
	}
}

type usernameTemplateData struct {
	DisplayName string
	RoleName    string
}

func generateUsername(req *logical.Request, role *dynamicRole) (string, error) {
	if role.UsernameTemplate == "" {
		randStr, err := base62.Random(20)
		if err != nil {
			return "", err
		}
		username := fmt.Sprintf("v_%s_%s_%s_%d", req.DisplayName, role.Name, randStr, time.Now().Unix())
		return username, nil
	}
	tmpl, err := template.NewTemplate(
		template.Template(role.UsernameTemplate),
	)
	if err != nil {
		return "", err
	}
	usernameData := usernameTemplateData{
		DisplayName: req.DisplayName,
		RoleName:    role.Name,
	}
	return tmpl.Generate(usernameData)
}

type dynamicTemplateData struct {
	Username              string
	Password              string
	DisplayName           string
	RoleName              string
	IssueTime             string
	IssueTimeSeconds      int64
	ExpirationTime        string
	ExpirationTimeSeconds int64
}

func applyTemplate(rawTemplate string, data dynamicTemplateData) (string, error) {
	tmpl, err := template.NewTemplate(
		template.Template(rawTemplate),
	)
	if err != nil {
		return "", fmt.Errorf("failed to parse template: %w", err)
	}
	str, err := tmpl.Generate(data)
	if err != nil {
		return "", fmt.Errorf("failed to execute template: %w", err)
	}

	return str, nil
}

func getString(m map[string]interface{}, key string) (string, error) {
	if m == nil {
		return "", fmt.Errorf("nil map")
	}

	val, exists := m[key]
	if !exists {
		return "", nil
	}

	str, ok := val.(string)
	if !ok {
		return "", fmt.Errorf("key %s has %T value, not string", key, val)
	}
	return str, nil
}
