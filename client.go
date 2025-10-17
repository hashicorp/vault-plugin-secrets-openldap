// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package openldap

import (
	"errors"
	"fmt"

	"github.com/go-ldap/ldap/v3"
	"github.com/go-ldap/ldif"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/sdk/helper/ldaputil"

	"github.com/hashicorp/vault-plugin-secrets-openldap/client"
)

type ldapClient interface {
	UpdateDNPassword(conf *client.Config, dn string, newPassword string) error
	UpdateUserPassword(conf *client.Config, user, newPassword string) error
	UpdateSelfManagedDNPassword(conf *client.Config, dn, currentPassword, newPassword string) error
	Execute(conf *client.Config, entries []*ldif.Entry, continueOnError bool) error
}

func NewClient(logger hclog.Logger) *Client {
	return &Client{
		ldap: client.New(logger),
	}
}

var _ ldapClient = (*Client)(nil)

type Client struct {
	ldap client.Client
}

// UpdateDNPassword updates the password for the object with the given DN.
func (c *Client) UpdateDNPassword(conf *client.Config, dn string, newPassword string) error {
	scope := ldap.ScopeBaseObject
	filters := map[*client.Field][]string{
		client.FieldRegistry.ObjectClass: {"*"},
	}

	userAttr := conf.UserAttr
	if userAttr == "" {
		userAttr = defaultUserAttr(conf.Schema)
	}
	field := client.FieldRegistry.Parse(userAttr)
	if field == nil {
		return fmt.Errorf("unsupported userattr %q", userAttr)
	}

	if field == client.FieldRegistry.UserPrincipalName && conf.UPNDomain != "" {
		scope = ldap.ScopeWholeSubtree
		bindUser := fmt.Sprintf("%s@%s", ldaputil.EscapeLDAPValue(dn), conf.UPNDomain)
		filters[field] = []string{bindUser}
		dn = conf.UserDN
	}

	newValues, err := client.GetSchemaFieldRegistry(conf, newPassword)
	if err != nil {
		return fmt.Errorf("error updating password: %s", err)
	}

	return c.ldap.UpdatePassword(conf, dn, scope, newValues, filters)
}

// UpdateUserPassword updates the password for the object with the given username.
func (c *Client) UpdateUserPassword(conf *client.Config, username string, newPassword string) error {
	userAttr := conf.UserAttr
	if userAttr == "" {
		userAttr = defaultUserAttr(conf.Schema)
	}

	field := client.FieldRegistry.Parse(userAttr)
	if field == nil {
		return fmt.Errorf("unsupported userattr %q", userAttr)
	}

	filters := map[*client.Field][]string{
		field: {username},
	}

	newValues, err := client.GetSchemaFieldRegistry(conf, newPassword)
	if err != nil {
		return fmt.Errorf("error updating password: %s", err)
	}

	return c.ldap.UpdatePassword(conf, conf.UserDN, ldap.ScopeWholeSubtree, newValues, filters)
}

func (c *Client) UpdateSelfManagedDNPassword(conf *client.Config, dn string, currentPassword string, newPassword string) error {
	if dn == "" {
		// Optionally implement a search to resolve DN from username, userdn, userattr in cfg.
		return errors.New("user DN resolution not implemented")
	}
	if currentPassword == "" || newPassword == "" {
		return fmt.Errorf("both current and new password must be provided for self-managed password changes on dn: %s", dn)
	}

	scope := ldap.ScopeBaseObject
	filters := map[*client.Field][]string{
		client.FieldRegistry.ObjectClass: {"*"},
	}
	currentValues, err := client.GetSchemaFieldRegistry(conf, currentPassword)
	if err != nil {
		return fmt.Errorf("error updating password: %s", err)
	}
	newValues, err := client.GetSchemaFieldRegistry(conf, newPassword)
	if err != nil {
		return fmt.Errorf("error updating password: %s", err)
	}
	// Use a copy of the config to avoid modifying the original with the bind dn/password for rotation
	rotationConfEntry := *conf.ConfigEntry
	rotationConfEntry.BindDN = dn
	rotationConfEntry.BindPassword = currentPassword
	rotationConf := *conf
	rotationConf.ConfigEntry = &rotationConfEntry
	return c.ldap.UpdateSelfManagedPassword(&rotationConf, scope, currentValues, newValues, filters)
}

func (c *Client) Execute(conf *client.Config, entries []*ldif.Entry, continueOnError bool) (err error) {
	return c.ldap.Execute(conf, entries, continueOnError)
}
