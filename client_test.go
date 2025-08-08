// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package openldap

import (
	"fmt"
	"os"
	"path"
	"testing"

	"github.com/go-ldap/ldap/v3"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/sdk/helper/ldaputil"
	"github.com/ory/dockertest/v3"
	"github.com/ory/dockertest/v3/docker"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/hashicorp/vault-plugin-secrets-openldap/client"
	"github.com/hashicorp/vault-plugin-secrets-openldap/ldapifc"
)

func GetTestClient(fake *ldapifc.FakeLDAPConnection) *Client {
	ldapClient := client.NewWithClient(hclog.NewNullLogger(), &ldapifc.FakeLDAPClient{
		ConnToReturn: fake,
	})

	return &Client{ldap: ldapClient}
}

// UpdateDNPassword when the UserAttr is "userPrincipalName"
func Test_UpdateDNPassword_AD_UserPrincipalName(t *testing.T) {
	newPassword := "newpassword"
	conn := &ldapifc.FakeLDAPConnection{
		ModifyRequestToExpect: &ldap.ModifyRequest{
			DN: "CN=Bob,CN=Users,DC=example,DC=net",
		},
		SearchRequestToExpect: &ldap.SearchRequest{
			BaseDN: "cn=users",
			Scope:  ldap.ScopeWholeSubtree,
			Filter: "(&(objectClass=*)(userPrincipalName=bob@example.net))",
		},
		SearchResultToReturn: &ldap.SearchResult{
			Entries: []*ldap.Entry{
				{
					DN: "CN=Bob,CN=Users,DC=example,DC=net",
				},
			},
		},
	}

	c := GetTestClient(conn)
	config := &client.Config{
		ConfigEntry: &ldaputil.ConfigEntry{
			Url:          "ldaps://ldap:386",
			UserDN:       "cn=users",
			UPNDomain:    "example.net",
			UserAttr:     "userPrincipalName",
			BindDN:       "username",
			BindPassword: "password",
		},
		Schema: client.SchemaAD,
	}

	// depending on the schema, the password may be formatted, so we leverage this helper function
	fields, err := client.GetSchemaFieldRegistry(config, newPassword)
	assert.NoError(t, err)
	for k, v := range fields {
		conn.ModifyRequestToExpect.Replace(k.String(), v)
	}

	err = c.UpdateDNPassword(config, "bob", newPassword)
	assert.NoError(t, err)
}

// Test_UpdateDNPassword_AD_UserPrincipalName_Missing_upndomain.
func Test_UpdateDNPassword_AD_UserPrincipalName_Missing_upndomain(t *testing.T) {
	newPassword := "newpassword"
	conn := &ldapifc.FakeLDAPConnection{
		ModifyRequestToExpect: &ldap.ModifyRequest{
			DN: "CN=Bob,CN=Users,DC=example,DC=net",
		},
		SearchRequestToExpect: &ldap.SearchRequest{
			BaseDN: "CN=Bob,CN=Users,DC=example,DC=net",
			Scope:  ldap.ScopeBaseObject,
			Filter: "(objectClass=*)",
		},
		SearchResultToReturn: &ldap.SearchResult{
			Entries: []*ldap.Entry{
				{
					DN: "CN=Bob,CN=Users,DC=example,DC=net",
				},
			},
		},
	}

	c := GetTestClient(conn)
	config := &client.Config{
		ConfigEntry: &ldaputil.ConfigEntry{
			Url:          "ldaps://ldap:386",
			UserDN:       "cn=users",
			UserAttr:     "userPrincipalName",
			BindDN:       "CN=Bob,CN=Users,DC=example,DC=net",
			BindPassword: "password",
		},
		Schema: client.SchemaAD,
	}

	// depending on the schema, the password may be formatted, so we leverage this helper function
	fields, err := client.GetSchemaFieldRegistry(config, newPassword)
	assert.NoError(t, err)
	for k, v := range fields {
		conn.ModifyRequestToExpect.Replace(k.String(), v)
	}

	err = c.UpdateDNPassword(config, config.BindDN, newPassword)
	assert.NoError(t, err)
}

// UpdateDNPassword when the UserAttr is "dn"
func Test_UpdateDNPassword_AD_DN(t *testing.T) {
	newPassword := "newpassword"
	conn := &ldapifc.FakeLDAPConnection{
		ModifyRequestToExpect: &ldap.ModifyRequest{
			DN: "CN=Bob,CN=Users,DC=example,DC=net",
		},
		SearchRequestToExpect: &ldap.SearchRequest{
			BaseDN: "CN=Bob,CN=Users,DC=example,DC=net",
			Scope:  ldap.ScopeBaseObject,
			Filter: "(objectClass=*)",
		},
		SearchResultToReturn: &ldap.SearchResult{
			Entries: []*ldap.Entry{
				{
					DN: "CN=Bob,CN=Users,DC=example,DC=net",
				},
			},
		},
	}

	c := GetTestClient(conn)
	config := &client.Config{
		ConfigEntry: &ldaputil.ConfigEntry{
			Url:          "ldaps://ldap:386",
			UserAttr:     "dn",
			BindDN:       "username",
			BindPassword: "password",
		},
		Schema: client.SchemaAD,
	}

	// depending on the schema, the password may be formatted, so we leverage this helper function
	fields, err := client.GetSchemaFieldRegistry(config, newPassword)
	assert.NoError(t, err)
	for k, v := range fields {
		conn.ModifyRequestToExpect.Replace(k.String(), v)
	}

	err = c.UpdateDNPassword(config, "CN=Bob,CN=Users,DC=example,DC=net", newPassword)
	assert.NoError(t, err)
}

const customldif = `dn: cn=User1,dc=example,dc=org
changetype: add
objectClass: inetOrgPerson
cn: User1
sn: Lastname1
givenName: Firstname1
userPassword: password1

dn: cn=User2,dc=example,dc=org
changetype: add
objectClass: inetOrgPerson
cn: User2
sn: Lastname2
givenName: Firstname2
userPassword: password2
`

func Test_UpdateDNPassword(t *testing.T) {
	ldapServer := setupDockerLDAP(t)
	config := &client.Config{
		ConfigEntry: &ldaputil.ConfigEntry{
			Url:          ldapServer,
			BindDN:       "cn=admin,dc=example,dc=org",
			BindPassword: "admin",
		},
		Schema: client.SchemaOpenLDAP,
	}

	c := NewClient(hclog.NewNullLogger())
	newPassword := "newpassword"
	err := c.UpdateDNPassword(config, "cn=user1,dc=example,dc=org", newPassword)
	assert.NoError(t, err)
}

func Test_UpdateUserPassword(t *testing.T) {
	ldapServer := setupDockerLDAP(t)
	config := &client.Config{
		ConfigEntry: &ldaputil.ConfigEntry{
			Url:          ldapServer,
			BindDN:       "cn=admin,dc=example,dc=org",
			BindPassword: "admin",
			UserDN:       "dc=example,dc=org",
		},
		Schema: client.SchemaOpenLDAP,
	}

	c := NewClient(hclog.NewNullLogger())
	newPassword := "newpassword"
	err := c.UpdateUserPassword(config, "User1", newPassword)
	assert.NoError(t, err)
}

func setupDockerLDAP(t *testing.T) string {
	t.Helper()
	pool, err := dockertest.NewPool("")
	require.NoError(t, err)
	err = pool.Client.Ping()
	require.NoError(t, err)

	tempDir, err := os.MkdirTemp("", "ldif")
	require.NoError(t, err)

	customLdifFile := path.Join(tempDir, "custom.ldif")
	err = os.WriteFile(customLdifFile, []byte(customldif), 0o644)
	require.NoError(t, err)

	opts := dockertest.RunOptions{
		Repository: "osixia/openldap",
		Tag:        "latest",
		PortBindings: map[docker.Port][]docker.PortBinding{
			"389/tcp": {{HostIP: "", HostPort: "389"}},
		},
		// Mount the custom ldif file
		Mounts: []string{customLdifFile + ":/container/service/slapd/assets/config/bootstrap/ldif/custom.ldif"},
		Cmd:    []string{"--copy-service"},
	}

	resource, err := pool.RunWithOptions(&opts)
	require.NoError(t, err)
	t.Cleanup(func() {
		resource.Close()
		pool.Purge(resource)
	})

	ip := resource.GetBoundIP("389/tcp") + ":389"
	ldapServer := "ldap://" + ip
	err = pool.Retry(func() error {
		conn, err := ldap.DialURL(ldapServer)
		if err != nil {
			return err
		}
		t.Cleanup(func() {
			conn.Close()
		})

		// make sure we can connect to the server and bind
		if err := conn.Bind("cn=admin,dc=example,dc=org", "admin"); err != nil {
			return err
		}

		// ensure the users were created
		results, err := conn.Search(&ldap.SearchRequest{
			BaseDN: "dc=example,dc=org",
			Scope:  ldap.ScopeWholeSubtree,
			Filter: "(objectclass=inetOrgPerson)",
		})
		if err != nil {
			return err
		}
		if len(results.Entries) != 2 {
			return fmt.Errorf("expected 2 entries, got %d", len(results.Entries))
		}

		return nil
	})

	require.NoError(t, err)
	return ldapServer
}
