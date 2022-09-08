module github.com/hashicorp/vault-plugin-secrets-openldap

go 1.17

require (
	github.com/armon/go-metrics v0.3.10
	github.com/go-ldap/ldap/v3 v3.4.1
	github.com/go-ldap/ldif v0.0.0-20200320164324-fd88d9b715b3
	github.com/hashicorp/go-hclog v1.0.0
	github.com/hashicorp/go-multierror v1.1.1
	github.com/hashicorp/go-secure-stdlib/base62 v0.1.2
	github.com/hashicorp/go-secure-stdlib/parseutil v0.1.6
	github.com/hashicorp/go-secure-stdlib/strutil v0.1.2
	github.com/hashicorp/vault/api v1.2.0
	github.com/hashicorp/vault/sdk v0.5.3
	github.com/mitchellh/mapstructure v1.5.0
	github.com/stretchr/testify v1.7.0
	golang.org/x/text v0.3.7
)
