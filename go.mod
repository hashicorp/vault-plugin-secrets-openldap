module github.com/hashicorp/vault-plugin-secrets-openldap

go 1.13

require (
	github.com/go-ldap/ldap/v3 v3.4.1
	github.com/go-ldap/ldif v0.0.0-20200320164324-fd88d9b715b3
	github.com/hashicorp/errwrap v1.1.0
	github.com/hashicorp/go-hclog v1.0.0
	github.com/hashicorp/go-multierror v1.1.1
	github.com/hashicorp/go-secure-stdlib/base62 v0.1.2
	github.com/hashicorp/go-secure-stdlib/parseutil v0.1.1
	github.com/hashicorp/go-secure-stdlib/strutil v0.1.1
	github.com/hashicorp/vault/api v1.2.0
	github.com/hashicorp/vault/sdk v0.2.1
	github.com/hashicorp/yamux v0.0.0-20181012175058-2f1d1f20f75d // indirect
	github.com/mitchellh/mapstructure v1.4.2
	github.com/stretchr/testify v1.7.0
	golang.org/x/text v0.3.7
)
