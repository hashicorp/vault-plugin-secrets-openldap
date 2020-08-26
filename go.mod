module github.com/hashicorp/vault-plugin-secrets-openldap

go 1.13

require (
	github.com/go-ldap/ldap/v3 v3.1.10
	github.com/hashicorp/errwrap v1.0.0
	github.com/hashicorp/go-hclog v0.14.1
	github.com/hashicorp/go-multierror v1.1.0
	github.com/hashicorp/vault/api v1.0.5-0.20200826195146-c03009a7e370
	github.com/hashicorp/vault/sdk v0.1.14-0.20200826195146-c03009a7e370
	github.com/hashicorp/yamux v0.0.0-20181012175058-2f1d1f20f75d // indirect
	golang.org/x/text v0.3.2
)
