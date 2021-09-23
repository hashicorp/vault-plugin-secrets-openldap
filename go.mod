module github.com/hashicorp/vault-plugin-secrets-openldap

go 1.13

require (
	github.com/go-ldap/ldap/v3 v3.2.4
	github.com/hashicorp/errwrap v1.1.0
	github.com/hashicorp/go-hclog v0.16.1
	github.com/hashicorp/go-multierror v1.1.1
	github.com/hashicorp/vault v1.8.2
	github.com/hashicorp/vault/api v1.1.2-0.20210713235431-1fc8af4c041f
	github.com/hashicorp/vault/sdk v0.2.2-0.20210825150427-9b1f4d486f5d
	golang.org/x/text v0.3.6
)
