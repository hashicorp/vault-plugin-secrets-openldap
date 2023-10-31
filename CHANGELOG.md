## Unreleased

### IMPROVEMENTS:
* add rotate-root support when using userattr=userPrincipalName
* add `skip_static_role_import_rotation` and `skip_import_rotation` to allow users to retain the existing role password
on import (note: Vault will not know the role password until it is rotated)
 
## v0.11.1

### IMPROVEMENTS:

* update dependencies [GH-XXX](https://github.com/hashicorp/vault-plugin-secrets-openldap/pull/XXX)
  * github.com/hashicorp/go-metrics v0.5.1
  * github.com/hashicorp/vault/api v1.9.2
  * github.com/hashicorp/vault/sdk v0.9.2
  * github.com/stretchr/testify v1.8.4
  * golang.org/x/text v0.12.0

## v0.11.0

### IMPROVEMENTS:

* enable plugin multiplexing [GH-55](https://github.com/hashicorp/vault-plugin-secrets-openldap/pull/55)
* update dependencies
  * `github.com/hashicorp/vault/api` v1.9.1
  * `github.com/hashicorp/vault/sdk` v0.9.0

## v0.10.0

CHANGES:

* CreateOperation should only be implemented alongside ExistenceCheck [[GH-50]](https://github.com/hashicorp/vault-plugin-secrets-openldap/pull/50)

IMPROVEMENTS:

* Update golang.org/x/text to v0.3.8 [[GH-48]](https://github.com/hashicorp/vault-plugin-secrets-openldap/pull/48)

## v0.9.0

FEATURES:

- Adds service account check-out functionality for `ad`, `openldap`, and `racf` schemas.

IMPROVEMENTS:

- Adds the `last_password` field to the static role [credential response](https://www.vaultproject.io/api-docs/secret/openldap#static-role-passwords)
- Adds the `userdn` and `userattr` configuration parameters to control how user LDAP
  search is performed for service account check-out and static roles.
- Adds the `upndomain` configuration parameter to allow construction of a userPrincipalName
  (UPN) string for authentication.

BUG FIXES:

- Fix config updates so that they retain prior values set in storage
- Fix `last_bind_password` client rotation retry that may occur after a root credential rotation
