## Unreleased

## v0.12.1

### BUG FIXES:
* Fix inability to rotate-root when using `userattr=userPrincipalName` and `upndomain` is not set [GH-91](https://github.com/hashicorp/vault-plugin-secrets-openldap/pull/91)

## v0.12.0

* update dependencies [GH-90](https://github.com/hashicorp/vault-plugin-secrets-openldap/pull/90)
  * Bump golang.org/x/crypto from 0.7.0 to 0.17.0 (#87)
  * Bump github.com/go-jose/go-jose/v3 from 3.0.0 to 3.0.1 (#86)
  * Bump google.golang.org/grpc from 1.53.0 to 1.56.3 (#84)
  * Bump golang.org/x/net from 0.8.0 to 0.17.0 (#81)

## v0.11.3

### FEATURES:
* add `skip_static_role_import_rotation` and `skip_import_rotation` to allow users to retain the existing role password
on import (note: Vault will not know the role password until it is rotated) [GH-83](https://github.com/hashicorp/vault-plugin-secrets-openldap/pull/83)

### BUG FIXES:
* Revert back to armon/go-metrics [GH-88](https://github.com/hashicorp/vault-plugin-secrets-openldap/pull/88)

### IMPROVEMENTS:
* add rotate-root support when using userattr=userPrincipalName

## v0.11.2

### IMPROVEMENTS:

* update dependencies [GH-XXX](https://github.com/hashicorp/vault-plugin-secrets-openldap/pull/XXX)
  * github.com/hashicorp/go-metrics v0.5.1
  * github.com/hashicorp/vault/api v1.9.2
  * github.com/hashicorp/vault/sdk v0.9.2
  * github.com/stretchr/testify v1.8.4
  * golang.org/x/text v0.12.0

## v0.11.1

### IMPROVEMENTS:
* prevent overwriting of schema and password_policy values on update of config [GH-75](https://github.com/hashicorp/vault-plugin-secrets-openldap/pull/75)

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
