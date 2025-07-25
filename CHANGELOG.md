## Unreleased

## v0.16.0
### June 4, 2025

IMPROVEMENTS:
* Upgrade Go to 1.24.3
* Updated dependencies:
  * `github.com/go-ldap/ldap/v3` v3.4.10 -> v3.4.11
  * `github.com/hashicorp/go-secure-stdlib/parseutil` v0.1.9 -> v0.2.0
  * `github.com/hashicorp/vault/sdk` v0.15.2 -> v0.17.0
  * `github.com/ory/dockertest/v3` v3.11.0 -> v3.12.0
  * `golang.org/x/text v0.24.0` -> v0.25.0

BUG FIXES:

* Fix issue where roles created before 0.14.5 had a nil NextVaultRotation value: [GH-156](https://github.com/hashicorp/vault-plugin-secrets-openldap/pull/156)

## v0.15.4

### April 16, 2025

BUG FIXES:

* Fix issue where roles created before 0.14.5 had a nil NextVaultRotation value: [GH-158](https://github.com/hashicorp/vault-plugin-secrets-openldap/pull/158)

## v0.15.2
### March 27, 2025

BUG FIXES:
* Fix a panic when a performance standby node attempts to write/update config: [GH-154](https://github.com/vault-plugin-secrets-openldap/pull/154)

## v0.15.1
### February 26, 2025

IMPROVEMENTS:
* Updated dependencies:
  * `github.com/hashicorp/vault/sdk` v0.15.0 -> v0.15.2
  * `golang.org/x/crypto` v0.33.0 -> v0.35.0
  * `github.com/jose/go-jose` v4.0.4 -> v4.0.5

## v0.15.0

FEATURES:

* (Enterprise feature) Add api fields to allow for scheduled rotation of root credentials. (https://github.com/vault-plugin-secrets-openldap/pull/141)

IMPROVEMENTS:
* Updated dependencies:
  * `github.com/go-ldap/ldap/v3` v3.4.8 -> v3.4.10
  * `github.com/hashicorp/vault/api` v1.15.0 -> v1.16.0
  * `github.com/ory/dockertest/v3` v3.10.0 -> v3.11.0
  * `golang.org/x/text` v0.21.0 -> v0.22.0

BUG FIXES:

* Fix a bug where static role passwords are erroneously rotated across backend restarts when using skip import rotation. (https://github.com/hashicorp/vault-plugin-secrets-openldap/pull/140)

## v0.14.6

BUG FIXES:

* Fix issue where roles created before 0.14.5 had a nil NextVaultRotation value: [GH-159](https://github.com/hashicorp/vault-plugin-secrets-openldap/pull/159)

## v0.14.5

BUG FIXES:

* Fix a bug where static role passwords are erroneously rotated across backend restarts when using skip import rotation. (https://github.com/hashicorp/vault-plugin-secrets-openldap/pull/140)

## v0.14.4

BUG FIXES:

* Update static role rotation to generate a new password after 2 failed attempts (https://github.com/hashicorp/vault-plugin-secrets-openldap/pull/125)

## v0.14.3

BUG FIXES:

* fix an edge case where add an LDAP user or service account can be added to more than one role or set (https://github.com/hashicorp/vault-plugin-secrets-openldap/pull/123)

## v0.14.2

BUG FIXES:

* fix a panic on static role creation when the config is unset (https://github.com/hashicorp/vault-plugin-secrets-openldap/pull/119)

* fix case sensitivity issues in the role rotation process (https://github.com/hashicorp/vault-plugin-secrets-openldap/pull/118)

## v0.14.1

BUG FIXES:
* fix a panic on init when static roles have names defined as hierarchical paths (https://github.com/hashicorp/vault-plugin-secrets-openldap/pull/115)

## v0.14.0

### IMPROVEMENTS:

* update dependencies [GH-113](https://github.com/hashicorp/vault-plugin-secrets-openldap/pull/113)
  * `github.com/go-ldap/ldap/v3` v3.4.6 -> v3.4.8
  * `github.com/hashicorp/go-hclog` v1.6.2 -> v1.6.3
  * `github.com/hashicorp/go-secure-stdlib/parseutil` v0.1.7 -> v0.1.8
  * `github.com/hashicorp/vault/api` v1.13.0 -> v1.14.0
  * `github.com/hashicorp/vault/sdk` v0.12.0 -> v0.13.0
  * `golang.org/x/text` v0.14.0 -> v0.18.0
  * `github.com/hashicorp/go-retryablehttp` v0.7.1 -> v0.7.7
* bump .go-version to 1.22.6

## v0.13.7

BUG FIXES:

* Fix issue where roles created before 0.14.5 had a nil NextVaultRotation value: [GH-160](https://github.com/hashicorp/vault-plugin-secrets-openldap/pull/160)

## v0.13.5

BUG FIXES:

* Fix a bug where static role passwords are erroneously rotated across backend restarts when using skip import rotation. (https://github.com/hashicorp/vault-plugin-secrets-openldap/pull/140)

## v0.13.4

BUG FIXES:

* Update static role rotation to generate a new password after 2 failed attempts (https://github.com/hashicorp/vault-plugin-secrets-openldap/pull/125)

IMPROVEMENTS:
* Updated dependencies (https://github.com/hashicorp/vault-plugin-secrets-openldap/pull/133):
  * `github.com/docker/docker` v24.0.9+incompatible -> v25.0.6+incompatible
  * `github.com/hashicorp/go-retryablehttp` v0.7.1 -> v0.7.7
  * `golang.org/x/net` v0.23.0 -> v0.30.0
  * `google.golang.org/protobuf` v1.33.0 ->  v1.35.2

## v0.13.1

BUG FIXES:
* fix a panic on init when static roles have names defined as hierarchical paths (https://github.com/hashicorp/vault-plugin-secrets-openldap/pull/116)

## v0.13.0

FEATURES:
* Enable role and set names with hierarchical paths
  * https://github.com/hashicorp/vault-plugin-secrets-openldap/pull/102
  * https://github.com/hashicorp/vault-plugin-secrets-openldap/pull/104
  * https://github.com/hashicorp/vault-plugin-secrets-openldap/pull/105

IMPROVEMENTS:
* Updated dependencies (https://github.com/hashicorp/vault-plugin-secrets-openldap/pull/101):
   * `github.com/go-ldap/ldap/v3` v3.4.4 -> v3.4.6
   * `github.com/hashicorp/go-hclog` v1.5.0 -> v1.6.2
   * `github.com/hashicorp/go-secure-stdlib/parseutil` v0.1.7 -> v0.1.8
   * `github.com/hashicorp/vault/api` v1.9.2 -> v1.13.0
   * `github.com/hashicorp/vault/sdk` v0.11.1-0.20240325190132-c20eae3e84c5 -> v0.12.0
   * `github.com/stretchr/testify` v1.8.4 -> v1.9.0

## v0.12.6

BUG FIXES:

* Fix issue where roles created before 0.14.5 had a nil NextVaultRotation value: [GH-161](https://github.com/hashicorp/vault-plugin-secrets-openldap/pull/161)

## v0.12.4

BUG FIXES:

* Fix a bug where static role passwords are erroneously rotated across backend restarts when using skip import rotation. (https://github.com/hashicorp/vault-plugin-secrets-openldap/pull/140)

## v0.12.3

BUG FIXES:

* Update static role rotation to generate a new password after 2 failed attempts (https://github.com/hashicorp/vault-plugin-secrets-openldap/pull/125)

IMPROVEMENTS:
* Updated dependencies (https://github.com/hashicorp/vault-plugin-secrets-openldap/pull/133):
  * `github.com/docker/docker` v24.0.9+incompatible -> v25.0.6+incompatible
  * `github.com/hashicorp/go-retryablehttp` v0.7.1 -> v0.7.7
  * `github.com/go-jose/go-jose/v3` v3.0.1 -> v3.0.3
  * `golang.org/x/net` v0.17.0 -> v0.28.0
  * `google.golang.org/protobuf` v1.30.0 ->  v1.34.2

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
