## Unreleased

FEATURES:

- Adds service account check-out functionality for `ad`, `openldap`, and `racf` schemas.

IMPROVEMENTS:

- Adds the `last_password` field to the `static-cred` read response in case newly rotated
  password takes time to propagate.
- Adds the `userdn` and `userattr` configuration parameters to control how user LDAP 
  search is performed for service account check-out and static roles.
- Adds the `upndomain` configuration parameter to allow construction of a userPrincipalName 
  (UPN) string for authentication.

BUG FIXES:

- Properly set `LastBindPassword` and `last_bind_password_rotation` to fix fallback
  bind attempt after a rotate-root operation.
- Disallow `username` and `dn` modification for static role updates to prevent possible 
  password rotation of a user after it's no longer managed by the static role.
- Disallow the same user from being managed by more than one static role.
