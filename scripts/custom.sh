vault namespace create test
vault namespace create -namespace=test ad1
vault secrets enable -namespace=test/ad1 openldap
vault write -namespace=test/ad1 sys/policies/password/example policy=@example_policy.hcl

vault write -namespace=test/ad1 openldap/config \
    url=ldaps://127.0.0.1 \
    binddn="CN=vault-ad-admin,CN=Users,DC=example,DC=com" \
    bindpass="foo-pass" \
    ttl=1m \
    schema=ad \
    insecure_tls=true

# vault write openldap/static-role/mary dn="CN=mary.smith,CN=Users,DC=example,DC=com" username="mary.smith" rotation_period="48h"
vault write -namespace=test/ad1 openldap/static-role/mary dn="CN=mary.smith,CN=Users,DC=example,DC=com" username="mary.smith" rotation_period="10s"
# vault write -namespace=test/ad1 openldap/rotate-role/mary

vault write -namespace=test/ad1 openldap/config \
    url=ldaps://127.0.0.1 \
    binddn="CN=vault-ad-admin,CN=Users,DC=example,DC=com" \
    bindpass="foo-pass" \
    ttl=1m \
    schema=ad \
    insecure_tls=true \
    password_policy="example"
# vault read openldap/static-cred/mary

# vault write sys/plugins/reload/backend mounts=openldap/

# MOUNT_UUID=$(vault read -format=json sys/mounts | jq -r '.data["openldap/"].uuid')
# echo $MOUNT_UUID
# vault list -format=json sys/raw/logical/$MOUNT_UUID/wal
# WAL_ID=$(vault list -format=json sys/raw/logical/$MOUNT_UUID/wal | jq -r '.[0]')
# echo $WAL_ID
# vault read -format=json sys/raw/logical/$MOUNT_UUID/wal/$WAL_ID | jq -r '.data.value' | jq -r '.data.last_vault_rotation, .created_at'

# vault read -format=json sys/raw/logical/$MOUNT_UUID/config
# vault read -format=json sys/raw/logical/$MOUNT_UUID/static-role/mary
