# Terraform Bootstrap

## RACF Test

The `racf` directory contains terraform config to

- create 10 users on your RACF LDAP server with password phrases
- configure the openldap secrets engine to connect to your RACF server
- create 10 static roles to manage the RACF user password phrases

### Prerequisites

- Vault server running with a `plugin_directory` configured
- RACF LDAP Server
- Modify `variables.tf` as necessary for your environment; in particular, `racf_bind_username`.

### Setup
Build, copy the plugin binary to the plugin dir, and register the plugin with Vault:
```
export PLUGIN_DIR=<your plugin dir path>
export PLUGIN_PATH=racf
make configure
```

Create the RACF users and configure the secrets engine:
```
cd bootstrap/terraform/racf/
export TF_VAR_racf_bind_password=foobar
terraform apply
```

### Teardown
Cleanup the RACF users and Vault:
```
terraform destroy
```
