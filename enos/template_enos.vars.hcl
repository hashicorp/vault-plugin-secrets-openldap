// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

// ========================= IMPORTANT =================================
// COPY this file to an `enos*.vars.hcl` and fill in the required values.
// =====================================================================

// artifactory_token is the token to use when authenticating to artifactory.
// artifactory_token = "yourtoken"

// artifactory_host is the artifactory host to search for vault artifacts.
// artifactory_host = "https://artifactory.hashicorp.engineering/artifactory"

// artifactory_repo is the artifactory repo to search for vault artifacts.
// artifactory_repo = "hashicorp-crt-stable-local*"

// aws_region is the AWS region where we'll create infrastructure
// for the smoke scenario
// aws_region = "us-east-1"

// aws_ssh_keypair_name is the AWS keypair to use for SSH
// aws_ssh_keypair_name = "enos-ci-ssh-key"

// aws_ssh_private_key_path is the path to the AWS keypair private key
// aws_ssh_private_key_path = "./support/private_key.pem"

// backend_log_level is the server log level for the backend. Supported values include 'trace',
// 'debug', 'info', 'warn', 'error'"
// backend_log_level = "trace"

// backend_instance_type is the instance type to use for the Vault backend. Must support arm64
// backend_instance_type = "t4g.small"

// project_name is the description of the project. It will often be used to tag infrastructure
// resources.
// project_name = "vault-openldap-se-enos-integration"

// distro_version_amzn is the version of Amazon Linux 2 to use for "distro:amzn" variants
// distro_version_amzn = "2"

// distro_version_ubuntu is the version of ubuntu to use for "distro:ubuntu" variants
// distro_version_ubuntu = "22.04" // or "24.04"

// ldap_artifact_path is the path to the LDAP plugin artifact (zip file) to be installed.
// ldap_artifact_path = "~/go/vault-plugins/vault-plugin-secrets-openldap.zip"

// ldap_artifactory_repo is the Artifactory repository where the LDAP plugin artifact is stored.
// ldap_artifactory_repo = "hashicorp-vault-ecosystem-staging-local"

// ldap_base_dn is the base distinguished name for the LDAP directory.
// ldap_base_dn = "dc=example,dc=com"

// ldap_bind_pass is the password for the LDAP bind distinguished name.
// ldap_bind_pass = "adminpassword"

// ldap_dynamic_role_ldif_templates_path is the path to the LDIF templates for dynamic roles.
// ldap_dynamic_role_ldif_templates_path = "/tmp"

// ldap_dynamic_user_role_name is the name of the dynamic role for LDAP users.
// ldap_dynamic_user_role_name = "adam"

// ldap_library_set_name is the name of the library set to use for the LDAP plugin.
// ldap_library_set_name = "dev-team"

// ldap_plugin_version is the version of the LDAP plugin being used.
// ldap_plugin_version = "0.15.0"

// ldap_revision is the git SHA of the LDAP plugin artifact being tested.
// ldap_revision = "2ee1253cb5ff67196d0e4747e8aedd1c4903625f"

// ldap_rotation_period is the period after which the LDAP root creds will be rotated.
// ldap_rotation_period = "10" // (in seconds)

// ldap_rotation_window is the time window during which the LDAP root creds can be rotated.
// ldap_rotation_window = "3600" // (in seconds)

// ldap_schema specifies the LDAP schema to use (e.g., openldap).
// ldap_schema = "openldap"

// ldap_service_account_names is a list of service account names to be used with the LDAP plugin.
// ldap_service_account_names = ["staticuser", "bob.johnson", "mary.smith"]

// ldap_tag is the tag or version identifier for the LDAP plugin build.
// ldap_tag = "1.3.0"

// ldap_username is the username for the LDAP user to authenticate.
// ldap_username = "mary"

// ldap_user_old_password is the old password for the LDAP user.
// ldap_user_old_password = "defaultpassword"

// ldap_user_role_name is the name of the role on the Vault side.
// ldap_user_role_name = "mary"

// makefile_dir is the directory containing the Makefile for building the plugin.
// makefile_dir = "/Users/<user>/hashicorp/plugins/vault-plugin-secrets-openldap/"

// plugin_dest_dir is the local directory where the plugin artifact will be stored.
// plugin_dest_dir = "/Users/<user>/go/vault-plugins"

// plugin_dir_vault is the directory on the Vault server where plugins are installed.
// plugin_dir_vault = "/etc/vault/plugins"

// plugin_mount_path is the mount path in Vault where the plugin will be enabled.
// plugin_mount_path = "local-secrets-ldap"

// plugin_name is the name of the Vault plugin to be used for LDAP secrets.
// plugin_name = "vault-plugin-secrets-openldap"

// tags are a map of tags that will be applied to infrastructure resources that
// support tagging.
// tags = { "Project Name" : "Vault", "Something Cool" : "Value" }

// terraform_plugin_cache_dir is the directory to cache Terraform modules and providers.
// It must exist.
// terraform_plugin_cache_dir = "/Users/<user>/.terraform/plugin-cache-dir

// ui_test_filter is the test filter to limit the ui tests to execute for the ui scenario. It will
// be appended to the ember test command as '-f=\"<filter>\"'.
// ui_test_filter = "sometest"

// ui_run_tests sets whether to run the UI tests or not for the ui scenario. If set to false a
// cluster will be created but no tests will be run.
// ui_run_tests = true

// vault_artifact_path is the path to CRT generated or local vault.zip bundle. When
// using the "builder:local" variant a bundle will be built from the current branch.
// In CI it will use the output of the build workflow.
// vault_artifact_path = "./dist/vault.zip"

// vault_artifact_type is the type of Vault artifact to use when installing Vault from artifactory.
// It should be 'package' for .deb or # .rpm package and 'bundle' for .zip bundles"
// vault_artifact_type = "bundle"

// vault_build_date is the build date for Vault artifact. Some validations will require the binary build
// date to match"
// vault_build_date = "2023-07-07T14:06:37Z" // make ci-get-date for example

// vault_enable_audit_devices sets whether or not to enable every audit device. It true
// a file audit device will be enabled at the path /var/log/vault_audit.log, the syslog
// audit device will be enabled, and a socket audit device connecting to 127.0.0.1:9090
// will be enabled. The netcat program is run in listening mode to provide an endpoint
// that the socket audit device can connect to.
// vault_enable_audit_devices = true

// vault_install_dir is the directory where the vault binary will be installed on
// the remote machines.
// vault_install_dir = "/opt/vault/bin"

// vault_local_binary_path is the path of the local binary that we're upgrading to.
// vault_local_binary_path = "./support/vault"

// vault_instance_type is the instance type to use for the Vault backend
// vault_instance_type = "t3.small"

// vault_instance_count is how many instances to create for the Vault cluster.
// vault_instance_count = 3

// vault_license_path is the path to a valid Vault enterprise edition license.
// This is only required for non-ce editions"
// vault_license_path = "./support/vault.hclic"

// vault_local_build_tags override the build tags we pass to the Go compiler for builder:local variants.
// vault_local_build_tags = ["ui", "ent"]

// vault_log_level is the server log level for Vault logs. Supported values (in order of detail) are
// trace, debug, info, warn, and err."
// vault_log_level = "trace"

// vault_product_version is the version of Vault we are testing. Some validations will expect the vault
// binary and cluster to report this version.
// vault_product_version = "1.15.0"

// vault_revision is the git sha of Vault artifact we are testing. Some validations will expect the vault
// binary and cluster to report this revision.
// vault_revision = "df733361af26f8bb29b63704168bbc5ab8d083de"