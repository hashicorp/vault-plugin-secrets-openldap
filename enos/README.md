# Enos

Enos is a quality testing framework that allows composing and executing quality
requirement scenarios as code. For the OpenLDAP secrets engine Vault plugin,
scenarios are currently executable from a developer machine that has the requisite dependencies 
and configuration. Future plans include executing scenarios via Github Actions.

Refer to the [Enos documentation](https://github.com/hashicorp/Enos-Docs)
for further information regarding installation, execution or composing Enos scenarios.

## Requirements
- AWS access. HashiCorp Vault developers should use Doormat.
- Terraform >= 1.7
- Enos >= v0.4.0. You can [download a release](https://github.com/hashicorp/enos/releases/) or
  install it with Homebrew:
  ```shell
  brew tap hashicorp/tap && brew update && brew install hashicorp/tap/enos
  ```
- An SSH keypair in the AWS region you wish to run the scenario. You can use
  Doormat to log in to the AWS console to create or upload an existing keypair.
- A Vault artifact is downloaded from the GHA artifacts when using the `artifact_source:crt` variants or from Artifactory when using `artifact_source:artifactory`.
- An OpenLDAP plugin artifact is downloaded from releases when using the `ldap_artifact_source:releases`, from Artifactory when using `ldap_artifact_source:artifactory`, and is built locally from the current branch when using  `ldap_artifact_source:local` variant.

## Scenario Variables
For local execution you can specify all the required variables using environment
variables, or you can update `enos.vars.hcl` with values and uncomment the lines.

Variables that are required (include):
* `aws_ssh_keypair_name`
* `aws_ssh_private_key_path`
* `vault_bundle_path`
* `vault_license_path` (only required for non-OSS editions)
* `plugin_name`
* `plugin_dir_vault`
* `ldap_bind_pass`
* `ldap_schema`
* `ldap_tag`
* `ldap_base_dn`
* `ldap_user_role_name`
* `ldap_username`
* `ldap_user_old_password`
* `ldap_dynamic_user_role_name`
* `ldap_dynamic_role_ldif_templates_path`
* `ldap_library_set_name`
* `ldap_service_account_names`

See [enos.vars.hcl](template_enos.vars.hcl) or [enos-variables.hcl](./enos-variables.hcl)
for further descriptions of the variables.

Additional variable information can also be found in the [Scenario Outlines](#scenario_outlines)

**[Future Works]** In CI, each scenario should be executed via Github Actions and should be configured using
environment variable inputs that follow the `ENOS_VAR_varname` pattern.

## Scenario Outlines
Enos is capable of producing an outline of each scenario that is defined in a given directory. These
scenarios often include a description of what behavior the scenario performs, which variants are
available, and which variables are required. They also provide a step by step breakdown including
which quality requirments are verifiend by a given step.

You can generate outlines of all scenarios or specify one via it's name.

From the `enos` directory:
```bash
enos scenario outline openldap_smoke
```

There are also HTML versions available for an improved reading experience:
```bash
enos scenario outline --format html > index.html
open index.html
```

## Executing Scenarios
From the `enos` directory:

```bash
# List all available scenarios
enos scenario list
# Run the smoke or restart scenario with a Vault artifact from Artifactory and an
# openLDAP secrets engine plugin artifact that is built locally.
# Make sure the local machine has been configured as detailed in the requirements section.
# This will execute the scenario and clean up any resources if successful.
enos scenario run openldap_smoke artifact_source:artifactory ldap_artifact_source:local 
enos scenario run openldap_restart artifact_source:artifactory ldap_artifact_source:local  
# To run a specific variant of a scenario, you can specify the variant values.
enos scenario run openldap_smoke arch:amd64 artifact_source:artifactory artifact_type:package config_mode:env \
  distro:amzn edition:ent ip_version:4 seal:shamir ldap_artifact_source:local ldap_config_root_rotation_method:manual
# Launch an individual scenario but leave infrastructure up after execution
enos scenario launch openldap_smoke artifact_source:artifactory ldap_artifact_source:local
# Check an individual scenario for validity. This is useful during scenario
# authoring and debugging.
enos scenario validate openldap_smoke artifact_source:artifactory ldap_artifact_source:local
# If you've run the tests and desire to see the outputs, such as the URL or
# credentials, you can run the output command to see them. Please note that
# after "run" or destroy there will be no "outputs" as the infrastructure
# will have been destroyed and state cleared.
enos scenario output openldap_smoke artifact_source:artifactory ldap_artifact_source:local
# Explicitly destroy all existing infrastructure
enos scenario destroy openldap_smoke artifact_source:artifactory ldap_artifact_source:local
```

Refer to the [Enos documentation](https://github.com/hashicorp/Enos-Docs)
for further information regarding installation, execution or composing scenarios.

# Variants
Both scenarios support a matrix of variants.

## `ldap_artifact_source:local`
This variant is for running the Enos scenario locally. It builds the plugin binary
from the current branch, placing the binary at the `ldap_artifact_path`.

## `ldap_artifact_source:releases`
This variant is for running the Enos scenario to test an artifact from HashiCorp releases. It requires following Enos variables to be set:
* `ldap_plugin_version`
* `ldap_revision`

## `ldap_artifact_source:artifactory`
This variant is for running the Enos scenario to test an artifact from Artifactory. It requires following Enos variables to be set:
* `artifactory_username`
* `artifactory_token`
* `aws_ssh_keypair_name`
* `aws_ssh_private_key_path`
* `ldap_plugin_version`
* `ldap_revision`
* `ldap_artifactory_repo`

Refer to the **Variants** section in the [Vault README on GitHub](https://github.com/hashicorp/vault/blob/main/README.md).
for further information regarding Vault's `artifact_source` matrix variants. <br>
Note: `artifact_source:local` isn't supported in this project since we never build Vault locally.

**[Future Work]** In order to achieve broad coverage while
keeping test run time reasonable, the variants executed by the `enos-run` Github
Actions (CI) should use `enos scenario sample` to maximize variant distribution per scenario.