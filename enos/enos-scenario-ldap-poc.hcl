scenario "ldap_poc" {
  description = "POC scenario for LDAP plugin testing with Docker backend"

  matrix {
    # Versions from vault-enterprise/.release/versions.hcl (active branches)
    # Latest patch versions for each active minor version (1.19.x, 1.20.x, 1.21.x, 2.x.x)
    # To update 1.x: cd vault-enterprise/tools/pipeline && go run . releases list versions --edition enterprise --upper 1.21.99 --lower 1.19.0 -f json | jq -r '.versions | map(select(. | test("^1\\.(19|20|21)\\."))) | group_by(split(".")[1]) | map(max) | .[]'
    # To update 2.x: cd vault-enterprise/tools/pipeline && go run . releases list versions --edition enterprise --upper 2.99.99 --lower 2.0.0 -f json | jq -r '.versions | map(select(. | test("^2\\."))) | sort | .[]'
    #
    # TODO: Automate version updates
    # Enos doesn't support dynamic matrix values. Options:
    # 1. Create update-versions.sh script that runs pipeline tool and updates this file via sed
    # 2. Add GitHub Actions workflow (weekly cron) to auto-create PR with version updates
    # 3. Pre-commit hook to check if versions are stale (compare with pipeline tool output)
    vault_version = ["2.0.0", "1.21.5", "1.20.9", "1.19.9"]
  }

  terraform_cli = terraform_cli.default
  terraform     = terraform.default

  step "create_network" {
    description = "Create Docker network for the cluster"
    module      = module.docker_network

    variables {
      network_name  = "${var.docker_network_name}-${matrix.vault_version}"
      vault_version = matrix.vault_version
    }
  }

  step "setup_ldap" {
    description = "Deploy OpenLDAP container"
    module      = module.ldap_container
    depends_on  = [step.create_network]

    variables {
      network_id          = step.create_network.network_id
      container_name      = "openldap-poc-${matrix.vault_version}"
      vault_version       = matrix.vault_version
      ldap_admin_password = "adminpassword"
    }
  }

  step "create_vault_cluster" {
    description = "Deploy Vault cluster in Docker"
    module      = module.vault_cluster
    depends_on  = [step.create_network]

    variables {
      network_id    = step.create_network.network_id
      cluster_name  = "${var.vault_cluster_name}-${matrix.vault_version}"
      vault_version = matrix.vault_version
      vault_edition = "ent"
      vault_license = var.vault_license_path != "" ? trimspace(file(abspath(var.vault_license_path))) : ""
      # Bind-mount a per-variant host directory into /vault/plugins so Vault's
      # -dev-plugin-dir flag finds a valid path on startup. Without this the
      # container exits immediately because /vault/plugins does not exist inside
      # the image. The vault_cluster module creates the directory before starting
      # the container, so no binary needs to be staged for this scenario.
      plugin_dir    = abspath("${path.root}/.enos/plugins/${matrix.vault_version}")
    }
  }

  step "run_blackbox_system_tests" {
    description = "Run plugin-owned blackbox SystemTests"
    module      = module.run_test
    depends_on  = [step.setup_ldap, step.create_vault_cluster]

    variables {
      vault_address      = step.create_vault_cluster.vault_address
      vault_token        = step.create_vault_cluster.vault_token
      vault_cluster_name = "${var.vault_cluster_name}-${matrix.vault_version}"
      repo_root          = abspath("${path.root}/..")
      test_package       = "./blackbox"
      test_timeout       = "5m"
      ldap_url_private   = step.setup_ldap.ldap_url
      ldap_url_public    = step.setup_ldap.ldap_url_public
      ldap_bind_dn       = step.setup_ldap.ldap_bind_dn
      ldap_bind_pass     = step.setup_ldap.ldap_bind_pass
      ldap_username      = "enos"
      ldap_admin_pw      = step.setup_ldap.ldap_bind_pass
    }
  }

  output "vault_address" {
    description = "Vault cluster address"
    value       = step.create_vault_cluster.vault_address
  }

  output "vault_token" {
    description = "Vault root token"
    value       = step.create_vault_cluster.vault_token
    sensitive   = true
  }

  output "ldap_url" {
    description = "LDAP connection URL"
    value       = step.setup_ldap.ldap_url
  }

  output "ldap_url_public" {
    description = "LDAP connection URL (public/host)"
    value       = step.setup_ldap.ldap_url_public
  }

  output "ldap_bind_dn" {
    description = "LDAP bind DN"
    value       = step.setup_ldap.ldap_bind_dn
  }

  output "ldap_bind_pass" {
    description = "LDAP bind password"
    value       = step.setup_ldap.ldap_bind_pass
    sensitive   = true
  }
}
