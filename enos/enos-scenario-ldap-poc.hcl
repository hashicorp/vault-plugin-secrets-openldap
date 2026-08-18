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
      network_name = "${var.docker_network_name}-${matrix.vault_version}"
      subnet       = matrix.vault_version == "2.0.0" ? "172.24.0.0/16" : (matrix.vault_version == "1.21.5" ? "172.25.0.0/16" : (matrix.vault_version == "1.20.9" ? "172.26.0.0/16" : "172.27.0.0/16"))
    }
  }

  step "setup_ldap" {
    description = "Deploy OpenLDAP container"
    module      = module.ldap_container
    depends_on  = [step.create_network]

    variables {
      network_id          = step.create_network.network_id
      container_name      = "openldap-poc-${matrix.vault_version}"
      ldap_domain         = "example.org"
      ldap_admin_password = "adminpassword"
      ldap_port           = matrix.vault_version == "2.0.0" ? 1389 : (matrix.vault_version == "1.21.5" ? 1390 : (matrix.vault_version == "1.20.9" ? 1391 : 1392))
      ldaps_port          = matrix.vault_version == "2.0.0" ? 1636 : (matrix.vault_version == "1.21.5" ? 1637 : (matrix.vault_version == "1.20.9" ? 1638 : 1639))
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
      vault_port    = matrix.vault_version == "2.0.0" ? 8199 : (matrix.vault_version == "1.21.5" ? 8200 : (matrix.vault_version == "1.20.9" ? 8201 : 8202))
    }
  }

  step "run_blackbox_system_tests" {
    description = "Run plugin-owned blackbox SystemTests"
    module      = module.run_test
    depends_on  = [step.setup_ldap, step.create_vault_cluster]

    variables {
      vault_address    = step.create_vault_cluster.vault_address
      vault_token      = step.create_vault_cluster.vault_token
      repo_root        = abspath("${path.root}/..")
      test_package     = "./blackbox"
      test_timeout     = "5m"
      ldap_url_private = step.setup_ldap.ldap_url
      ldap_url_public  = step.setup_ldap.ldap_url_public
      ldap_bind_dn     = step.setup_ldap.ldap_bind_dn
      ldap_bind_pass   = step.setup_ldap.ldap_bind_pass
      ldap_username    = "enos"
      ldap_admin_pw    = step.setup_ldap.ldap_bind_pass
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