scenario "plugin_upgrade" {
  description = <<-EOF
    Verifies that changes on the current branch do not introduce regressions in the
    LDAP secrets engine plugin. The scenario runs in two phases against the same
    live Vault cluster:

      Phase 1 — Baseline: run the full blackbox test suite against the builtin
      released plugin that ships with the Vault image. This confirms the starting
      state is healthy and seeds real plugin data (mounts, roles, leases).

      Phase 2 — Upgrade: copy the candidate plugin binary (built from this branch)
      into the running container, register it in the Vault plugin catalog, and
      reload the secrets engine mount to hot-swap the plugin in-place. Then re-run
      the full blackbox suite to confirm that all existing data and functionality
      are preserved under the candidate plugin.
  EOF

  matrix {
    # Each value in vault_version produces one independent test run. The scenario upgrades
    # FROM that released version TO the candidate plugin built from this branch. Running
    # all variants together gives confidence that the candidate plugin is safe to ship
    # regardless of which supported Vault version a customer is currently running.
    #
    # Versions are pinned to the latest patch of each active minor release branch.
    # The source of truth is vault-enterprise/.release/versions.hcl.
    #
    # To refresh the list, run the pipeline tool and copy the output here:
    #   1.x (active minors 1.19, 1.20, 1.21):
    #     cd vault-enterprise/tools/pipeline && \
    #     go run . releases list versions --edition enterprise --upper 1.21.99 --lower 1.19.0 -f json \
    #     | jq -r '.versions | map(select(. | test("^1\\.(19|20|21)\\."))) | group_by(split(".")[1]) | map(max) | .[]'
    #   2.x:
    #     cd vault-enterprise/tools/pipeline && \
    #     go run . releases list versions --edition enterprise --upper 2.99.99 --lower 2.0.0 -f json \
    #     | jq -r '.versions | map(select(. | test("^2\\."))) | sort | .[]'
    #
    # TODO: Enos does not support dynamic matrix values, so this list must be kept
    # up to date manually. Automation options: a weekly GitHub Actions cron that
    # opens a version-bump PR, or a pre-commit hook that warns when the list is stale.
    vault_version = ["2.0.0", "1.21.5", "1.20.9", "1.19.9"]
  }

  terraform_cli = terraform_cli.default
  terraform     = terraform.default

  # Create an isolated Docker bridge network for this scenario variant.
  # Each matrix cell (vault_version) gets its own network and non-overlapping
  # subnet so all variants can run concurrently on the same host without conflict.
  step "create_network" {
    description = "Create an isolated Docker bridge network for this scenario variant."
    module = module.docker_network

    variables {
      network_name = "${var.docker_network_name}-${matrix.vault_version}"
      # Subnets are statically mapped per version to guarantee no CIDR overlap
      # when running all matrix variants concurrently on the same host.
      subnet = matrix.vault_version == "2.0.0" ? "172.24.0.0/16" : (matrix.vault_version == "1.21.5" ? "172.25.0.0/16" : (matrix.vault_version == "1.20.9" ? "172.26.0.0/16" : "172.27.0.0/16"))
    }
  }

  # Deploy an OpenLDAP container into the Docker network.
  # Provides the real LDAP directory backend that the secrets engine connects to,
  # so both the released and candidate plugins exercise genuine LDAP operations.
  step "setup_ldap" {
    description = "Deploy an OpenLDAP container as the LDAP backend for the secrets engine."
    module     = module.ldap_container
    depends_on = [step.create_network]

    variables {
      network_id          = step.create_network.network_id
      container_name      = "openldap-poc-${matrix.vault_version}"
      ldap_admin_password = "adminpassword"
      # Ports are offset per version to avoid collisions when running in parallel.
      ldap_port  = matrix.vault_version == "2.0.0" ? 1389 : (matrix.vault_version == "1.21.5" ? 1390 : (matrix.vault_version == "1.20.9" ? 1391 : 1392))
      ldaps_port = matrix.vault_version == "2.0.0" ? 1636 : (matrix.vault_version == "1.21.5" ? 1637 : (matrix.vault_version == "1.20.9" ? 1638 : 1639))
    }
  }

  # Deploy a Vault cluster into the Docker network.
  # Vault starts with its builtin released plugin — this is the baseline state
  # we test against in Phase 1 before upgrading to the candidate plugin.
  step "create_vault_cluster" {
    description = "Deploy a Vault cluster running the builtin released plugin."
    module     = module.vault_cluster
    depends_on = [step.create_network]

    variables {
      network_id    = step.create_network.network_id
      cluster_name  = "${var.vault_cluster_name}-${matrix.vault_version}"
      vault_version = matrix.vault_version
      vault_edition = "ent"
      # License is required for enterprise editions. Supply via var.vault_license_path.
      vault_license = var.vault_license_path != "" ? trimspace(file(abspath(var.vault_license_path))) : ""
      # API ports are offset per version to avoid collisions when running in parallel.
      vault_port = matrix.vault_version == "2.0.0" ? 8199 : (matrix.vault_version == "1.21.5" ? 8200 : (matrix.vault_version == "1.20.9" ? 8201 : 8202))
    }
  }

  # Phase 1 — Baseline: run the blackbox suite against the builtin released plugin.
  # This confirms the starting state is healthy and creates real plugin data
  # (mounts, roles, leases) that must survive the upgrade intact.
  # If this step fails, the upgrade step is never reached.
  step "run_baseline_tests" {
    description = "Run blackbox tests against the builtin released plugin to establish a healthy baseline."
    module     = module.run_test
    depends_on = [step.setup_ldap, step.create_vault_cluster]

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

  # Copy the candidate plugin binary into a per-variant host directory so the
  # upgrade step can docker cp it into the running container. Runs in parallel
  # with run_baseline_tests since it only touches the host filesystem.
  step "stage_candidate_plugin" {
    description = "Copy the candidate plugin binary to the host staging directory."
    module      = module.stage_candidate_plugin
    # Explicit depends_on prevents Enos from scheduling this after upgrade_to_candidate_plugin.
    depends_on  = [step.create_network]

    variables {
      plugin_binary_path = var.plugin_binary_path
      plugin_name        = "vault-plugin-secrets-openldap"
      # Per-variant directory prevents parallel matrix runs from clobbering each other.
      plugin_dir = abspath("${path.root}/.enos/plugins/${matrix.vault_version}")
    }
  }

  # Phase 2 — Upgrade: docker cp the staged binary into the running container,
  # register it in the Vault plugin catalog with the new SHA256, and reload
  # the secrets engine mount to hot-swap the plugin in-place. Vault does not
  # restart; all existing mount data is preserved.
  step "upgrade_to_candidate_plugin" {
    description = "Upgrade the running LDAP secrets engine to the candidate plugin."
    module      = module.upgrade_plugin
    depends_on  = [step.run_baseline_tests, step.stage_candidate_plugin]

    variables {
      vault_address        = step.create_vault_cluster.vault_address
      vault_token          = step.create_vault_cluster.vault_token
      vault_container_name = "${var.vault_cluster_name}-${matrix.vault_version}-node"
      # Pass dir and name separately — Enos does not allow string interpolation
      # of step outputs; the script assembles the full path as PLUGIN_DIR/PLUGIN_NAME.
      plugin_dir           = step.stage_candidate_plugin.plugin_dir
      plugin_name          = step.stage_candidate_plugin.plugin_name
      plugin_mount         = "ldap"
    }
  }

  # Phase 2 — Verification: re-run the full blackbox suite against the same
  # Vault cluster now running the candidate plugin. Tests verify that all data
  # created in Phase 1 (mounts, roles, leases) is still intact and functional,
  # and that new operations complete successfully. Any failure is a regression.
  step "run_blackbox_system_tests" {
    description = "Run blackbox tests against the candidate plugin to detect regressions."
    module     = module.run_test
    depends_on = [step.upgrade_to_candidate_plugin]

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

  # ---------------------------------------------------------------------------
  # Outputs
  # Expose key connection details so they can be inspected after a run or used
  # by downstream enos steps/scenarios in the future.
  # ---------------------------------------------------------------------------

  output "vault_address" {
    description = "Vault cluster API address for this matrix variant"
    value       = step.create_vault_cluster.vault_address
  }

  output "vault_token" {
    description = "Vault root token (sensitive)"
    value       = step.create_vault_cluster.vault_token
    sensitive   = true
  }

  output "ldap_url" {
    description = "Internal LDAP connection URL (container-to-container)"
    value       = step.setup_ldap.ldap_url
  }

  output "ldap_url_public" {
    description = "Public LDAP connection URL (host-to-container, for local debugging)"
    value       = step.setup_ldap.ldap_url_public
  }

  output "ldap_bind_dn" {
    description = "LDAP bind DN used by the secrets engine connection config"
    value       = step.setup_ldap.ldap_bind_dn
  }

  output "ldap_bind_pass" {
    description = "LDAP bind password (sensitive)"
    value       = step.setup_ldap.ldap_bind_pass
    sensitive   = true
  }
}
