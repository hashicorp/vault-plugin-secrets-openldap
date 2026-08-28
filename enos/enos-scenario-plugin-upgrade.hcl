scenario "plugin_upgrade" {
  description = <<-EOF
    Verifies that changes on the current branch do not introduce regressions in the
    LDAP secrets engine plugin. The scenario runs in two phases against the same
    live Vault cluster:

      Phase 1 — Candidate: register the plugin built from this branch, then run
      the full blackbox test suite against it. This confirms the unreleased plugin
      works correctly before any comparison to the released version.

      Phase 2 — Released: remove the candidate plugin registration so Vault falls
      back to the builtin released plugin that ships with the image, then re-run
      the full blackbox suite to confirm that the released baseline is also
      unaffected. Any regression here points to an environment or infrastructure
      issue rather than a plugin code change.
  EOF

  matrix {
    # Each value in vault_version produces one independent test run. The scenario
    # tests the candidate plugin built from this branch first, then reverts to
    # the released builtin plugin that ships with the Vault image. Running all
    # variants together gives confidence that the candidate plugin is safe to
    # ship regardless of which supported Vault version a customer is currently running.
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
    #
    # NOTE: Vault 2.x (e.g. 2.0.0) requires a new "Vaultlink" license format
    # that is incompatible with the 1.x VAULT_LICENSE CI secret. For CI, only
    # re-add 2.x versions once a separate VAULT_LICENSE_V2 secret is provisioned.
    # For local runs, supply a valid 2.x license via var.vault_license_path.
    vault_version = ["2.0.0", "1.21.5", "1.20.9", "1.19.9"]
  }

  terraform_cli = terraform_cli.default
  terraform     = terraform.default

  # ---------------------------------------------------------------------------
  # Step 1 — Create network
  # ---------------------------------------------------------------------------

  # Create an isolated Docker bridge network for this scenario variant.
  # Each matrix cell (vault_version) gets its own network and non-overlapping
  # subnet so all variants can run concurrently on the same host without conflict.
  # The docker_network module derives the unique subnet from vault_version.
  step "create_network" {
    description = "Create an isolated Docker bridge network for this scenario variant."
    module      = module.docker_network

    variables {
      network_name  = "${var.docker_network_name}-${matrix.vault_version}"
      vault_version = matrix.vault_version
    }
  }

  # ---------------------------------------------------------------------------
  # Step 2 — Deploy backend dependencies (LDAP + candidate plugin)
  # Both steps depend only on the network and are independent of each other,
  # so they can run in parallel.
  # ---------------------------------------------------------------------------

  # Deploy an OpenLDAP container into the Docker network.
  # Provides the real LDAP directory backend that the secrets engine connects to,
  # so both the candidate and released plugins exercise genuine LDAP operations.
  # The ldap_container module derives unique host ports from vault_version.
  step "setup_ldap" {
    description = "Deploy an OpenLDAP container as the LDAP backend for the secrets engine."
    module      = module.ldap_container
    depends_on  = [step.create_network]

    variables {
      network_id          = step.create_network.network_id
      container_name      = "openldap-${matrix.vault_version}"
      vault_version       = matrix.vault_version
      ldap_admin_password = "adminpassword"
    }
  }

  # Cross-compile the candidate plugin binary for linux/arm64 and write it into
  # a per-variant host directory. Must complete before create_vault_cluster so
  # the directory exists when Docker bind-mounts it into the container.
  step "stage_candidate_plugin" {
    description = "Cross-compile the candidate plugin for linux/arm64 and stage it on the host for the Vault container bind-mount."
    module      = module.stage_candidate_plugin
    depends_on  = [step.create_network]

    variables {
      repo_root   = abspath("${path.root}/..")
      plugin_name = "vault-plugin-secrets-openldap"
      # Absolute path to go so the enos non-login shell doesn't pick up a
      # stale system Go from /usr/local/go instead of the GVM-managed version.
      go_binary  = var.go_binary
      plugin_dir = abspath("${path.root}/.enos/plugins/${matrix.vault_version}")
    }
  }

  # ---------------------------------------------------------------------------
  # Step 3 — Deploy Vault cluster
  # ---------------------------------------------------------------------------

  # Deploy a Vault cluster into the Docker network.
  # Vault starts with its builtin released plugin available. The candidate plugin
  # binary is already present on disk via the bind-mount; we register it in the
  # catalog before Phase 1 so Phase 1 exercises the unreleased candidate.
  # The vault_cluster module derives the unique host port from vault_version.
  step "create_vault_cluster" {
    description = "Deploy a Vault cluster with the candidate plugin staged and ready for registration."
    module      = module.vault_cluster
    depends_on  = [step.create_network, step.stage_candidate_plugin]

    variables {
      network_id    = step.create_network.network_id
      cluster_name  = "${var.vault_cluster_name}-${matrix.vault_version}"
      vault_version = matrix.vault_version
      vault_edition = "ent"
      # License is required for enterprise editions. Supply via var.vault_license_path.
      vault_license = var.vault_license_path != "" ? trimspace(file(abspath(var.vault_license_path))) : ""
      # Bind-mount the per-variant staging directory so the upgrade step can
      # inject the candidate plugin binary without restarting the container.
      plugin_dir    = abspath("${path.root}/.enos/plugins/${matrix.vault_version}")
    }
  }

  # ---------------------------------------------------------------------------
  # Phase 1 — Candidate plugin
  # ---------------------------------------------------------------------------

  # Register the candidate plugin in the Vault plugin catalog before running
  # Phase 1 tests. This ensures Phase 1 exercises the unreleased plugin built
  # from this branch rather than the builtin released plugin.
  step "register_candidate_plugin" {
    description = "Register the candidate plugin binary in the Vault plugin catalog so Phase 1 tests run against the unreleased plugin."
    module      = module.manage_plugin
    depends_on  = [step.setup_ldap, step.create_vault_cluster]

    variables {
      action               = "register"
      vault_address        = step.create_vault_cluster.vault_address
      vault_token          = step.create_vault_cluster.vault_token
      vault_container_name = "${var.vault_cluster_name}-${matrix.vault_version}-node"
      plugin_dir           = step.stage_candidate_plugin.plugin_dir
      plugin_name          = step.stage_candidate_plugin.plugin_name
    }
  }

  # Run the blackbox suite against the candidate plugin.
  # Confirms the unreleased plugin works correctly and creates real plugin data
  # (mounts, roles, leases) before we revert to the released plugin.
  # If this step fails, the released-plugin test step is never reached.
  step "run_candidate_tests" {
    description = "Run blackbox tests against the candidate plugin built from this branch."
    module      = module.run_test
    depends_on  = [step.register_candidate_plugin]

    variables {
      vault_address      = step.create_vault_cluster.vault_address
      vault_token        = step.create_vault_cluster.vault_token
      vault_cluster_name = "${var.vault_cluster_name}-${matrix.vault_version}"
      repo_root          = abspath("${path.root}/..")
      seed_ldif          = abspath("${path.root}/modules/run_test/testdata/seed.ldif")
      test_package       = "./blackbox"
      test_timeout       = var.blackbox_test_timeout
      ldap_url_private   = step.setup_ldap.ldap_url
      ldap_url_public    = step.setup_ldap.ldap_url_public
      ldap_bind_dn       = step.setup_ldap.ldap_bind_dn
      ldap_bind_pass     = step.setup_ldap.ldap_bind_pass
      ldap_username      = "enos"
      ldap_admin_pw      = step.setup_ldap.ldap_bind_pass
    }
  }

  # ---------------------------------------------------------------------------
  # Phase 2 — Released (builtin) plugin
  # ---------------------------------------------------------------------------

  # Remove the candidate plugin catalog entry so Vault falls back to the builtin
  # released plugin that ships with the image. No container restart is needed —
  # Vault resolves the plugin from the builtin registry the next time a fresh
  # ldap/ mount is enabled by the Phase 2 tests.
  step "revert_to_released_plugin" {
    description = "Remove the candidate catalog entry so Vault reverts to the builtin released plugin for Phase 2 tests."
    module      = module.manage_plugin
    depends_on  = [step.run_candidate_tests]

    variables {
      action        = "revert"
      vault_address = step.create_vault_cluster.vault_address
      vault_token   = step.create_vault_cluster.vault_token
      plugin_name   = step.stage_candidate_plugin.plugin_name
    }
  }

  # ---------------------------------------------------------------------------
  # Phase 2 — Verification against released plugin
  # ---------------------------------------------------------------------------

  # Re-run the full blackbox suite against the same Vault cluster, now running
  # the builtin released plugin. Tests confirm the released plugin is healthy
  # and provides a stable baseline. Any failure here indicates an environment
  # or infrastructure issue rather than a regression in the candidate plugin.
  step "run_released_tests" {
    description = "Run blackbox tests against the builtin released plugin that ships with the Vault image."
    module      = module.run_test
    depends_on  = [step.revert_to_released_plugin]

    variables {
      vault_address      = step.create_vault_cluster.vault_address
      vault_token        = step.create_vault_cluster.vault_token
      vault_cluster_name = "${var.vault_cluster_name}-${matrix.vault_version}"
      repo_root          = abspath("${path.root}/..")
      seed_ldif          = abspath("${path.root}/modules/run_test/testdata/seed.ldif")
      test_package       = "./blackbox"
      test_timeout       = var.blackbox_test_timeout
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
