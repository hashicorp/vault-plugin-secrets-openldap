scenario "plugin_upgrade" {
  description = <<-EOF
    Verifies that changes on the current branch do not introduce regressions in the
    LDAP secrets engine plugin. The scenario runs in two phases against the same
    live Vault cluster:

      Phase 1 — Baseline: run the full blackbox test suite against the builtin
      released plugin that ships with the Vault image. This confirms the starting
      state is healthy and seeds real plugin data (mounts, roles, leases).

      Phase 2 — Upgrade: copy the candidate plugin binary (built from this branch)
      into the running container, register it in the Vault plugin catalog, then
      re-run the full blackbox suite to confirm that all existing data and
      functionality are preserved under the candidate plugin.
  EOF

  matrix {
    # Each value in vault_version produces one independent test run. The scenario
    # upgrades FROM that released version TO the candidate plugin built from this
    # branch. Running all variants together gives confidence that the candidate
    # plugin is safe to ship regardless of which supported Vault version a
    # customer is currently running.
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
  # Port and subnet allocations
  #
  # Each matrix variant is assigned a unique set of ports and a unique subnet
  # so all four variants can run concurrently on the same host without conflict.
  #
  # Mapping (index → vault_version):
  #   0 → 2.0.0   subnet 172.24.0.0/16  vault_port 8199  ldap_port 1389  ldaps_port 1636
  #   1 → 1.21.5  subnet 172.25.0.0/16  vault_port 8200  ldap_port 1390  ldaps_port 1637
  #   2 → 1.20.9  subnet 172.26.0.0/16  vault_port 8201  ldap_port 1391  ldaps_port 1638
  #   3 → 1.19.9  subnet 172.27.0.0/16  vault_port 8202  ldap_port 1392  ldaps_port 1639
  # ---------------------------------------------------------------------------
  locals {
    subnet     = matrix.vault_version == "2.0.0" ? "172.24.0.0/16" : (matrix.vault_version == "1.21.5" ? "172.25.0.0/16" : (matrix.vault_version == "1.20.9" ? "172.26.0.0/16" : "172.27.0.0/16"))
    vault_port = matrix.vault_version == "2.0.0" ? 8199 : (matrix.vault_version == "1.21.5" ? 8200 : (matrix.vault_version == "1.20.9" ? 8201 : 8202))
    ldap_port  = matrix.vault_version == "2.0.0" ? 1389 : (matrix.vault_version == "1.21.5" ? 1390 : (matrix.vault_version == "1.20.9" ? 1391 : 1392))
    ldaps_port = matrix.vault_version == "2.0.0" ? 1636 : (matrix.vault_version == "1.21.5" ? 1637 : (matrix.vault_version == "1.20.9" ? 1638 : 1639))

    # Per-variant host directory for the staged candidate plugin binary.
    # Isolating by version prevents parallel matrix runs from clobbering each other.
    candidate_plugin_dir = abspath("${path.root}/.enos/plugins/${matrix.vault_version}")

    # Per-variant name suffix appended to all Docker resources (network, containers).
    variant_suffix = matrix.vault_version
  }

  # ---------------------------------------------------------------------------
  # Step 1 — Create network
  # ---------------------------------------------------------------------------

  # Create an isolated Docker bridge network for this scenario variant.
  # Each matrix cell (vault_version) gets its own network and non-overlapping
  # subnet so all variants can run concurrently on the same host without conflict.
  step "create_network" {
    description = "Create an isolated Docker bridge network for this scenario variant."
    module      = module.docker_network

    variables {
      network_name = "${var.docker_network_name}-${local.variant_suffix}"
      subnet       = local.subnet
    }
  }

  # ---------------------------------------------------------------------------
  # Step 2 — Deploy backend dependencies (LDAP + candidate plugin)
  # Both steps depend only on the network and are independent of each other,
  # so they can run in parallel.
  # ---------------------------------------------------------------------------

  # Deploy an OpenLDAP container into the Docker network.
  # Provides the real LDAP directory backend that the secrets engine connects to,
  # so both the released and candidate plugins exercise genuine LDAP operations.
  step "setup_ldap" {
    description = "Deploy an OpenLDAP container as the LDAP backend for the secrets engine."
    module      = module.ldap_container
    depends_on  = [step.create_network]

    variables {
      network_id          = step.create_network.network_id
      container_name      = "openldap-${local.variant_suffix}"
      ldap_admin_password = "adminpassword"
      ldap_port           = local.ldap_port
      ldaps_port          = local.ldaps_port
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
      plugin_dir = local.candidate_plugin_dir
    }
  }

  # ---------------------------------------------------------------------------
  # Step 3 — Deploy Vault cluster
  # ---------------------------------------------------------------------------

  # Deploy a Vault cluster into the Docker network.
  # Vault starts with its builtin released plugin — this is the baseline state
  # we test against in Phase 1 before upgrading to the candidate plugin.
  step "create_vault_cluster" {
    description = "Deploy a Vault cluster running the builtin released plugin."
    module      = module.vault_cluster
    depends_on  = [step.create_network, step.stage_candidate_plugin]

    variables {
      network_id    = step.create_network.network_id
      cluster_name  = "${var.vault_cluster_name}-${local.variant_suffix}"
      vault_version = matrix.vault_version
      vault_edition = "ent"
      # License is required for enterprise editions. Supply via var.vault_license_path.
      vault_license = var.vault_license_path != "" ? trimspace(file(abspath(var.vault_license_path))) : ""
      vault_port    = local.vault_port
      # Bind-mount the per-variant staging directory so the upgrade step can
      # inject the candidate plugin binary without restarting the container.
      plugin_dir = local.candidate_plugin_dir
    }
  }

  # ---------------------------------------------------------------------------
  # Phase 1 — Baseline
  # ---------------------------------------------------------------------------

  # Run the blackbox suite against the builtin released plugin.
  # Confirms the starting state is healthy and creates real plugin data
  # (mounts, roles, leases) that must survive the upgrade intact.
  # If this step fails, the upgrade step is never reached.
  step "run_baseline_tests" {
    description = "Run blackbox tests against the builtin released plugin to establish a healthy baseline."
    module      = module.run_test
    depends_on  = [step.setup_ldap, step.create_vault_cluster]

    variables {
      vault_address      = step.create_vault_cluster.vault_address
      vault_token        = step.create_vault_cluster.vault_token
      vault_cluster_name = "${var.vault_cluster_name}-${local.variant_suffix}"
      repo_root          = abspath("${path.root}/..")
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
  # Phase 2 — Upgrade
  # ---------------------------------------------------------------------------

  # Register the candidate plugin in the Vault plugin catalog:
  #   1. Compute the SHA256 of the binary already present in the container
  #      at /vault/plugins/ (placed there via the bind-mount).
  #   2. Call vault plugin register to update the catalog entry's sha256 field.
  #
  # No container restart is required. The bind-mount already exposes the new
  # binary on disk; Vault will load it the next time the mount is enabled.
  step "register_candidate_plugin" {
    description = "Register the candidate plugin binary in the Vault plugin catalog (updates SHA256; no container restart needed)."
    module      = module.upgrade_plugin
    depends_on  = [step.run_baseline_tests, step.stage_candidate_plugin]

    variables {
      vault_address        = step.create_vault_cluster.vault_address
      vault_token          = step.create_vault_cluster.vault_token
      vault_container_name = "${var.vault_cluster_name}-${local.variant_suffix}-node"
      plugin_dir           = step.stage_candidate_plugin.plugin_dir
      plugin_name          = step.stage_candidate_plugin.plugin_name
    }
  }

  # ---------------------------------------------------------------------------
  # Phase 2 — Verification
  # ---------------------------------------------------------------------------

  # Re-run the full blackbox suite against the same Vault cluster, now running
  # the candidate plugin. Tests verify that all data created in Phase 1 (mounts,
  # roles, leases) is still intact and functional, and that new operations
  # complete successfully. Any failure here is a regression introduced by the
  # candidate plugin.
  step "run_post_upgrade_tests" {
    description = "Run blackbox tests against the candidate plugin to detect regressions."
    module      = module.run_test
    depends_on  = [step.register_candidate_plugin]

    variables {
      vault_address      = step.create_vault_cluster.vault_address
      vault_token        = step.create_vault_cluster.vault_token
      vault_cluster_name = "${var.vault_cluster_name}-${local.variant_suffix}"
      repo_root          = abspath("${path.root}/..")
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
