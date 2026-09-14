# CI Integration Analysis for PR #238

## Current State

The `.github/workflows/enos-tests.yaml` workflow **already runs the `plugin_upgrade` scenario** that was added in PR #238.

### Workflow Configuration (Line 121)
```bash
enos scenario run plugin_upgrade vault_version:${{ matrix.vault_version }}
```

### Matrix Configuration
The workflow runs against 4 Vault versions in parallel:
- 2.0.0
- 1.21.5
- 1.20.9
- 1.19.9

## What's Already Working

✅ The `plugin_upgrade` scenario is configured to run in CI
✅ Matrix parallelization is set up correctly
✅ All required dependencies are installed (Podman, ldap-utils, Terraform, Enos)
✅ Vault license handling is configured
✅ Container logs are captured on failure

## Potential Issues

### 1. Scenario Name Mismatch?
The PR adds a scenario file `enos-scenario-plugin-upgrade.hcl` which defines `scenario "plugin_upgrade"`. The workflow runs `plugin_upgrade`. **This matches correctly.**

### 2. Missing Scenario?
If you want to run **both** scenarios (`ldap_poc` AND `plugin_upgrade`), the workflow needs to be updated to run both:

```yaml
- name: Run Enos scenarios
  run: |
    cd enos
    ENOS_VAR_vault_license_path="$(pwd)/support/vault.hclic"
    export ENOS_VAR_vault_license_path
    
    # Run both scenarios
    enos scenario run ldap_poc vault_version:${{ matrix.vault_version }}
    enos scenario run plugin_upgrade vault_version:${{ matrix.vault_version }}
```

### 3. Workflow Not Triggering?
The workflow triggers on:
- Pull requests to `main`, `release/**`, `hashigator/**`
- Pushes to `main`, `hashigator/**`
- Manual workflow dispatch

**Check:** Is your PR branch named with the `hashigator/` prefix? If not, the workflow won't run automatically.

## Recommendations

### If you want ONLY plugin_upgrade to run (current state):
**No changes needed.** The workflow already runs it.

### If you want BOTH scenarios to run:
Update the workflow to run both scenarios sequentially or add a second matrix dimension for scenario selection.

### If the workflow isn't triggering:
1. Ensure your branch name matches the trigger patterns
2. Check GitHub Actions tab to see if the workflow ran
3. Verify the workflow file is on the correct branch

## Quick Fix: Add Both Scenarios

If you want both scenarios to run, here's the minimal change needed:

```yaml
# Replace line 113-121 with:
- name: Run Enos scenarios
  run: |
    cd enos
    ENOS_VAR_vault_license_path="$(pwd)/support/vault.hclic"
    export ENOS_VAR_vault_license_path
    
    echo "=== Running ldap_poc scenario ==="
    enos scenario run ldap_poc vault_version:${{ matrix.vault_version }}
    
    echo "=== Running plugin_upgrade scenario ==="
    enos scenario run plugin_upgrade vault_version:${{ matrix.vault_version }}
```

This runs both scenarios for each Vault version in the matrix.
