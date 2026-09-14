# Fix for Local Enos Execution

## Problem

The `plugin_upgrade` scenario fails locally with:
```
Error: Cannot connect to the Docker daemon at unix:///var/run/docker.sock. Is the docker daemon running?
```

## Root Cause

Docker Desktop on macOS uses a non-standard socket location:
- **Actual socket:** `/Users/ltcarbonell/.docker/run/docker.sock`
- **Expected by Terraform:** `unix:///var/run/docker.sock`

While macOS creates a symlink at `/var/run/docker.sock`, the Terraform Docker provider doesn't follow it properly.

## Solution

Set the `DOCKER_HOST` environment variable before running Enos:

```bash
export DOCKER_HOST=unix:///Users/ltcarbonell/.docker/run/docker.sock
cd enos
enos scenario run plugin_upgrade vault_version:1.21.5
```

Or run it inline:

```bash
cd enos
DOCKER_HOST=unix:///Users/ltcarbonell/.docker/run/docker.sock enos scenario run plugin_upgrade vault_version:1.21.5
```

## Permanent Fix

Add to your shell profile (`~/.zshrc` or `~/.bashrc`):

```bash
# Docker Desktop socket location for Terraform/Enos
export DOCKER_HOST=unix://${HOME}/.docker/run/docker.sock
```

Then reload your shell:
```bash
source ~/.zshrc  # or ~/.bashrc
```

## Why CI Works

The CI workflow explicitly sets `DOCKER_HOST` for Podman (line 82-83 in `.github/workflows/enos-tests.yaml`):

```yaml
USER_ID="$(id -u)"
echo "DOCKER_HOST=unix:///run/user/${USER_ID}/podman/podman.sock" >> "$GITHUB_ENV"
```

Your local environment needs the same explicit configuration for Docker Desktop.

## Verification

After setting `DOCKER_HOST`, verify it works:

```bash
echo $DOCKER_HOST
# Should output: unix:///Users/ltcarbonell/.docker/run/docker.sock

docker info
# Should show Docker info without errors

cd enos
enos scenario run plugin_upgrade vault_version:1.21.5
# Should now work
```
