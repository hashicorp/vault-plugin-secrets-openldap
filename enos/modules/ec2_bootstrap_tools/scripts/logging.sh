#!/usr/bin/env bash

# choose a log‐file, defaulting to /var/log/my-plugin.log
LOG_FILE="${LOG_FILE:-/var/log/my-plugin.log}"
sudo mkdir -p "$(dirname "$LOG_FILE")"
sudo touch "$LOG_FILE"

# redirect all stdout/stderr into it (and still see it on console via tee)
exec > >(sudo tee -a "$LOG_FILE") 2>&1
