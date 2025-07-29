// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

output "cluster_name" {
  value = local.cluster_name
}

output "hosts" {
  description = "The ec2 instance target hosts"
  value       = local.hosts
}

output "plugin_arch" {
  description = "machine architecture for GOARCH"
  value       = local.go_arch
}

output "plugin_os" {
  description = "machine os for GOOS"
  value       = local.go_os
}