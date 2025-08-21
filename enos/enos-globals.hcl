// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

globals {
  archs                             = ["amd64", "arm64"]
  artifact_sources                  = ["local", "crt", "artifactory"]
  ldap_artifact_sources             = ["local", "releases", "artifactory"]
  ldap_config_root_rotation_methods = ["period", "schedule", "manual"]
  artifact_types                    = ["bundle", "package"]
  backends                          = ["raft"]
  backend_tag_key                   = "VaultStorage"
  build_tags = {
    "ce"               = ["ui"]
    "ent"              = ["ui", "enterprise", "ent"]
    "ent.fips1403"     = ["ui", "enterprise", "cgo", "hsm", "fips", "fips_140_3", "ent.fips1403"]
    "ent.hsm"          = ["ui", "enterprise", "cgo", "hsm", "venthsm"]
    "ent.hsm.fips1403" = ["ui", "enterprise", "cgo", "hsm", "fips", "fips_140_3", "ent.hsm.fips1403"]
  }
  config_modes = ["env", "file"]
  distros      = ["amzn", "ubuntu"]
  // Different distros may require different packages, or use different aliases for the same package
  distro_packages = {
    amzn = {
      "2"    = ["nc"]
      "2023" = ["nc"]
    }
    ubuntu = {
      "20.04" = ["netcat"]
      "22.04" = ["netcat"]
      "24.04" = ["netcat-openbsd"]
    }
  }
  distro_version = {
    amzn   = var.distro_version_amzn
    ubuntu = var.distro_version_ubuntu
  }
  editions            = ["ce", "ent", "ent.fips1403", "ent.hsm", "ent.hsm.fips1403"]
  enterprise_editions = [for e in global.editions : e if e != "ce"]
  ip_versions         = ["4", "6"]
  package_manager = {
    "amzn"   = "yum"
    "ubuntu" = "apt"
  }
  packages = ["jq"]
  // Ports that we'll open up for ingress in the security group for all target machines.
  // Port protocol maps to the IpProtocol schema: https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_IpPermission.html
  ports = {
    ssh : {
      description = "SSH"
      port        = 22
      protocol    = "tcp"
    },
    ldap : {
      description = "LDAP"
      port        = 389
      protocol    = "tcp"
    },
    vault_agent : {
      description = "Vault Agent"
      port        = 8100
      protocol    = "tcp"
    },
    vault_proxy : {
      description = "Vault Proxy"
      port        = 8101
      protocol    = "tcp"
    },
    vault_listener : {
      description = "Vault Addr listener"
      port        = 8200
      protocol    = "tcp"
    },
    vault_cluster : {
      description = "Vault Cluster listener"
      port        = 8201
      protocol    = "tcp"
    },
  }
  seals = ["awskms", "pkcs11", "shamir"]
  tags = merge({
    "Project Name" : var.project_name
    "Project" : "Enos",
    "Environment" : "ci"
  }, var.tags)
  vault_install_dir = {
    bundle  = "/opt/vault/bin"
    package = "/usr/bin"
  }
  vault_license_path  = abspath(var.vault_license_path != null ? var.vault_license_path : joinpath(path.root, "./support/vault.hclic"))
  vault_tag_key       = "vault-cluster"
  ldap_tag_key        = "ldap-server-cluster"
  vault_disable_mlock = false
}
