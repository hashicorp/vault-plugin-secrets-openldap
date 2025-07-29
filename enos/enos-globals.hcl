// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

globals {
  archs                 = ["amd64", "arm64"]
  artifact_sources      = ["local", "crt", "artifactory"]
  ldap_artifact_sources = ["local", "artifactory", "releases"]
  artifact_types        = ["bundle", "package"]
  backends              = ["raft"]
  backend_tag_key       = "VaultStorage"
  build_tags = {
    "ce"               = ["ui"]
    "ent"              = ["ui", "enterprise", "ent"]
    "ent.fips1403"     = ["ui", "enterprise", "cgo", "hsm", "fips", "fips_140_3", "ent.fips1403"]
    "ent.hsm"          = ["ui", "enterprise", "cgo", "hsm", "venthsm"]
    "ent.hsm.fips1403" = ["ui", "enterprise", "cgo", "hsm", "fips", "fips_140_3", "ent.hsm.fips1403"]
  }
  config_modes = ["env", "file"]
  distros      = ["amzn", "leap", "rhel", "sles", "ubuntu"]
  // Different distros may require different packages, or use different aliases for the same package
  distro_packages = {
    amzn = {
      "2"    = ["nc"]
      "2023" = ["nc"]
    }
    leap = {
      "15.6" = ["netcat", "openssl"]
    }
    rhel = {
      "8.10" = ["nc"]
      "9.5"  = ["nc"]
    }
    sles = {
      // When installing Vault RPM packages on a SLES AMI, the openssl package provided
      // isn't named "openssl, which rpm doesn't know how to handle. Therefore we add the
      // "correctly" named one in our package installation before installing Vault.
      "15.6" = ["netcat-openbsd", "openssl"]
    }
    ubuntu = {
      "20.04" = ["netcat"]
      "22.04" = ["netcat"]
      "24.04" = ["netcat-openbsd"]
    }
  }
  distro_version = {
    amzn   = var.distro_version_amzn
    leap   = var.distro_version_leap
    rhel   = var.distro_version_rhel
    sles   = var.distro_version_sles
    ubuntu = var.distro_version_ubuntu
  }
  editions            = ["ce", "ent", "ent.fips1403", "ent.hsm", "ent.hsm.fips1403"]
  enterprise_editions = [for e in global.editions : e if e != "ce"]
  ip_versions         = ["4", "6"]
  package_manager = {
    "amzn"   = "yum"
    "leap"   = "zypper"
    "rhel"   = "yum"
    "sles"   = "zypper"
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
