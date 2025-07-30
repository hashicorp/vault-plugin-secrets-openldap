// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

globals {
  description = {
    bootstrap_vault_cluster_targets = <<-EOF
      Installs bootstrap tools (e.g. shasum) on the Vault cluster targets.
    EOF

    build_vault = <<-EOF
      Determine which Vault artifact we want to use for the scenario. Depending on the
      'artifact_source' variant we'll either build Vault from the local branch, fetch a candidate
      build from Artifactory, or use a local artifact that was built in CI via CRT.
    EOF

    build_ldap = <<-EOF
      Determine which openldap plugin artifact we want to use for the scenario. Depending on the
      'artifact_source' variant we'll either build openldap secrets engine plugin from the local branch or
      fetch a candidate build from Artifactory.
    EOF

    configure_plugin = <<-EOF
      Configure the Vault plugin.
    EOF

    create_ldap_server = <<-EOF
      Sets up the docker container and ldap server.
    EOF

    create_ldap_server_target = <<-EOF
      Create the target machines that we'll setup the LDAP server onto.
    EOF

    create_seal_key = <<-EOF
      Create the necessary seal key infrastructure for Vaults auto-unseal functionality. Depending
      on the 'seal' variant this step will perform different actions. When using 'shamir' the step
      is a no-op as we won't require an external seal mechanism. When using 'pkcs11' this step will
      create a SoftHSM slot and associated token which can be distributed to all target nodes. When
      using 'awskms' a new AWSKMS key will be created. The necessary security groups and policies
      for Vault target nodes to access it the AWSKMS key are handled in the target modules.
    EOF

    create_vault_cluster = <<-EOF
      Create the the Vault cluster. In this module we'll install, configure, start, initialize and
      unseal all the nodes in the Vault. After initialization it also enables various audit engines.
    EOF

    create_vault_cluster_targets = <<-EOF
      Create the target machines that we'll install Vault onto. We also handle creating AWS instance
      profiles and security groups that allow for auto-discovery via the retry_join functionality in
      Consul. The security group firewall rules will automatically allow SSH access from the host
      external IP address of the machine executing Enos, in addition to all of the required ports
      for Vault to function and be accessible in the VPC.
      Note: Consul is not supported for plugin testing with enos.
    EOF

    create_vpc = <<-EOF
      Create an AWS VPC, internet gateway, default security group, and default subnet that allows
      egress traffic via the internet gateway.
    EOF

    ec2_info = <<-EOF
      Query various endpoints in AWS Ec2 to gather metadata we'll use later in our run when creating
      infrastructure for the Vault cluster. This metadata includes:
        - AMI IDs for different Linux distributions and platform architectures
        - Available Ec2 Regions
        - Availability Zones for our desired machine instance types
    EOF

    get_local_metadata = <<-EOF
      Performs several Vault quality verification that are dynamically modified based on the Vault
      binary version, commit SHA, build-date (commit SHA date), and edition metadata. When we're
      testing existing artifacts this expected metadata is passed in via Enos variables. When we're
      building a local by using the 'artifact_source:local' variant, this step executes and
      populates the expected metadata with that of our branch so that we don't have to update the
      Enos variables on each commit.
    EOF

    get_vault_cluster_ip_addresses = <<-EOF
      Map the public and private IP addresses of the Vault cluster nodes and segregate them by
      their leader status. This allows us to easily determine the public IP addresses of the leader
      and follower nodes.
    EOF

    read_vault_license = <<-EOF
      When deploying Vault Enterprise, ensure a Vault Enterprise license is present on disk and
      read its contents so that we can utilize it when configuring the Vault Enterprise cluster.
      Must have the 'edition' variant to be set to any Enterprise edition.
    EOF

    setup_plugin = <<-EOF
      Build, register, and enable the Vault plugin.
    EOF

    verify_raft_cluster_all_nodes_are_voters = <<-EOF
      When configured with a 'backend:raft' variant, verify that all nodes in the cluster are
      healthy and are voters.
    EOF

    verify_vault_unsealed = <<-EOF
      Verify that the Vault cluster has successfully unsealed.
    EOF

    verify_vault_version = <<-EOF
      Verify that the Vault CLI has the correct embedded version metadata and that the Vault Cluster
      verision history includes our expected version. The CLI metadata that is validated includes
      the Vault version, edition, build date, and any special prerelease metadata.
    EOF

    wait_for_cluster_to_have_leader = <<-EOF
      Wait for a leader election to occur before we proceed with any further quality verification.
    EOF

  }
}
