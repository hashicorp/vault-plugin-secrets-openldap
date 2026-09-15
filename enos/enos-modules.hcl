module "docker_network" {
  source = "./modules/docker_network"
}

module "ldap_container" {
  source = "./modules/ldap_container"
}

module "vault_cluster" {
  source = "./modules/vault_cluster"
}

module "run_test" {
  source = "./modules/run_test"
}

module "stage_candidate_plugin" {
  source = "./modules/stage_candidate_plugin"
}

module "manage_plugin" {
  source = "./modules/manage_plugin"
}
