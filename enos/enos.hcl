terraform_cli "default" {
  plugin_cache_dir = abspath(joinpath(path.root, ".terraform/plugin-cache"))
}

terraform "default" {
  required_version = ">= 1.2.0"

  required_providers {
    docker = {
      source  = "kreuzwerker/docker"
      version = "~> 3.0"
    }
    enos = {
      source = "registry.terraform.io/hashicorp-forge/enos"
    }
  }
}
