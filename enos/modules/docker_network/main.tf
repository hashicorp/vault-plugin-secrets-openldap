terraform {
  required_providers {
    docker = {
      source  = "kreuzwerker/docker"
      version = "~> 3.0"
    }
  }
}

variable "network_name" {
  description = "Name of the Docker network"
  type        = string
}

variable "subnet" {
  description = "Subnet for the Docker network"
  type        = string
  default     = "172.25.0.0/16"
}

resource "docker_network" "main" {
  name = var.network_name
  driver = "bridge"
  
  ipam_config {
    subnet = var.subnet
  }
}

output "network_id" {
  description = "ID of the created Docker network"
  value       = docker_network.main.id
}

output "network_name" {
  description = "Name of the created Docker network"
  value       = docker_network.main.name
}
