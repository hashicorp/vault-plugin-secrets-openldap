// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

locals {
  hosts = { for idx in range(var.instance_count) : idx => {
    ipv6       = try(aws_instance.targets[idx].ipv6_addresses[0], "")
    public_ip  = aws_instance.targets[idx].public_ip
    private_ip = aws_instance.targets[idx].private_ip
    }
  }
}
