# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0

output "info" {
  value = <<EOF

You can SSH into the RACF system with one of the configured users:
    ssh USER0@${trimprefix(var.racf_ldap_url, "ldap://")}

EOF
}
