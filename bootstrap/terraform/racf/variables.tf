# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0

variable "racf_bind_username" {
  description = "The RACF bind distinguished name"
  type        = string
  default     = "RACFID=JMF,PROFILETYPE=USER,CN=RACFHC4"
}

variable "racf_user_dn" {
  description = "The RACF base distinguished name for managed users"
  type        = string
  default     = "PROFILETYPE=USER,CN=RACFHC4"
}

# set this with:
#   export TF_VAR_racf_bind_password=foobar
variable "racf_bind_password" {
  description = "The RACF bind password"
  type        = string
  sensitive   = true
}

# set this with:
#   export TF_VAR_racf_ldap_url=ldap://test.com
variable "racf_ldap_url" {
  description = "The LDAP server URL"
  type        = string
}

variable "racf_group" {
  description = "The user's primary or default group"
  type        = string
  default     = "RACFID=SVTGRP,PROFILETYPE=GROUP,CN=RACFHC4"
}

