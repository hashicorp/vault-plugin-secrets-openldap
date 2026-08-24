//go:build blackbox
// +build blackbox

// Copyright IBM Corp. 2025, 2026
// SPDX-License-Identifier: BUSL-1.1

package blackbox

import "testing"

type SystemTest struct {
	Name string
	Fn   func(t *testing.T)
}

var SystemTests = []SystemTest{
	{
		Name: "basic_smoke",
		Fn:   TestBasicSmoke,
	},
	{
		Name: "ldap_library_set_delete",
		Fn:   TestLDAP_LibrarySetDelete,
	},
	{
		Name: "ldap_library_set_read",
		Fn:   TestLDAP_LibrarySetRead,
	},
	{
		Name: "ldap_static_role_create",
		Fn:   TestLDAP_StaticRoleCreate,
	},
	{
		Name: "ldap_dynamic_role_audit_sensitive_data",
		Fn:   TestLDAPDynamicRoleAuditSensitiveData,
	},
	{
		Name: "ldap_dynamic_role_audit_trail",
		Fn:   TestLDAPDynamicRoleAuditTrail,
	},
	{
		Name: "ldap_dynamic_role_basic_operations",
		Fn:   TestLDAPDynamicRoleBasicOperations,
	},
	{
		Name: "ldap_dynamic_role_bulk_deletion",
		Fn:   TestLDAPDynamicRoleBulkDeletion,
	},
	{
		Name: "ldap_dynamic_role_deletion",
		Fn:   TestLDAPDynamicRoleDeletion,
	},
	{
		Name: "ldap_dynamic_role_deletion_with_active_credentials",
		Fn:   TestLDAPDynamicRoleDeletionWithActiveCredentials,
	},
	{
		Name: "ldap_dynamic_role_listing",
		Fn:   TestLDAPDynamicRoleListing,
	},
	{
		Name: "ldap_dynamic_role_rollback_on_creation_failure",
		Fn:   TestLDAPDynamicRoleRollbackOnCreationFailure,
	},
	{
		Name: "ldap_dynamic_role_rollback_on_deletion_failure",
		Fn:   TestLDAPDynamicRoleRollbackOnDeletionFailure,
	},
	{
		Name: "ldap_dynamic_role_validation",
		Fn:   TestLDAPDynamicRoleValidation,
	},
	{
		Name: "ldap_root_credential_rollback_workflows",
		Fn:   TestLDAPRootCredentialRollbackWorkflows,
	},
	{
		Name: "ldap_secrets_engine_comprehensive",
		Fn:   TestLDAPSecretsEngineComprehensive,
	},
}

func TestBasicSmoke(t *testing.T) {
	t.Log("vault-plugin-secrets-openldap blackbox smoke test")
}
