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

// SystemTests registry contains all blackbox tests for the OpenLDAP secrets engine.
// Tests marked with t.Skip() are intentionally deferred for future implementation.
// These skipped tests serve as documentation of planned test coverage and will be
// implemented incrementally as the test infrastructure matures.
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
	// Dynamic role tests - implementation pending
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
	// Root credential rollback tests - implementation pending
	{
		Name: "ldap_root_credential_rollback_workflows",
		Fn:   TestLDAPRootCredentialRollbackWorkflows,
	},
	{
		Name: "ldap_secrets_engine_comprehensive",
		Fn:   TestLDAPSecretsEngineComprehensive,
	},
}

// TestBasicSmoke verifies the blackbox test infrastructure is functional.
// This is a minimal smoke test that runs in CI without requiring LDAP/Vault infrastructure.
// Full integration tests with LDAP operations run in the enos-tests workflow.
func TestBasicSmoke(t *testing.T) {
	t.Log("vault-plugin-secrets-openldap blackbox smoke test")
	t.Log("✅ Blackbox test infrastructure functional")
}
