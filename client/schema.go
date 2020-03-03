package client

import (
	"fmt"
	"github.com/hashicorp/vault/sdk/helper/strutil"
)

// SupportedSchema returns a slice of different OpenLDAP schemas supported
// by the plugin.  This is used to change the FieldRegistry when modifying
// user passwords.
func SupportedSchema() []string {
	return []string{"openldap", "rcaf"}
}

// ValidSchema checks if the configured schema is supported by the plugin.
func ValidSchema(schema string) bool {
	return strutil.StrListContains(SupportedSchema(), schema)
}

// GetSchemaFieldRegistry type switches field registries depending on the configured schema.
// For example, IBM RCAF has a custom OpenLDAP schema so the password is stored in a different
// attribute.
func GetSchemaFieldRegistry(schema string, newPassword string) (map[*Field][]string, error) {
	switch schema {
	case "openldap":
		fields := map[*Field][]string{FieldRegistry.UserPassword: {newPassword}}
		return fields, nil
	case "rcaf":
		fields := map[*Field][]string{
			FieldRegistry.RcafPassword:   {newPassword},
			FieldRegistry.RcafAttributes: {"noexpired"},
		}
		return fields, nil
	default:
		return nil, fmt.Errorf("configured schema %s not valid", schema)
	}
}
