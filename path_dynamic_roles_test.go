package openldap

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	paths "path"
	"reflect"
	"testing"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/mock"
)

func TestDynamicRoleCreateUpdate(t *testing.T) {
	roleName := "testrole"

	type testCase struct {
		createData *framework.FieldData

		putErr   error
		putTimes int

		expectErr bool
	}

	tests := map[string]testCase{
		"bad default_ttl": {
			createData: dynamicRoleFieldData(map[string]interface{}{
				"name":        roleName,
				"default_ttl": "foo",
			}),

			putErr:   nil,
			putTimes: 0,

			expectErr: true,
		},
		"bad max_ttl": {
			createData: dynamicRoleFieldData(map[string]interface{}{
				"name":    roleName,
				"max_ttl": "foo",
			}),

			putErr:   nil,
			putTimes: 0,

			expectErr: true,
		},
		"missing creation_ldif": {
			createData: dynamicRoleFieldData(map[string]interface{}{
				"name": roleName,
			}),

			putErr:   nil,
			putTimes: 0,

			expectErr: true,
		},
		"creation_ldif bad template syntax": {
			createData: dynamicRoleFieldData(map[string]interface{}{
				"name":          roleName,
				"creation_ldif": `dn: cn={{.Username,ou=users,dc=learn,dc=example`,
			}),

			putErr:   nil,
			putTimes: 0,

			expectErr: true,
		},
		"creation_ldif bad LDIF syntax": {
			createData: dynamicRoleFieldData(map[string]interface{}{
				"name":          roleName,
				"creation_ldif": `foo bar`,
			}),

			putErr:   nil,
			putTimes: 0,

			expectErr: true,
		},
		"multiple LDIF entries": {
			createData: dynamicRoleFieldData(map[string]interface{}{
				"name":          roleName,
				"creation_ldif": simpleLDAPTemplate + "\n\n" + simpleLDAPTemplate,
				// 				"creation_ldif": `dn: cn={{.Username}},ou=users,dc=hashicorp,dc=com
				// objectClass: person
				// objectClass: top
				// cn: learn
				// sn: learn
				// memberOf: cn=dev,ou=groups,dc=hashicorp,dc=com
				// userPassword: {{.Password}}
				//
				// dn: cn={{.Username}},ou=users,dc=hashicorp,dc=com
				// objectClass: person
				// objectClass: top
				// cn: learn
				// sn: learn
				// memberOf: cn=dev,ou=groups,dc=hashicorp,dc=com
				// userPassword: {{.Password}}`,
			}),

			putErr:   nil,
			putTimes: 0,

			expectErr: true,
		},
		"modify LDIF entry": {
			createData: dynamicRoleFieldData(map[string]interface{}{
				"name": roleName,
				"creation_ldif": `dn: cn=testuser,ou=users,dc=hashicorp,dc=com
changetype: modify
add: mail
mail: test@hashicorp.com
-`,
			}),

			putErr:   nil,
			putTimes: 0,

			expectErr: true,
		},
		"delete LDIF entry": {
			createData: dynamicRoleFieldData(map[string]interface{}{
				"name": roleName,
				"creation_ldif": `dn: cn=testuser,ou=users,dc=hashicorp,dc=com
changetype: delete`,
			}),

			putErr:   nil,
			putTimes: 0,

			expectErr: true,
		},
		"storage error": {
			createData: dynamicRoleFieldData(map[string]interface{}{
				"name":          roleName,
				"creation_ldif": simpleLDAPTemplate,
			}),

			putErr:   fmt.Errorf("test error"),
			putTimes: 1,

			expectErr: true,
		},
		"happy path": {
			createData: dynamicRoleFieldData(map[string]interface{}{
				"name":          roleName,
				"creation_ldif": simpleLDAPTemplate,
			}),

			putErr:   nil,
			putTimes: 1,

			expectErr: false,
		},
		"base64 encoded creation_ldif": {
			createData: dynamicRoleFieldData(map[string]interface{}{
				"name":          roleName,
				"creation_ldif": base64Encode(simpleLDAPTemplate),
			}),

			putErr:   nil,
			putTimes: 1,

			expectErr: false,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			client := new(mockLDAPClient)
			defer client.AssertExpectations(t) // No expectations

			b := Backend(client)

			storage := new(mockStorage)
			storage.On("Put", mock.Anything, mock.Anything).
				Return(test.putErr)
			defer storage.AssertNumberOfCalls(t, "Put", test.putTimes)

			req := &logical.Request{
				Storage: storage,
			}

			ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
			defer cancel()

			_, err := b.pathDynamicRoleCreateUpdate(ctx, req, test.createData)
			t.Logf("err: %s", err)
			if test.expectErr && err == nil {
				t.Fatalf("err expected, got nil")
			}
			if !test.expectErr && err != nil {
				t.Fatalf("no error expected, got: %s", err)
			}
		})
	}
}

func TestDynamicRoleRead(t *testing.T) {
	roleName := "testrole"

	type testCase struct {
		storageResp *logical.StorageEntry
		storageErr  error

		expectedResp *logical.Response
		expectErr    bool
	}

	tests := map[string]testCase{
		"storage failure": {
			storageResp:  nil,
			storageErr:   fmt.Errorf("test error"),
			expectedResp: nil,
			expectErr:    true,
		},
		"no role found": {
			storageResp:  nil,
			storageErr:   nil,
			expectedResp: nil,
			expectErr:    false,
		},
		"happy path": {
			storageResp: &logical.StorageEntry{
				Key: paths.Join(dynamicRolePath, roleName),
				Value: jsonEncode(t, dynamicRole{
					Name: roleName,
					CreationLDIF: `dn: cn={{.Username}},ou=users,dc=hashicorp,dc=com
objectClass: person
objectClass: top
cn: learn
sn: learn
memberOf: cn=dev,ou=groups,dc=hashicorp,dc=com
userPassword: {{.Password}}`,
					UsernameTemplate: "v-foo-{{.RoleName}}-{{rand 20}}-{{unix_seconds}}",
					DefaultTTL:       24 * time.Hour,
					MaxTTL:           5 * 24 * time.Hour,
				}),
			},
			storageErr: nil,
			expectedResp: &logical.Response{
				Data: map[string]interface{}{
					"creation_ldif": `dn: cn={{.Username}},ou=users,dc=hashicorp,dc=com
objectClass: person
objectClass: top
cn: learn
sn: learn
memberOf: cn=dev,ou=groups,dc=hashicorp,dc=com
userPassword: {{.Password}}`,
					"username_template": "v-foo-{{.RoleName}}-{{rand 20}}-{{unix_seconds}}",
					"default_ttl":       (24 * time.Hour).Seconds(),
					"max_ttl":           (5 * 24 * time.Hour).Seconds(),
				},
			},
			expectErr: false,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			client := new(mockLDAPClient)
			defer client.AssertExpectations(t) // No expectations

			b := Backend(client)

			storage := new(mockStorage)
			storage.On("Get", mock.Anything, paths.Join(dynamicRolePath, roleName)).
				Return(test.storageResp, test.storageErr)
			defer storage.AssertNumberOfCalls(t, "Get", 1)

			req := &logical.Request{
				Storage: storage,
			}
			data := dynamicRoleFieldData(map[string]interface{}{
				"name": roleName,
			})
			ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
			defer cancel()

			resp, err := b.pathDynamicRoleRead(ctx, req, data)
			if test.expectErr && err == nil {
				t.Fatalf("err expected, got nil")
			}
			if !test.expectErr && err != nil {
				t.Fatalf("no error expected, got: %s", err)
			}
			if !reflect.DeepEqual(resp, test.expectedResp) {
				t.Fatalf("Actual response: %#v\nExpected response: %#v", resp, test.expectedResp)
			}
		})
	}
}

func TestDynamicRoleList(t *testing.T) {
	type testCase struct {
		storageResp []string
		storageErr  error

		expectedResp *logical.Response
		expectErr    bool
	}

	tests := map[string]testCase{
		"storage failure": {
			storageResp:  nil,
			storageErr:   fmt.Errorf("test error"),
			expectedResp: nil,
			expectErr:    true,
		},
		"happy path": {
			storageResp: []string{
				"foo",
				"bar",
				"baz",
			},
			storageErr: nil,
			expectedResp: &logical.Response{
				Data: map[string]interface{}{
					"keys": []string{
						"foo",
						"bar",
						"baz",
					},
				},
			},
			expectErr: false,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			client := new(mockLDAPClient)
			defer client.AssertExpectations(t) // No expectations

			b := Backend(client)

			storage := new(mockStorage)
			storage.On("List", mock.Anything, dynamicRolePath).
				Return(test.storageResp, test.storageErr)
			defer storage.AssertNumberOfCalls(t, "List", 1)

			req := &logical.Request{
				Storage: storage,
			}
			data := dynamicRoleFieldData(map[string]interface{}{})
			ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
			defer cancel()

			resp, err := b.pathDynamicRoleList(ctx, req, data)
			if test.expectErr && err == nil {
				t.Fatalf("err expected, got nil")
			}
			if !test.expectErr && err != nil {
				t.Fatalf("no error expected, got: %s", err)
			}
			if !reflect.DeepEqual(resp, test.expectedResp) {
				t.Fatalf("Actual response: %#v\nExpected response: %#v", resp, test.expectedResp)
			}
		})
	}
}

func TestDynamicRoleExistenceCheck(t *testing.T) {
	roleName := "testrole"

	type testCase struct {
		storageResp *logical.StorageEntry
		storageErr  error

		expectedExists bool
		expectErr      bool
	}

	tests := map[string]testCase{
		"storage failure": {
			storageResp:    nil,
			storageErr:     fmt.Errorf("test error"),
			expectedExists: false,
			expectErr:      true,
		},
		"no role found": {
			storageResp:    nil,
			storageErr:     nil,
			expectedExists: false,
			expectErr:      false,
		},
		"happy path": {
			storageResp: &logical.StorageEntry{
				Key: paths.Join(dynamicRolePath, roleName),
				Value: jsonEncode(t, dynamicRole{
					Name: roleName,
					CreationLDIF: `dn: cn={{.Username}},ou=users,dc=hashicorp,dc=com
objectClass: person
objectClass: top
cn: learn
sn: learn
memberOf: cn=dev,ou=groups,dc=hashicorp,dc=com
userPassword: {{.Password}}`,
					UsernameTemplate: "v-foo-{{.RoleName}}-{{rand 20}}-{{unix_seconds}}",
					DefaultTTL:       24 * time.Hour,
					MaxTTL:           5 * 24 * time.Hour,
				}),
			},
			storageErr:     nil,
			expectedExists: true,
			expectErr:      false,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			client := new(mockLDAPClient)
			defer client.AssertExpectations(t) // No expectations

			b := Backend(client)

			storage := new(mockStorage)
			storage.On("Get", mock.Anything, paths.Join(dynamicRolePath, roleName)).
				Return(test.storageResp, test.storageErr)
			defer storage.AssertNumberOfCalls(t, "Get", 1)

			req := &logical.Request{
				Storage: storage,
			}
			data := dynamicRoleFieldData(map[string]interface{}{
				"name": roleName,
			})
			ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
			defer cancel()

			exists, err := b.pathDynamicRoleExistenceCheck(ctx, req, data)
			if test.expectErr && err == nil {
				t.Fatalf("err expected, got nil")
			}
			if !test.expectErr && err != nil {
				t.Fatalf("no error expected, got: %s", err)
			}

			if test.expectedExists && !exists {
				t.Fatalf("expected role to exist, did not")
			}
			if !test.expectedExists && exists {
				t.Fatalf("did not expect role to exist, but did")
			}
		})
	}
}

func TestConvertToDuration(t *testing.T) {
	type testCase struct {
		input map[string]interface{}
		keys  []string

		expectedOutput map[string]interface{}
		expectErr      bool
	}

	tests := map[string]testCase{
		"missing key": {
			input: map[string]interface{}{
				"foo": "1h",
			},
			keys: []string{
				"bar",
			},
			expectedOutput: map[string]interface{}{
				"foo": "1h",
			},
			expectErr: false,
		},
		"time.Duration": {
			input: map[string]interface{}{
				"foo": 1 * time.Hour,
			},
			keys: []string{
				"foo",
			},
			expectedOutput: map[string]interface{}{
				"foo": 1 * time.Hour,
			},
			expectErr: false,
		},
		"int": {
			input: map[string]interface{}{
				"foo": int(1 * time.Hour),
			},
			keys: []string{
				"foo",
			},
			expectedOutput: map[string]interface{}{
				"foo": 1 * time.Hour,
			},
			expectErr: false,
		},
		"int8": {
			input: map[string]interface{}{
				"foo": int8(123),
			},
			keys: []string{
				"foo",
			},
			expectedOutput: map[string]interface{}{
				"foo": time.Duration(123),
			},
			expectErr: false,
		},
		"int16": {
			input: map[string]interface{}{
				"foo": int16(123),
			},
			keys: []string{
				"foo",
			},
			expectedOutput: map[string]interface{}{
				"foo": time.Duration(123),
			},
			expectErr: false,
		},
		"int32": {
			input: map[string]interface{}{
				"foo": int32(123),
			},
			keys: []string{
				"foo",
			},
			expectedOutput: map[string]interface{}{
				"foo": time.Duration(123),
			},
			expectErr: false,
		},
		"int64": {
			input: map[string]interface{}{
				"foo": int64(123),
			},
			keys: []string{
				"foo",
			},
			expectedOutput: map[string]interface{}{
				"foo": time.Duration(123),
			},
			expectErr: false,
		},
		"string": {
			input: map[string]interface{}{
				"foo": "1h",
			},
			keys: []string{
				"foo",
			},
			expectedOutput: map[string]interface{}{
				"foo": 1 * time.Hour,
			},
			expectErr: false,
		},
		"bad string": {
			input: map[string]interface{}{
				"foo": "foo",
			},
			keys: []string{
				"foo",
			},
			expectedOutput: map[string]interface{}{
				"foo": "foo",
			},
			expectErr: true,
		},
		"unsupported type": {
			input: map[string]interface{}{
				"foo": struct {
					Dur string
				}{
					Dur: "1h",
				},
			},
			keys: []string{
				"foo",
			},
			expectedOutput: map[string]interface{}{
				"foo": struct {
					Dur string
				}{
					Dur: "1h",
				},
			},
			expectErr: true,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			data := test.input // The original map is being modified so let's make this an explicit variable
			err := convertToDuration(data, test.keys...)
			if test.expectErr && err == nil {
				t.Fatalf("err expected, got nil")
			}
			if !test.expectErr && err != nil {
				t.Fatalf("no error expected, got: %s", err)
			}

			if !reflect.DeepEqual(data, test.expectedOutput) {
				t.Fatalf("Actual: %#v\nExpected: %#v", data, test.expectedOutput)
			}
		})
	}
}

func dynamicRoleFieldData(data map[string]interface{}) *framework.FieldData {
	schema := map[string]*framework.FieldSchema{
		"name": {
			Type:        framework.TypeLowerCaseString,
			Description: "Name of the role",
			Required:    true,
		},
		"creation_ldif": {
			Type:        framework.TypeString,
			Description: "LDIF string used to create new entities within OpenLDAP. This LDIF can be templated.",
			Required:    true,
		},
		"username_template": {
			Type:        framework.TypeString,
			Description: "The template used to create a username",
		},
		"default_ttl": {
			Type:        framework.TypeDurationSecond,
			Description: "Default TTL for dynamic credentials",
		},
		"max_ttl": {
			Type:        framework.TypeDurationSecond,
			Description: "Max TTL a dynamic credential can be extended to",
		},
	}

	return &framework.FieldData{
		Raw:    data,
		Schema: schema,
	}
}

func base64Encode(str string) string {
	return base64.StdEncoding.EncodeToString([]byte(str))
}

func jsonEncode(t *testing.T, value interface{}) []byte {
	t.Helper()

	b, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("failed to marshal object: %s", err)
	}
	return b
}

const simpleLDAPTemplate = `dn: cn={{.Username}},ou=users,dc=hashicorp,dc=com
objectClass: person
objectClass: top
cn: learn
sn: learn
memberOf: cn=dev,ou=groups,dc=hashicorp,dc=com
userPassword: {{.Password}}`
