// Copyright (c) HashiCorp, Inc.
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
}

func TestBasicSmoke(t *testing.T) {
	t.Log("vault-plugin-secrets-openldap blackbox smoke test")
}
