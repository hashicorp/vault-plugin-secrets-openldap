// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package openldap

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/require"
)

// The library of service accounts that can be checked out
// is a discrete set of features. This test suite provides
// end-to-end tests of these interrelated endpoints.
func TestCheckOut(t *testing.T) {
	ctx := context.Background()
	b, s := getBackend(false)
	defer b.Cleanup(ctx)

	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      configPath,
		Storage:   s,
		Data: map[string]interface{}{
			"binddn":   "euclid",
			"password": "password",
			"url":      "ldap://ldap.forumsys.com:389",
			"userdn":   "cn=read-only-admin,dc=example,dc=com",
		},
	}
	resp, err := b.HandleRequest(ctx, req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err: %v, resp: %v", err, resp.Error())
	}

	setName := "test-set"
	ts := testSuite{
		b:               b,
		s:               s,
		name:            setName,
		svcAccountNames: getTestSvcAccountNames(setName, 2),
	}
	// Exercise all set endpoints.
	t.Run("write set", ts.WriteSet())
	t.Run("read set", ts.ReadSet())
	t.Run("read set status", ts.ReadSetStatus())
	t.Run("write set toggle off", ts.WriteSetToggleOff())
	t.Run("read set toggle off", ts.ReadSetToggleOff())
	t.Run("write conflicting set", ts.WriteSetWithConflictingServiceAccounts())
	t.Run("list sets", ts.ListSets([]string{ts.name}))
	t.Run("delete set", ts.DeleteSet())

	// Do some common updates on sets and ensure they work.
	t.Run("write set", ts.WriteSet())
	t.Run("add service account", ts.AddAnotherServiceAccount())
	t.Run("remove service account", ts.RemoveServiceAccount())

	t.Run("check initial status", ts.CheckInitialStatus())
	t.Run("check out account", ts.PerformCheckOut())
	t.Run("check updated status", ts.CheckUpdatedStatus())
	t.Run("normal check in", ts.NormalCheckIn())
	t.Run("return to initial status", ts.CheckInitialStatus())
	t.Run("check out again", ts.PerformCheckOut())
	t.Run("check updated status", ts.CheckUpdatedStatus())
	t.Run("force check in", ts.ForceCheckIn())
	t.Run("check all are available", ts.CheckInitialStatus())
}

func TestCheckOutHierarchicalPaths(t *testing.T) {
	ctx := context.Background()
	b, s := getBackend(false)
	defer b.Cleanup(ctx)

	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      configPath,
		Storage:   s,
		Data: map[string]interface{}{
			"binddn":   "euclid",
			"password": "password",
			"url":      "ldap://ldap.forumsys.com:389",
			"userdn":   "cn=read-only-admin,dc=example,dc=com",
		},
	}
	resp, err := b.HandleRequest(ctx, req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err: %v, resp: %v", err, resp.Error())
	}

	setNames := []string{"foo", "org/secure", "org/platform/dev", "org/platform/support"}

	var tSuiteForList testSuite
	for _, setName := range setNames {
		ts := testSuite{
			b:               b,
			s:               s,
			name:            setName,
			svcAccountNames: getTestSvcAccountNames(setName, 2),
		}
		// Exercise all set endpoints expect List Sets
		t.Run("write set", ts.WriteSet())
		t.Run("read set", ts.ReadSet())
		t.Run("read set status", ts.ReadSetStatus())
		t.Run("write set toggle off", ts.WriteSetToggleOff())
		t.Run("read set toggle off", ts.ReadSetToggleOff())
		t.Run("write conflicting set", ts.WriteSetWithConflictingServiceAccounts())
		t.Run("delete set", ts.DeleteSet())

		// Do some common updates on sets and ensure they work.
		t.Run("write set", ts.WriteSet())
		t.Run("add service account", ts.AddAnotherServiceAccount())
		t.Run("remove service account", ts.RemoveServiceAccount())

		t.Run("check initial status", ts.CheckInitialStatus())
		t.Run("check out account", ts.PerformCheckOut())
		t.Run("check updated status", ts.CheckUpdatedStatus())
		t.Run("normal check in", ts.NormalCheckIn())
		t.Run("return to initial status", ts.CheckInitialStatus())
		t.Run("check out again", ts.PerformCheckOut())
		t.Run("check updated status", ts.CheckUpdatedStatus())
		t.Run("force check in", ts.ForceCheckIn())
		t.Run("check all are available", ts.CheckInitialStatus())

		// capture test suite so we can perform a listing on all the created sets
		tSuiteForList = ts
	}

	tests := []struct {
		path             string
		expectedListResp []string
	}{
		{path: "org", expectedListResp: []string{"platform/", "secure"}},
		{path: "org/platform", expectedListResp: []string{"dev", "support"}},
	}
	for _, tt := range tests {
		// `LIST /library/:role_set`
		// will return direct sub-keys split on "/" for each level (split)
		t.Run("list sets hierarchy", tSuiteForList.ListSetsHierarchy(tt.path, tt.expectedListResp))
	}

	// `LIST /library`
	// will direct sub-keys split on "/" for the FIRST level (split) only
	t.Run("list library hierarchy", tSuiteForList.ListSets([]string{"foo", "org/"}))
}

// TestCheckOutRaces executes a whole bunch of calls at once and only looks for
// races. Responses are ignored because they'll vary depending on execution order.
func TestCheckOutRaces(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping check for races in the checkout system due to short flag")
	}

	ctx := context.Background()
	b, s := getBackend(false)
	defer b.Cleanup(ctx)

	// Get 100 goroutines ready to go.
	numParallel := 100
	start := make(chan bool, 1)
	end := make(chan bool, numParallel)
	for i := 0; i < numParallel; i++ {
		go func() {
			<-start
			b.HandleRequest(ctx, &logical.Request{
				Operation: logical.CreateOperation,
				Path:      libraryPrefix + "test-set",
				Storage:   s,
				Data: map[string]interface{}{
					"service_account_names":        []string{"tester1@example.com", "tester2@example.com"},
					"ttl":                          "10h",
					"max_ttl":                      "11h",
					"disable_check_in_enforcement": true,
				},
			})
			b.HandleRequest(ctx, &logical.Request{
				Operation: logical.UpdateOperation,
				Path:      libraryPrefix + "test-set",
				Storage:   s,
				Data: map[string]interface{}{
					"service_account_names": []string{"tester1@example.com", "tester2@example.com", "tester3@example.com"},
				},
			})
			b.HandleRequest(ctx, &logical.Request{
				Operation: logical.UpdateOperation,
				Path:      libraryPrefix + "test-set",
				Storage:   s,
				Data: map[string]interface{}{
					"service_account_names": []string{"tester1@example.com", "tester2@example.com"},
				},
			})
			b.HandleRequest(ctx, &logical.Request{
				Operation: logical.ReadOperation,
				Path:      libraryPrefix + "test-set",
				Storage:   s,
			})
			b.HandleRequest(ctx, &logical.Request{
				Operation: logical.UpdateOperation,
				Path:      libraryPrefix + "test-set",
				Storage:   s,
				Data: map[string]interface{}{
					"service_account_names":        []string{"tester1@example.com", "tester2@example.com"},
					"ttl":                          "10h",
					"disable_check_in_enforcement": false,
				},
			})
			b.HandleRequest(ctx, &logical.Request{
				Operation: logical.ReadOperation,
				Path:      libraryPrefix + "test-set",
				Storage:   s,
			})
			b.HandleRequest(ctx, &logical.Request{
				Operation: logical.ReadOperation,
				Path:      libraryPrefix + "test-set/status",
				Storage:   s,
			})
			b.HandleRequest(ctx, &logical.Request{
				Operation: logical.CreateOperation,
				Path:      libraryPrefix + "test-set2",
				Storage:   s,
				Data: map[string]interface{}{
					"service_account_names": "tester1@example.com",
				},
			})
			b.HandleRequest(ctx, &logical.Request{
				Operation: logical.ListOperation,
				Path:      libraryPrefix,
				Storage:   s,
			})
			b.HandleRequest(ctx, &logical.Request{
				Operation: logical.DeleteOperation,
				Path:      libraryPrefix + "test-set",
				Storage:   s,
			})
			b.HandleRequest(ctx, &logical.Request{
				Operation: logical.ReadOperation,
				Path:      libraryPrefix + "test-set/status",
				Storage:   s,
			})
			b.HandleRequest(ctx, &logical.Request{
				Operation: logical.ReadOperation,
				Path:      libraryPrefix + "test-set/check-out",
				Storage:   s,
			})
			b.HandleRequest(ctx, &logical.Request{
				Operation: logical.ReadOperation,
				Path:      libraryPrefix + "test-set/status",
				Storage:   s,
			})
			b.HandleRequest(ctx, &logical.Request{
				Operation: logical.ReadOperation,
				Path:      libraryPrefix + "test-set/check-in",
				Storage:   s,
			})
			b.HandleRequest(ctx, &logical.Request{
				Operation: logical.ReadOperation,
				Path:      libraryPrefix + "manage/test-set/check-in",
				Storage:   s,
			})
			end <- true
		}()
	}

	// Start them all at once.
	close(start)

	// Wait for them all to finish.
	timer := time.NewTimer(15 * time.Second)
	for i := 0; i < numParallel; i++ {
		select {
		case <-timer.C:
			t.Fatal("test took more than 15 seconds, may be deadlocked")
		case <-end:
			continue
		}
	}
}

type testSuite struct {
	b               logical.Backend
	s               logical.Storage
	name            string
	svcAccountNames []string
}

func (ts testSuite) WriteSet() func(t *testing.T) {
	return func(t *testing.T) {
		req := &logical.Request{
			Operation: logical.CreateOperation,
			Path:      libraryPrefix + ts.name,
			Storage:   ts.s,
			Data: map[string]interface{}{
				"service_account_names":        ts.svcAccountNames,
				"ttl":                          "10h",
				"max_ttl":                      "11h",
				"disable_check_in_enforcement": true,
			},
		}
		resp, err := ts.b.HandleRequest(context.Background(), req)
		if err != nil || (resp != nil && resp.IsError()) {
			t.Fatalf("err: %v, resp: %v", err, resp.Error())
		}
		if resp != nil {
			t.Fatalf("expected an empty response, got: %v", resp)
		}
	}
}

func (ts testSuite) AddAnotherServiceAccount() func(t *testing.T) {
	newSvcAccountSet := append(ts.svcAccountNames, "tester3@example.com")
	return func(t *testing.T) {
		req := &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      libraryPrefix + ts.name,
			Storage:   ts.s,
			Data: map[string]interface{}{
				"service_account_names": newSvcAccountSet,
			},
		}
		resp, err := ts.b.HandleRequest(context.Background(), req)
		if err != nil || (resp != nil && resp.IsError()) {
			t.Fatalf("err: %v, resp: %v", err, resp.Error())
		}
		if resp != nil {
			t.Fatalf("expected an empty response, got: %v", resp)
		}
	}
}

func (ts testSuite) RemoveServiceAccount() func(t *testing.T) {
	return func(t *testing.T) {
		req := &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      libraryPrefix + ts.name,
			Storage:   ts.s,
			Data: map[string]interface{}{
				"service_account_names": ts.svcAccountNames,
			},
		}
		resp, err := ts.b.HandleRequest(context.Background(), req)
		if err != nil || (resp != nil && resp.IsError()) {
			t.Fatalf("err: %v, resp: %v", err, resp.Error())
		}
		if resp != nil {
			t.Fatalf("expected an empty response, got: %v", resp)
		}
	}
}

func (ts testSuite) ReadSet() func(t *testing.T) {
	return func(t *testing.T) {
		req := &logical.Request{
			Operation: logical.ReadOperation,
			Path:      libraryPrefix + ts.name,
			Storage:   ts.s,
		}
		resp, err := ts.b.HandleRequest(context.Background(), req)
		if err != nil || (resp != nil && resp.IsError()) {
			t.Fatalf("err: %v, resp: %v", err, resp.Error())
		}
		if resp == nil {
			t.Fatal("expected a response")
		}
		serviceAccountNames := resp.Data["service_account_names"].([]string)
		if len(serviceAccountNames) != len(ts.svcAccountNames) {
			t.Fatalf("expected %d", len(ts.svcAccountNames))
		}
		disableCheckInEnforcement := resp.Data["disable_check_in_enforcement"].(bool)
		if !disableCheckInEnforcement {
			t.Fatal("check-in enforcement should be disabled")
		}
		ttl := resp.Data["ttl"].(int64)
		if ttl != 10*60*60 { // 10 hours
			t.Fatal(ttl)
		}
		maxTTL := resp.Data["max_ttl"].(int64)
		if maxTTL != 11*60*60 { // 11 hours
			t.Fatal(maxTTL)
		}
	}
}

func (ts testSuite) WriteSetToggleOff() func(t *testing.T) {
	return func(t *testing.T) {
		req := &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      libraryPrefix + ts.name,
			Storage:   ts.s,
			Data: map[string]interface{}{
				"service_account_names":        ts.svcAccountNames,
				"ttl":                          "10h",
				"disable_check_in_enforcement": false,
			},
		}
		resp, err := ts.b.HandleRequest(context.Background(), req)
		if err != nil || (resp != nil && resp.IsError()) {
			t.Fatalf("err: %v, resp: %v", err, resp.Error())
		}
		if resp != nil {
			t.Fatalf("expected an empty response, got: %v", resp)
		}
	}
}

func (ts testSuite) ReadSetToggleOff() func(t *testing.T) {
	return func(t *testing.T) {
		req := &logical.Request{
			Operation: logical.ReadOperation,
			Path:      libraryPrefix + ts.name,
			Storage:   ts.s,
		}
		resp, err := ts.b.HandleRequest(context.Background(), req)
		if err != nil || (resp != nil && resp.IsError()) {
			t.Fatalf("err: %v, resp: %v", err, resp.Error())
		}
		if resp == nil {
			t.Fatal("expected a response")
		}
		serviceAccountNames := resp.Data["service_account_names"].([]string)
		if len(serviceAccountNames) != len(ts.svcAccountNames) {
			t.Fatalf("expected %d", len(ts.svcAccountNames))
		}
		disableCheckInEnforcement := resp.Data["disable_check_in_enforcement"].(bool)
		if disableCheckInEnforcement {
			t.Fatal("check-in enforcement should be enabled")
		}
	}
}

func (ts testSuite) ReadSetStatus() func(t *testing.T) {
	return func(t *testing.T) {
		req := &logical.Request{
			Operation: logical.ReadOperation,
			Path:      libraryPrefix + ts.name + "/status",
			Storage:   ts.s,
		}
		resp, err := ts.b.HandleRequest(context.Background(), req)
		if err != nil || (resp != nil && resp.IsError()) {
			t.Fatalf("err: %v, resp: %v", err, resp.Error())
		}
		if resp == nil {
			t.Fatal("expected a response")
		}
		if len(resp.Data) != len(ts.svcAccountNames) {
			t.Fatalf("expected %d service accounts in this set", len(ts.svcAccountNames))
		}
		for i := 0; i < len(ts.svcAccountNames); i++ {
			n := ts.svcAccountNames[i]
			if resp.Data[n] == nil {
				t.Fatal("expected non-nil map")
			}
			testerStatus := resp.Data[n].(map[string]interface{})
			if !testerStatus["available"].(bool) {
				t.Fatal("should be available for checkout")
			}
		}
	}
}

func (ts testSuite) WriteSetWithConflictingServiceAccounts() func(t *testing.T) {
	existingSvcAcc := ts.svcAccountNames[0]
	return func(t *testing.T) {
		req := &logical.Request{
			Operation: logical.CreateOperation,
			Path:      libraryPrefix + "test-set2",
			Storage:   ts.s,
			Data: map[string]interface{}{
				"service_account_names": existingSvcAcc,
			},
		}
		resp, err := ts.b.HandleRequest(context.Background(), req)
		if err != nil {
			t.Fatal(err)
		}
		if resp == nil || !resp.IsError() {
			t.Fatal("expected err response because we're adding a service account managed by another set")
		}
	}
}

func (ts testSuite) ListSets(expectedListResp []string) func(t *testing.T) {
	return func(t *testing.T) {
		req := &logical.Request{
			Operation: logical.ListOperation,
			Path:      libraryPrefix,
			Storage:   ts.s,
		}
		resp, err := ts.b.HandleRequest(context.Background(), req)
		if err != nil || (resp != nil && resp.IsError()) {
			t.Fatalf("err: %v, resp: %v", err, resp.Error())
		}
		if resp == nil {
			t.Fatal("expected a response")
		}
		if resp.Data["keys"] == nil {
			t.Fatal("expected non-nil data")
		}
		listedKeys := resp.Data["keys"].([]string)
		require.Equal(t, expectedListResp, listedKeys)
	}
}

func (ts testSuite) ListSetsHierarchy(path string, expectedListResp []string) func(t *testing.T) {
	return func(t *testing.T) {
		req := &logical.Request{
			Operation: logical.ListOperation,
			Path:      libraryPrefix + path + "/",
			Storage:   ts.s,
		}
		resp, err := ts.b.HandleRequest(context.Background(), req)
		if err != nil || (resp != nil && resp.IsError()) {
			t.Fatalf("err: %v, resp: %v", err, resp.Error())
		}
		if resp == nil {
			t.Fatal("expected a response")
		}
		if resp.Data["keys"] == nil {
			t.Fatal("expected non-nil data")
		}
		listedKeys := resp.Data["keys"].([]string)
		require.Equal(t, expectedListResp, listedKeys)
	}
}

func (ts testSuite) DeleteSet() func(t *testing.T) {
	return func(t *testing.T) {
		req := &logical.Request{
			Operation: logical.DeleteOperation,
			Path:      libraryPrefix + ts.name,
			Storage:   ts.s,
		}
		resp, err := ts.b.HandleRequest(context.Background(), req)
		if err != nil || (resp != nil && resp.IsError()) {
			t.Fatalf("err: %v, resp: %v", err, resp.Error())
		}
		if resp != nil {
			t.Fatalf("expected an empty response, got: %v", resp)
		}
	}
}

func (ts testSuite) CheckInitialStatus() func(t *testing.T) {
	return func(t *testing.T) {
		req := &logical.Request{
			Operation: logical.ReadOperation,
			Path:      libraryPrefix + ts.name + "/status",
			Storage:   ts.s,
		}
		resp, err := ts.b.HandleRequest(context.Background(), req)
		if err != nil || (resp != nil && resp.IsError()) {
			t.Fatalf("err: %v, resp: %v", err, resp.Error())
		}
		if resp == nil {
			t.Fatal("expected a response")
		}
		for _, svcAcc := range ts.svcAccountNames {
			if resp.Data[svcAcc] == nil {
				t.Fatal("expected map to not be nil")
			}
			tester1CheckOut := resp.Data[svcAcc].(map[string]interface{})
			available := tester1CheckOut["available"].(bool)
			if !available {
				t.Fatalf("%s should be available", svcAcc)
			}
		}
	}
}

func (ts testSuite) PerformCheckOut() func(t *testing.T) {
	return func(t *testing.T) {
		req := &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      libraryPrefix + ts.name + "/check-out",
			Storage:   ts.s,
		}
		resp, err := ts.b.HandleRequest(context.Background(), req)
		if err != nil || (resp != nil && resp.IsError()) {
			t.Fatalf("err: %v, resp: %v", err, resp.Error())
		}
		if resp == nil {
			t.Fatal("expected a response")
		}
		if resp.Data == nil {
			t.Fatal("expected resp data to not be nil")
		}

		if resp.Data["service_account_name"] == nil {
			t.Fatal("expected string to be populated")
		}
		if resp.Data["service_account_name"].(string) == "" {
			t.Fatal("service account name should be populated")
		}
		if resp.Data["password"].(string) == "" {
			t.Fatal("password should be populated")
		}
		if !resp.Secret.Renewable {
			t.Fatal("lease should be renewable")
		}
		if resp.Secret.TTL != time.Hour*10 {
			t.Fatal("expected 10h TTL")
		}
		if resp.Secret.MaxTTL != time.Hour*11 {
			t.Fatal("expected 11h TTL")
		}
		if resp.Secret.InternalData["service_account_name"].(string) == "" {
			t.Fatal("internal service account name should not be empty")
		}
	}
}

func (ts testSuite) CheckUpdatedStatus() func(t *testing.T) {
	return func(t *testing.T) {
		req := &logical.Request{
			Operation: logical.ReadOperation,
			Path:      libraryPrefix + ts.name + "/status",
			Storage:   ts.s,
		}
		resp, err := ts.b.HandleRequest(context.Background(), req)
		if err != nil || (resp != nil && resp.IsError()) {
			t.Fatalf("err: %v, resp: %v", err, resp.Error())
		}
		if resp == nil {
			t.Fatal("expected a response")
		}
		if resp.Data == nil {
			t.Fatal("expected data to not be nil")
		}

		if resp.Data[ts.svcAccountNames[0]] == nil {
			t.Fatal("expected map to not be nil")
		}
		tester1CheckOut := resp.Data[ts.svcAccountNames[0]].(map[string]interface{})
		tester1Available := tester1CheckOut["available"].(bool)

		if resp.Data[ts.svcAccountNames[1]] == nil {
			t.Fatal("expected map to not be nil")
		}
		tester2CheckOut := resp.Data[ts.svcAccountNames[1]].(map[string]interface{})
		tester2Available := tester2CheckOut["available"].(bool)

		if tester1Available && tester2Available {
			t.Fatal("one of the testers should not be available")
		}
	}
}

func (ts testSuite) NormalCheckIn() func(t *testing.T) {
	return func(t *testing.T) {
		req := &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      libraryPrefix + ts.name + "/check-in",
			Storage:   ts.s,
		}
		resp, err := ts.b.HandleRequest(context.Background(), req)
		if err != nil || (resp != nil && resp.IsError()) {
			t.Fatalf("err: %v, resp: %v", err, resp.Error())
		}
		if resp == nil {
			t.Fatal("expected a response")
		}
		checkIns := resp.Data["check_ins"].([]string)
		if len(checkIns) != 1 {
			t.Fatal("expected 1 check-in")
		}
	}
}

func (ts testSuite) ForceCheckIn() func(t *testing.T) {
	return func(t *testing.T) {
		req := &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      libraryManagePrefix + ts.name + "/check-in",
			Storage:   ts.s,
		}
		resp, err := ts.b.HandleRequest(context.Background(), req)
		if err != nil || (resp != nil && resp.IsError()) {
			t.Fatalf("err: %v, resp: %v", err, resp.Error())
		}
		if resp == nil {
			t.Fatal("expected a response")
		}
		checkIns := resp.Data["check_ins"].([]string)
		if len(checkIns) != 1 {
			t.Fatal("expected 1 check-in")
		}
	}
}

func TestCheckOut_librarySet_Validate(t *testing.T) {
	tests := []struct {
		name    string
		set     *librarySet
		wantErr bool
	}{
		{
			name: "valid library set",
			set: &librarySet{
				ServiceAccountNames: []string{"name1"},
				TTL:                 time.Minute,
				MaxTTL:              2 * time.Minute,
			},
		},
		{
			name: "invalid library set with empty list of service account names",
			set: &librarySet{
				ServiceAccountNames: []string{},
				TTL:                 time.Minute,
				MaxTTL:              2 * time.Minute,
			},
			wantErr: true,
		},
		{
			name: "invalid library set with empty service account name",
			set: &librarySet{
				ServiceAccountNames: []string{""},
				TTL:                 time.Minute,
				MaxTTL:              2 * time.Minute,
			},
			wantErr: true,
		},
		{
			name: "invalid library set with max TTL less than TTL",
			set: &librarySet{
				ServiceAccountNames: []string{"name1", "name2"},
				TTL:                 2 * time.Minute,
				MaxTTL:              time.Minute,
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.set.Validate(); (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func getTestSvcAccountNames(name string, count int) []string {
	var s []string
	for i := 0; i < count; i++ {
		s = append(s, fmt.Sprintf("%s-tester-%d@example.com", name, i))
	}
	return s
}
