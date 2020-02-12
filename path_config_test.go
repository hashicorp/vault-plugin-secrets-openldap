package openldap

import (
	"context"
	"fmt"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
)

func TestConfig(t *testing.T) {
	t.Run("happy path with defaults", func(t *testing.T) {
		b, storage := getBackend(false)

		data := map[string]interface{}{
			"binddn":      "tester",
			"bindpass":    "pa$$w0rd",
			"url":         "ldap://138.91.247.105",
			"certificate": validCertificate,
			"formatter":   "mycustom{{PASSWORD}}",
		}

		req := &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      configPath,
			Storage:   storage,
			Data:      data,
		}

		resp, err := b.HandleRequest(context.Background(), req)
		if err != nil || (resp != nil && resp.IsError()) {
			t.Fatalf("err:%s resp:%#v\n", err, resp)
		}

		req = &logical.Request{
			Operation: logical.ReadOperation,
			Path:      configPath,
			Storage:   storage,
			Data:      nil,
		}

		resp, err = b.HandleRequest(context.Background(), req)
		if err != nil || (resp != nil && resp.IsError()) {
			t.Fatalf("err:%s resp:%#v\n", err, resp)
		}

		if resp.Data["insecure_tls"].(bool) {
			t.Fatalf("expected insecure_tls to be false but received true")
		}

		if fmt.Sprintf("%s", resp.Data["url"]) != `ldap://138.91.247.105` {
			t.Fatalf("expected url to be \"ldap://138.91.247.105\" but received %q", fmt.Sprintf("%s", resp.Data["url"]))
		}

		if resp.Data["tls_min_version"].(string) != defaultTLSVersion {
			t.Fatalf("expected tlsminversion to be \""+defaultTLSVersion+"\" but received %q", resp.Data["tlsminversion"])
		}

		if resp.Data["tls_max_version"].(string) != defaultTLSVersion {
			t.Fatalf("expected tlsmaxversion to be \""+defaultTLSVersion+"\" but received %q", resp.Data["tlsmaxversion"])
		}

		if resp.Data["binddn"] != "tester" {
			t.Fatalf("expected username to be \"tester\" but received %q", resp.Data["binddn"])
		}

		if resp.Data["ttl"] != defaultTTLInt {
			t.Fatalf("received unexpected ttl of \"%d\"", resp.Data["ttl"])
		}

		if resp.Data["max_ttl"] != maxTTLInt {
			t.Fatalf("received unexpected max_ttl of \"%d\"", resp.Data["max_ttl"])
		}

		if resp.Data["length"] != defaultPasswordLength {
			t.Fatalf("received unexpected length of \"%d\"", resp.Data["length"])
		}

		if resp.Data["formatter"] != "mycustom{{PASSWORD}}" {
			t.Fatalf("received unexpected formatter of \"%d\"", resp.Data["formatter"])
		}
	})

	t.Run("minimum config", func(t *testing.T) {
		b, storage := getBackend(false)

		data := map[string]interface{}{
			"binddn":   "tester",
			"bindpass": "pa$$w0rd",
			"url":      "ldap://138.91.247.105",
		}

		req := &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      configPath,
			Storage:   storage,
			Data:      data,
		}

		resp, err := b.HandleRequest(context.Background(), req)
		if err != nil || (resp != nil && resp.IsError()) {
			t.Fatalf("err:%s resp:%#v\n", err, resp)
		}
	})

	t.Run("missing binddn", func(t *testing.T) {
		b, storage := getBackend(false)

		data := map[string]interface{}{
			"bindpass": "pa$$w0rd",
			"url":      "ldap://138.91.247.105",
		}

		req := &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      configPath,
			Storage:   storage,
			Data:      data,
		}

		_, err := b.HandleRequest(context.Background(), req)
		if err == nil {
			t.Fatal("should have got error, didn't")
		}
	})

	t.Run("missing bindpass", func(t *testing.T) {
		b, storage := getBackend(false)

		data := map[string]interface{}{
			"binddn": "tester",
			"url":    "ldap://138.91.247.105",
		}

		req := &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      configPath,
			Storage:   storage,
			Data:      data,
		}

		_, err := b.HandleRequest(context.Background(), req)
		if err == nil {
			t.Fatal("should have got error, didn't")
		}
	})

	t.Run("delete config", func(t *testing.T) {
		b, storage := getBackend(false)

		data := map[string]interface{}{
			"binddn":   "tester",
			"bindpass": "pa$$w0rd",
			"url":      "ldap://138.91.247.105",
		}

		req := &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      configPath,
			Storage:   storage,
			Data:      data,
		}

		resp, err := b.HandleRequest(context.Background(), req)
		if err != nil || (resp != nil && resp.IsError()) {
			t.Fatalf("err:%s resp:%#v\n", err, resp)
		}

		req = &logical.Request{
			Operation: logical.DeleteOperation,
			Path:      configPath,
			Storage:   storage,
			Data:      nil,
		}

		resp, err = b.HandleRequest(context.Background(), req)
		if err != nil || (resp != nil && resp.IsError()) {
			t.Fatalf("err:%s resp:%#v\n", err, resp)
		}
	})
}
