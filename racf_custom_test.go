package openldap

import (
	"math/rand"
	"strings"
	"testing"
)

func TestRACFCustomPassword(t *testing.T) {
	for i := 0; i < 10000; i++ {
		length := 4 + rand.Int63n(60)
		password, err := racfCustomPassword(int(length))

		if err != nil {
			t.Fatal(err)
		}

		if len(password) != int(length) {
			t.Fatalf("%s isn't length %d", password, length)
		}

		if !strings.ContainsAny(password, "abcdefghijklmnopqrstuvwxyz") {
			t.Fatalf("%s doesn't contain a lowercase character", password)
		}

		if !strings.ContainsAny(password, "ABCDEFGHIJKLMNOPQRSTUVWXYZ") {
			t.Fatalf("%s doesn't contain an uppercase character", password)
		}

		if !strings.ContainsAny(password, "0123456789") {
			t.Fatalf("%s doesn't contain a digit", password)
		}

		if !strings.ContainsAny(password, "@#$") {
			t.Fatalf("%s doesn't contain a symbol", password)
		}
	}
}
