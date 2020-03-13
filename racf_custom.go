package openldap

import (
	"errors"
	"strings"

	"github.com/hashicorp/go-uuid"
	"github.com/hashicorp/vault/sdk/helper/base62"
)

const symbols = "@#$"
const lower = "abcdefghijklmnopqrstuvwxyz"
const upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
const digits = "0123456789"

// RACFCustomPassword generates passwords meeting the following requirements:
//
// At least one each of:
//   * upper case character
//   * lower case character
//   * number
//   * special character (@,#,$)
func racfCustomPassword(length int) (string, error) {
	if length > 255 {
		return "", errors.New("max password length exceeded")
	}

	// Retry until we meet requirements. This usually only takes a couple of tries.
	// In a 100M role test, the max number of retries was 14, so the 100 limit is very conservative.
	for tries := 0; tries < 100; tries++ {
		password, err := base62.Random(length)
		if err != nil {
			return "", err
		}

		randBytes, err := uuid.GenerateRandomBytes(2)
		if err != nil {
			return "", err
		}

		// Replace one of the characters with a random symbol. The slight bias in %
		// is noted but considered acceptable here.
		symbol := string(symbols[randBytes[0]%3])
		symbolPos := int(randBytes[1]) % length

		password = password[:symbolPos] + symbol + password[symbolPos+1:]

		if meetsRequirements(password, length) {
			return password, nil
		}
	}
	return "", errors.New("unable to generate password in 100 tries")
}

func meetsRequirements(s string, length int) bool {
	valid := true
	valid = len(s) == length
	valid = valid && strings.ContainsAny(s, lower)
	valid = valid && strings.ContainsAny(s, upper)
	valid = valid && strings.ContainsAny(s, digits)
	valid = valid && strings.ContainsAny(s, symbols)

	return valid
}
