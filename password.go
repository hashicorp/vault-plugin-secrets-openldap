package openldap

import (
	"fmt"
	"strings"
)

type passwordConf struct {
	TTL       int    `json:"ttl"`
	MaxTTL    int    `json:"max_ttl"`
	Length    int    `json:"length"`
	Formatter string `json:"formatter"`
}

func (c *passwordConf) Map() map[string]interface{} {
	return map[string]interface{}{
		"ttl":       c.TTL,
		"max_ttl":   c.MaxTTL,
		"length":    c.Length,
		"formatter": c.Formatter,
	}
}

func validatePwdSettings(formatter string, totalLength int) error {
	// Check for if there's no formatter.
	if formatter == "" {
		if totalLength < len(passwordComplexityPrefix)+minimumLengthOfComplexString {
			suggestedLength := minimumLengthOfComplexString + len(passwordComplexityPrefix)
			return fmt.Errorf(`it's not possible to generate a _secure_ password of length %d, 
please boost length to %d, though Vault recommends higher`, totalLength, suggestedLength)
		}
		return nil
	}

	// Check for if there is a formatter.
	if lengthOfPassword(formatter, totalLength) < minimumLengthOfComplexString {
		return fmt.Errorf(`since the desired length is %d, it isn't possible to generate a sufficiently complex password
- please increase desired length or remove characters from the formatter`, totalLength)
	}

	numPwdFields := strings.Count(formatter, pwdFieldTmpl)
	if numPwdFields == 0 {
		return fmt.Errorf("%s must contain password replacement field of %s", formatter, pwdFieldTmpl)
	}
	if numPwdFields > 1 {
		return fmt.Errorf("%s must contain one password replacement field of %s", formatter, pwdFieldTmpl)
	}
	return nil
}
