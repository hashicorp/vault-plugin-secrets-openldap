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
		if totalLength < len(PasswordComplexityPrefix)+minimumLengthOfComplexString {
			suggestedLength := minimumLengthOfComplexString + len(PasswordComplexityPrefix)
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

	numPwdFields := strings.Count(formatter, PwdFieldTmpl)
	if numPwdFields == 0 {
		return fmt.Errorf("%s must contain password replacement field of %s", formatter, PwdFieldTmpl)
	}
	if numPwdFields > 1 {
		return fmt.Errorf("%s must contain ONE password replacement field of %s", formatter, PwdFieldTmpl)
	}
	return nil
}
