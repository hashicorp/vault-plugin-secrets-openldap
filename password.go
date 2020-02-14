package openldap

import (
	"fmt"
	"strings"
)

type passwordConf struct {
	Length    int    `json:"length"`
	Formatter string `json:"formatter"`
}

func (c *passwordConf) Map() map[string]interface{} {
	return map[string]interface{}{
		"length":    c.Length,
		"formatter": c.Formatter,
	}
}

func validatePwdSettings(formatter string, totalLength int) error {
	// Check for if there's no formatter.
	if formatter == "" {
		if totalLength < len(passwordComplexityPrefix)+minimumLengthOfComplexString {
			suggestedLength := minimumLengthOfComplexString + len(passwordComplexityPrefix)
			return fmt.Errorf("password length %d is less than the minimum required (%d)", totalLength, suggestedLength)
		}
		return nil
	}

	// Check for if there is a formatter.
	if lengthOfPassword(formatter, totalLength) < minimumLengthOfComplexString {
		return fmt.Errorf("password length %d is smaller than desired length %d",
			lengthOfPassword(formatter, totalLength),  minimumLengthOfComplexString)
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
