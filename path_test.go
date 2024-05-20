// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package openldap

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPathRegexList(t *testing.T) {
	tests := map[string]struct {
		pattern string
		input   string
		want    map[string]string
		wantErr bool
	}{
		"single-part": {
			pattern: "prefix" + optionalGenericNameWithForwardSlashListRegex("value"),
			input:   "prefix/foo",
			want:    map[string]string{"value": "foo"},
		},
		"single-part-trailing-slash": {
			pattern: "prefix" + optionalGenericNameWithForwardSlashListRegex("value"),
			input:   "prefix/foo/",
			want:    map[string]string{"value": "foo/"},
		},
		"single-part-with-suffix": {
			pattern: "prefix" + optionalGenericNameWithForwardSlashListRegex("value") + "/suffix",
			input:   "prefix/foo/suffix",
			want:    map[string]string{"value": "foo"},
		},
		"multi-part": {
			pattern: "prefix" + optionalGenericNameWithForwardSlashListRegex("value"),
			input:   "prefix/foo/bar",
			want:    map[string]string{"value": "foo/bar"},
		},
		"multi-part-trailing-slash": {
			pattern: "prefix" + optionalGenericNameWithForwardSlashListRegex("value"),
			input:   "prefix/foo/bar/",
			want:    map[string]string{"value": "foo/bar/"},
		},
		"multi-part-with-suffix": {
			pattern: "prefix" + optionalGenericNameWithForwardSlashListRegex("value") + "/suffix",
			input:   "prefix/foo/bar/suffix",
			want:    map[string]string{"value": "foo/bar"},
		},
		"multi-prefix-single-part": {
			pattern: "prefix/a" + optionalGenericNameWithForwardSlashListRegex("value"),
			input:   "prefix/a/foo",
			want:    map[string]string{"value": "foo"},
		},
		"multi-prefix-single-part-with-suffix": {
			pattern: "prefix/a" + optionalGenericNameWithForwardSlashListRegex("value") + "/suffix",
			input:   "prefix/a/foo/suffix",
			want:    map[string]string{"value": "foo"},
		},
		"multi-prefix-multi-part": {
			pattern: "prefix/a" + optionalGenericNameWithForwardSlashListRegex("value"),
			input:   "prefix/a/foo/bar",
			want:    map[string]string{"value": "foo/bar"},
		},
		"multi-prefix-multi-part-trailing-slash": {
			pattern: "prefix/a" + optionalGenericNameWithForwardSlashListRegex("value"),
			input:   "prefix/a/foo/bar/",
			want:    map[string]string{"value": "foo/bar/"},
		},
		"multi-prefix-multi-part-with-suffix": {
			pattern: "prefix/a" + optionalGenericNameWithForwardSlashListRegex("value") + "/suffix",
			input:   "prefix/a/foo/bar/suffix",
			want:    map[string]string{"value": "foo/bar"},
		},
		"multi-prefix-single-part-with-multi-suffix": {
			pattern: "prefix/a" + optionalGenericNameWithForwardSlashListRegex("value") + "/b/suffix",
			input:   "prefix/a/foo/b/suffix",
			want:    map[string]string{"value": "foo"},
		},
		"multi-prefix-multi-part-with-multi-suffix": {
			pattern: "prefix/a" + optionalGenericNameWithForwardSlashListRegex("value") + "/b/suffix",
			input:   "prefix/a/foo/bar/b/suffix",
			want:    map[string]string{"value": "foo/bar"},
		},
		"single-part-special-chars": {
			pattern: "prefix" + optionalGenericNameWithForwardSlashListRegex("value"),
			input:   "prefix/foo-.bar",
			want:    map[string]string{"value": "foo-.bar"},
		},
		"multi-part-special-chars": {
			pattern: "prefix" + optionalGenericNameWithForwardSlashListRegex("value"),
			input:   "prefix/foo-.bar/baz-.qux",
			want:    map[string]string{"value": "foo-.bar/baz-.qux"},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			re, err := regexp.Compile(tc.pattern)
			require.NoError(t, err)
			got, err := getCaptures(re, tc.input)
			if tc.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, tc.want, got)
			}
		})
	}
}

func TestPathRegex(t *testing.T) {
	tests := map[string]struct {
		pattern string
		input   string
		want    map[string]string
		wantErr bool
	}{
		"single-part": {
			pattern: "prefix" + genericNameWithForwardSlashRegex("value"),
			input:   "prefix/foo",
			want:    map[string]string{"value": "foo"},
		},
		"single-part-with-suffix": {
			pattern: "prefix" + genericNameWithForwardSlashRegex("value") + "/suffix",
			input:   "prefix/foo/suffix",
			want:    map[string]string{"value": "foo"},
		},
		"multi-part": {
			pattern: "prefix" + genericNameWithForwardSlashRegex("value"),
			input:   "prefix/foo/bar",
			want:    map[string]string{"value": "foo/bar"},
		},
		"multi-part-with-suffix": {
			pattern: "prefix" + genericNameWithForwardSlashRegex("value") + "/suffix",
			input:   "prefix/foo/bar/suffix",
			want:    map[string]string{"value": "foo/bar"},
		},
		"multi-prefix-single-part": {
			pattern: "prefix/a" + genericNameWithForwardSlashRegex("value"),
			input:   "prefix/a/foo",
			want:    map[string]string{"value": "foo"},
		},
		"multi-prefix-single-part-with-suffix": {
			pattern: "prefix/a" + genericNameWithForwardSlashRegex("value") + "/suffix",
			input:   "prefix/a/foo/suffix",
			want:    map[string]string{"value": "foo"},
		},
		"multi-prefix-multi-part": {
			pattern: "prefix/a" + genericNameWithForwardSlashRegex("value"),
			input:   "prefix/a/foo/bar",
			want:    map[string]string{"value": "foo/bar"},
		},
		"multi-prefix-multi-part-with-suffix": {
			pattern: "prefix/a" + genericNameWithForwardSlashRegex("value") + "/suffix",
			input:   "prefix/a/foo/bar/suffix",
			want:    map[string]string{"value": "foo/bar"},
		},
		"multi-prefix-single-part-with-multi-suffix": {
			pattern: "prefix/a" + genericNameWithForwardSlashRegex("value") + "/b/suffix",
			input:   "prefix/a/foo/b/suffix",
			want:    map[string]string{"value": "foo"},
		},
		"multi-prefix-multi-part-with-multi-suffix": {
			pattern: "prefix/a" + genericNameWithForwardSlashRegex("value") + "/b/suffix",
			input:   "prefix/a/foo/bar/b/suffix",
			want:    map[string]string{"value": "foo/bar"},
		},
		"single-part-special-chars": {
			pattern: "prefix" + genericNameWithForwardSlashRegex("value"),
			input:   "prefix/foo-.bar",
			want:    map[string]string{"value": "foo-.bar"},
		},
		"multi-part-special-chars": {
			pattern: "prefix" + genericNameWithForwardSlashRegex("value"),
			input:   "prefix/foo-.bar/baz-.qux",
			want:    map[string]string{"value": "foo-.bar/baz-.qux"},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			re, _ := regexp.Compile(tc.pattern)
			got, err := getCaptures(re, tc.input)
			if tc.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, tc.want, got)
			}
		})
	}
}

func getCaptures(re *regexp.Regexp, input string) (map[string]string, error) {
	matches := re.FindStringSubmatch(input)
	if matches == nil {
		return nil, fmt.Errorf("no submatch found for input %s", input)
	}
	// We have a match, determine the mapping of the captures and
	// store that for returning.
	var captures map[string]string
	if captureNames := re.SubexpNames(); len(captureNames) > 1 {
		captures = make(map[string]string, len(captureNames))
		for i, name := range captureNames {
			if name != "" {
				captures[name] = matches[i]
			}
		}
	}
	return captures, nil
}
