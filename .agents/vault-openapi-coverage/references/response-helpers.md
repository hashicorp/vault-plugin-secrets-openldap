# Response schema helpers

When a response `Fields:` block is repeated across multiple operations **within the same file** (e.g. both `ReadOperation` and `UpdateOperation` for the same path), extract it to a local helper function rather than repeating the inline map literal. This follows the same pattern already used for input field schemas (e.g. `fieldSchemaRoleSetServiceAccountKey()`).

## Naming convention

Name the helper after the specific path and concept it belongs to:

```go
// Good — scoped to this file's context
func responseFieldsRoleSetKey() map[string]*framework.FieldSchema { ... }
func responseFieldsStaticAccountAccessToken() map[string]*framework.FieldSchema { ... }
func responseFieldsImpersonatedAccountAccessToken() map[string]*framework.FieldSchema { ... }
```

## Do not share response helpers across files

Even if two files happen to return the same fields today, each path owns its response contract independently. Do not put a shared helper in a common file (e.g. `field_data_utils.go`). This couples unrelated paths and prevents them from evolving independently. Define the helper in the same file as its callers.

## Do not extract single-use blocks

If a response `Fields:` block appears only once in a file, leave it inline. Extract only when the same block is repeated two or more times within the same file.

## Placement

Define response schema helpers at the top of the file, before the first `func path...` definition, grouped with any existing input schema helpers.
