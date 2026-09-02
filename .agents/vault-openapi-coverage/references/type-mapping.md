# Response schema type mapping

Use this reference when constructing the `Fields:` map inside a `Responses` block.

## Go-type → framework.TypeXxx table

Use the **first matching row** when the handler value type is ambiguous:

| Handler value / Go type | `framework.TypeXxx` | Notes |
|---|---|---|
| `string`, UUID, token, PEM, base64, `[]byte` rendered as string | `TypeString` | Default for any opaque string value |
| `int`, `int32`, `int64`, `uint`, `uint64`, count | `TypeInt` | Use for all integer scalars |
| `float32`, `float64` | `TypeFloat` | Rare — only when the value is a decimal number |
| `bool` | `TypeBool` | |
| `[]string`, `[]interface{}`, any slice of scalars | `TypeSlice` | Prefer over `TypeCommaStringSlice` for response fields |
| `map[string]interface{}`, `map[string]string`, nested object | `TypeMap` | |
| `time.Duration` value written as seconds integer | `TypeDurationSecond` | e.g. TTL, max_ttl, period stored as `int64` seconds |
| `time.Time` rendered as RFC3339 string | `TypeString` | Dates/timestamps are strings in the spec |
| comma-separated string input | `TypeCommaStringSlice` | **Input fields only** — in response schemas use `TypeSlice` |
| KV `map[string][]string` or complex nested map | `TypeKVPairs` | Used by auth metadata, alias metadata |
| raw JSON blob / `json.RawMessage` | `TypeString` | Serialised JSON is a string scalar in the spec |

## Disambiguation rules

- **`TypeSlice` vs `TypeCommaStringSlice`:** `TypeCommaStringSlice` is an input-parsing convenience type — the framework splits comma-joined user input into a slice. In response schemas the value is already a `[]string`, so always use `TypeSlice`. Never use `TypeCommaStringSlice` in a `Responses` block.
- **`TypeDurationSecond` vs `TypeInt`:** use `TypeDurationSecond` when the field name includes `ttl`, `period`, `max_ttl`, `explicit_max_ttl`, or `lease_duration`, and the value is an integer count of seconds. Use `TypeInt` for generic integer counts (e.g. `num_uses`, `version`).
- **`TypeString` for timestamps:** `time.Time` values are serialised to RFC3339 strings. Fields like `created_time`, `expiration`, `last_renewal_time` are `TypeString`.
- **`TypeMap` for nested objects:** any `resp.Data` value that is a `map[string]interface{}` or a struct serialised to JSON — use `TypeMap`. Examples: `metadata`, `mfa_requirement`, `custom_metadata`, `connection_details`.
- **Unrecognised helper call (e.g. `PasswordlessMap()`):** read the function body with `read_file` — do not guess the field list or types.

## Response code determination

- Handler returns `nil, nil` or empty `resp` → `204`.
- Returns `resp.Data` with keys → `200` with `Fields:`.
- Auth login (`resp.Auth`) → `200` with the standard token fields listed below — **do not use a bare `200` for login responses**.

A bare `Responses: map[int][]framework.Response{200: {{Description: "OK"}}}` with **no `Fields:`** still counts as a gap — the spec needs `content.application/json.schema` to be present.

## PopulateTokenData fields

Callers of `PopulateTokenData` include these stable fields in their read/update responses:

| Field | Type |
|---|---|
| `token_bound_cidrs` | `TypeSlice` |
| `token_explicit_max_ttl` | `TypeInt` |
| `token_max_ttl` | `TypeInt` |
| `token_no_default_policy` | `TypeBool` |
| `token_period` | `TypeInt` |
| `token_policies` | `TypeSlice` |
| `token_type` | `TypeString` |
| `token_ttl` | `TypeInt` |
| `token_num_uses` | `TypeInt` |
| `alias_metadata` | `TypeMap` |

## PopulateTokenAuth fields

Auth login handlers that set `resp.Auth` include these stable fields in the token response:

| Field | Type |
|---|---|
| `client_token` | `TypeString` |
| `accessor` | `TypeString` |
| `policies` | `TypeSlice` |
| `token_policies` | `TypeSlice` |
| `metadata` | `TypeMap` |
| `lease_duration` | `TypeInt` |
| `renewable` | `TypeBool` |
| `entity_id` | `TypeString` |
| `token_type` | `TypeString` |
| `orphan` | `TypeBool` |
| `mfa_requirement` | `TypeMap` |
| `num_uses` | `TypeInt` |
