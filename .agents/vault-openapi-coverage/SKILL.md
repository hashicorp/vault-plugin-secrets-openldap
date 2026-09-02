---
name: vault-openapi-coverage
description: >
  Install once globally and run against any Vault repo to automatically fix
  straightforward OpenAPI coverage gaps under builtin/logical, iterating until
  the remaining gaps must be fixed elsewhere. Focuses on builtin logical
  backends such as aws, consul, database, nomad, pki, pkiext, rabbitmq, ssh,
  totp, and transit by reading gap files directly, locating the defining Go
  source, and applying minimal source edits before validation. Also supports
  recognizing other Vault repo layouts, such as flat plugin repos, so the skill
  can still identify where repo-local source lives. Use when the user asks to
  reduce gaps in no_operation_summary.txt, no_path_descriptions.txt, or
  no_response_schema.txt for builtin logical backends. Trigger phrases:
  "openapi coverage", "operation summary", "path description",
  "response schema", "no_operation_summary", "no_path_descriptions",
  "coverage gaps", "vault openapi", "gen_openapi", "fix gaps".
metadata:
  argument-hint: '[endpoint-or-plugin]'
---

# Vault OpenAPI Coverage Skill

> **OUTPUT CONTRACT — Read this before doing anything else.**
> All tool calls (file reads, grep, handler body reads) are silent internal work. Do not narrate steps, announce tool calls, or show intermediate results to the user. The first and only output is the post-edit compile confirmation and the `git diff` prompt.

---

## Quick Start

Follow these steps in order every time the skill is activated:

1. Detect repo layout: Layout 1 if `builtin/logical/` exists in the workspace; Layout 2 if source is flat at the repo root.
2. Read the workspace gap files: `no_operation_summary.txt`, `no_path_descriptions.txt`, `no_response_schema.txt`.
3. In targeted mode, filter gap lines to the given backend or endpoint path.
4. Grep the relevant source tree for `Pattern`, `HelpSynopsis`, `Summary`, and `Callback`.
5. Derive all field values from context; open handler bodies only for `Responses` gaps where the return shape is not obvious.
6. Apply all edits in one `apply_diff` batch per file — do not present individual items for review first.
7. Run `go build` + `go vet`; fix any failures before stopping.
8. Prompt the engineer to run `git diff` and open a PR.

---

## When to Use

Use this skill when:
- The user asks to fix gaps in the workspace `no_operation_summary.txt`, `no_path_descriptions.txt`, or `no_response_schema.txt`.
- The user says "openapi coverage", "fix the gaps", "fix coverage for `<backend>`", or "fix `<endpoint-path>`".

Do not use this skill when:
- The user asks to edit `scripts/openapi.json` directly — always refuse and redirect to Go source edits.
- The workspace is not a Vault project and has no OpenAPI gap files.
- The user is asking a conceptual question about OpenAPI — just answer it.

> **Tip:** When the **`vault-openapi` Bob mode** is active, activate this skill immediately — no
> separate invocation is needed.

---

## Installation

Install this skill once into your global Bob directory so it is available in every Vault repo:

```bash
npx skills add https://github.com/hashicorp/vault-tools/tree/main/teams/eco/ai/.agents/skills/vault-openapi-coverage
```

This copies the skill to `~/.bob/skills/vault-openapi-coverage/`. Bob picks it up automatically
in every workspace — no per-repo clone required.

---

## What this skill does

Fix OpenAPI coverage gaps under `builtin/logical/` by editing Go source, then iterate on the local gap set until the only remaining items require changes outside the current builtin logical backend source tree.

Fix three types of gaps in `scripts/openapi.json`, each tracked by a gap file:

| Gap file | Missing field | Source field to set |
|---|---|---|
| `no_path_descriptions.txt` | `paths["/foo"].description` | `framework.Path.HelpSynopsis` |
| `no_operation_summary.txt` | `paths["/foo"].post.summary` | `framework.PathOperation.Summary` |
| `no_response_schema.txt` | typed `200` response schema | `framework.PathOperation.Responses` with `Fields:` |

Each line in a gap file is one missing item. Run `go run parse_json.go` to regenerate all three files from the current spec.

> **Note on spreadsheets:** `openapi_path_gaps.xlsx` and `openapi_operation_gaps.xlsx` are optional
> reference tools for the engineer — use them to decide which plugin or path to target before
> starting Bob. Bob does **not** require them and reads the raw gap files directly.

---

## How the spec is kept up to date

**Edit Go source only** — do not patch any `openapi.json` directly. The spec is regenerated from
source by the repo-local generation workflow.

### Layout 1 — Vault core repo

> **Critical:** `scripts/gen_openapi.sh` runs whatever `vault` binary is on `$PATH`. It does **not**
> recompile from source. After source edits, the binary must be rebuilt before running the script —
> otherwise the spec is generated from the old code and gap counts remain unchanged.

1. Edit the Go source to set the missing field (`HelpSynopsis`, `Summary`, `Responses` with `Fields:`).
2. After all source edits are done, run the full validation sequence:

```bash
# Catch compile errors first (fast)
go build ./builtin/logical/...
go vet  ./builtin/logical/...

# Rebuild the vault binary (slow — 2-5 min)
go build -o "$(go env GOPATH)/bin/vault" .

# Regenerate the spec and gap files, then check counts
bash scripts/gen_openapi.sh && go run parse_json.go
wc -l no_operation_summary.txt no_path_descriptions.txt no_response_schema.txt
```

### Layout 2 — Individual plugin repo

Plugin repos have no `scripts/gen_openapi.sh` and no `vault` main package to rebuild.
The gap files were generated from a Vault core checkout after the plugin was embedded there.

1. Edit the Go source (`path_*.go`, `backend.go`) at the repo root.
2. Verify the plugin compiles:

```bash
go build ./...
go vet  ./...
```

Gap counts drop the next time the plugin is vendored into a Vault core build and that repo's
full validation sequence is run. If a local Vault core checkout is available:

```bash
# In the Vault core repo
go build -o "$(go env GOPATH)/bin/vault" .
bash scripts/gen_openapi.sh && go run parse_json.go
wc -l no_operation_summary.txt no_path_descriptions.txt no_response_schema.txt
```

---

## Source-to-spec field mapping

```
framework.Path.HelpSynopsis       →  OASPathItem.description          (omitempty — blank = gap)
framework.PathOperation.Summary   →  OASOperation.summary             (omitempty — blank = gap)
framework.PathOperation.Responses →  OASOperation.responses content   (no Fields: = gap)
```

`cleanString()` applies `TrimSpace` + collapse `\s+` before writing to the spec. A whitespace-only
`HelpSynopsis` becomes `""` → `omitempty` drops the key → recorded as a gap.

---

## Writing good values

**HelpSynopsis** (path description) — short phrase, no trailing period, describes the resource group:
> "Configure the LDAP secrets engine." / "Manage Kubernetes auth method roles." / "Generate a Consul token for a given role."

Derive from: `Pattern` URL segments → `OperationPrefix` → sibling paths in the same file → raw path string.

**Summary** (operation summary) — complete sentence, imperative verb, ends with period:
> GET single resource → "Return the …" · GET list → "List all …" · POST config → "Configure …"
> POST generate → "Generate …" · POST login → "Authenticate with …" · DELETE → "Delete …"

Derive from: `HelpSynopsis` on the Path → Pattern segments → handler name → raw path.

**Responses with typed fields** — read the handler body, collect **all** `resp.Data` keys including those assigned inside `if`/`switch` branches. A field that is only conditionally emitted must still appear in the schema — the spec describes every field the endpoint *can* return, not only the fields it *always* returns.

> **Important — input schema ≠ response schema:** The `Fields:` map at the top of a `framework.Path` describes **input parameters** (what the caller sends). The `Fields:` map inside a `Responses` block describes **output fields** (what the handler returns). These are different and should never be conflated. Response fields may include computed/derived fields not present in the input schema (e.g. `service_account_project`), and may use different types (e.g. `TypeSlice` instead of `TypeCommaStringSlice`, `TypeInt` instead of `TypeDurationSecond`).

When mapping Go types to `framework.TypeXxx`, read [`references/type-mapping.md`](references/type-mapping.md). Load that file now if you are about to write any `Responses` block.

---

## Response schema helpers

When a `Responses` `Fields:` block is repeated two or more times within the same file, extract it to a helper function. Read [`references/response-helpers.md`](references/response-helpers.md) for naming conventions, placement rules, and what not to extract.

---

## Scope modes

Choose a mode based on what the user provides:

### Full mode (default)
Triggered by: `fix the gaps`, `fix coverage`, `openapi coverage`

- **Layout 1:** fixes every gap in all three gap files that maps to `builtin/logical/`.
- **Layout 2:** fixes every gap in all three gap files — the entire repo is one backend.

### Targeted mode
Triggered by: `fix coverage for pki`, `fix gaps for transit`, `fix /database/roles`

Fixes only the gaps that match the given backend or endpoint path. Everything else is ignored.

**Matching rules — Layout 1:**
- Backend name (e.g. `aws`, `consul`, `database`, `nomad`, `pki`, `pkiext`, `rabbitmq`, `ssh`, `totp`, `transit`) — restrict work to `builtin/logical/<backend>/`.
- Endpoint path (e.g. `/database/roles`) — filter gap file lines that contain that path substring, then resolve only within the matching `builtin/logical/` backend.

**Matching rules — Layout 2:**
- Backend name matching is irrelevant — all source is at the repo root.
- Endpoint path (e.g. `/roles`) — filter gap file lines that contain that path substring, then restrict grepping to `path_*.go` and `backend.go` at the repo root.

---

## Workflow

### Phase 0 — Read the gap files and discover source

> **Silent.** Execute all reads and grep calls without producing any output. Do not summarise gap counts, list filenames, or narrate what you found.

Read the raw gap files to build the work list:

```
read_file: no_operation_summary.txt
read_file: no_path_descriptions.txt
read_file: no_response_schema.txt
```

In **targeted mode**, filter each file's lines to only those matching the given backend or
endpoint path. Only lines that still represent a missing item are worked on.

Then use the `grep` **tool** to locate `Pattern`, `HelpSynopsis`, `Summary`, and `Callback`.
The search path differs by layout:

```
# Layout 1 — full mode: grep across all builtin logical backends
grep tool: pattern="Pattern|HelpSynopsis|Summary:|Callback\b"
           path=builtin/logical/
           include=*.go  (exclude *_test.go)

# Layout 1 — targeted mode: scope to one backend
grep tool: pattern="Pattern|HelpSynopsis|Summary:|Callback\b"
           path=builtin/logical/transit/    # example

# Layout 2 — full or targeted mode: grep at the repo root
grep tool: pattern="Pattern|HelpSynopsis|Summary:|Callback\b"
           path=.                           # repo root
           include=*.go  (exclude *_test.go, focus on path_*.go and backend.go)
```

> **Layout 2 note:** Plugin repos have no `builtin/logical/` tree. All path definitions live in
> `path_*.go` and `backend.go` at the repo root. Do not attempt to grep `builtin/` — it does
> not exist. If the repo has no gap files either, ask the user where the gap list came from
> (typically a Vault core checkout) before proceeding.

The gap file contents plus the grep output give you:
- the full gap list (filtered to scope in targeted mode)
- every `Pattern`, `HelpSynopsis`, `Summary`, and handler name in the relevant files

That is enough to derive all three field values for every gap without reading any file body.

### Phase 1 — Read handler bodies only when needed

> **Silent.** Open handler bodies without announcing which files you are reading or what you found.

Open a handler body only if:
- the `Responses` gap requires typed fields **and** the handler name from the grep output doesn't
  make the return shape obvious, **or**
- a `HelpSynopsis` / `Summary` cannot be inferred from the `Pattern` + sibling paths alone.

When reading a handler body for a `Responses` gap, scan the **entire** handler function for every
assignment to `resp.Data` or the local `data` map — including keys inside `if`, `else`, `switch`,
and `case` blocks. Include every such key in the `Fields:` map regardless of whether it is
conditionally reachable. The schema documents what the endpoint *can* return, not only what it
*always* returns.

Use a single `read_file` with a tight line range covering just that handler. Never read an entire file.

**Layout 2:** handler bodies are in the same `path_*.go` files at the repo root — no path prefix needed.

### Phase 2 — Apply all edits in one batch

Derive values for **every** gap in scope (using Phases 0–1), then apply them all at once — one
`apply_diff` call per file, with all SEARCH/REPLACE blocks for that file combined.  Do not
present individual items for review before applying.

Do not touch any `openapi.json` directly.

After all edits are applied, confirm the code compiles cleanly:

**Layout 1 — Vault core repo:**

```bash
go build ./builtin/logical/...
go vet  ./builtin/logical/...
```

**Layout 2 — Individual plugin repo:**

```bash
go build ./...
go vet  ./...
```

**Optional — verify gap counts drop (Layout 1 only):**

If the engineer wants to confirm the spec reflects the changes before opening a PR, they can
rebuild the binary and regenerate the spec:

```bash
# Rebuild the vault binary (slow — 2-5 min)
go build -o "$(go env GOPATH)/bin/vault" .

# Regenerate the spec and gap files, then recount
bash scripts/gen_openapi.sh && go run parse_json.go
wc -l no_operation_summary.txt no_path_descriptions.txt no_response_schema.txt
```

This step is **not required** before opening a PR — the CI pipeline regenerates the spec from
the rebuilt binary.

After the compile check passes, prompt the engineer to review the diff and open a PR:

> All edits are applied.  Please run:
>
> ```bash
> git diff
> ```
>
> Review the changes, then open a PR when satisfied.

After the PR is approved and merged, **require** the engineer to update the spreadsheets:

> **Required after PR is merged:** update `openapi_path_gaps.xlsx` and
> `openapi_operation_gaps.xlsx` to reflect the fixed rows:
>
> 1. Change each fixed cell from `No` → `Yes`.
> 2. Update the "Total Gaps" count for each fixed row.
> 3. Update the matching plugin row in the "Plugin Summary" sheet.
> 4. Commit and push the updated spreadsheets to the main branch.

---

## Common pitfalls

| Symptom | Fix |
|---|---|
| Gap count doesn't drop after `gen_openapi.sh` | The binary in `$PATH` was not rebuilt — run `go build -o "$(go env GOPATH)/bin/vault" .` first, then rerun the script |
| `gen_openapi.sh` errors for azure, keymgmt, kmip, transform, etc. | Normal — these are enterprise-only or unlicensed plugins; skipped with `\|\| true` and do not affect other backends |
| Blank `HelpSynopsis` in source but spec shows no description | `cleanString` turns whitespace into `""` → `omitempty` drops it; use a single-line string with no leading/trailing newlines |
| Bare `200` still a gap after adding `Responses:` | Add `Fields:` — a `Responses` block with no `Fields` map has no `content` key in the spec |
| `duplicate field name HelpSynopsis` compile error | Field already exists — check before injecting |
| `PasswordlessMap()` fields unknown | `read_file` the actual `PasswordlessMap` function in ldaputil — don't guess |

---

## Where to find the source file

Use this table to locate the Go source for a given gap path before grepping.

| Builtin logical backend | Source location |
|---|---|
| `aws` | `builtin/logical/aws/` |
| `consul` | `builtin/logical/consul/` |
| `database` | `builtin/logical/database/` |
| `nomad` | `builtin/logical/nomad/` |
| `pki` | `builtin/logical/pki/` |
| `pkiext` | `builtin/logical/pkiext/` |
| `rabbitmq` | `builtin/logical/rabbitmq/` |
| `ssh` | `builtin/logical/ssh/` |
| `totp` | `builtin/logical/totp/` |
| `transit` | `builtin/logical/transit/` |

**Tip:** derive the backend from the first stable path segment after the mount placeholder and keep edits inside the matching `builtin/logical/<backend>/` directory.

---

## Examples

### Example 1 — `no_path_descriptions.txt` and `no_operation_summary.txt` gaps

**Before** (missing `HelpSynopsis` and `Summary` — both are gaps):

```go
{
    Pattern: "roles/" + framework.GenericNameRegex("name"),
    Operations: map[logical.Operation]framework.OperationHandler{
        logical.ReadOperation: &framework.PathOperation{
            Callback: b.pathRoleRead,
        },
        logical.DeleteOperation: &framework.PathOperation{
            Callback: b.pathRoleDelete,
        },
    },
}
```

**After** (fixed):

```go
{
    Pattern:      "roles/" + framework.GenericNameRegex("name"),
    HelpSynopsis: "Manage named roles.",
    Operations: map[logical.Operation]framework.OperationHandler{
        logical.ReadOperation: &framework.PathOperation{
            Summary:  "Return the named role configuration.",
            Callback: b.pathRoleRead,
        },
        logical.DeleteOperation: &framework.PathOperation{
            Summary:  "Delete the named role.",
            Callback: b.pathRoleDelete,
        },
    },
}
```

### Example 2 — `no_response_schema.txt` gap

The handler body contains:

```go
func (b *backend) pathRoleRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
    role, err := b.role(ctx, req.Storage, d.Get("name").(string))
    if err != nil || role == nil {
        return nil, err
    }
    return &logical.Response{
        Data: map[string]interface{}{
            "ttl":      int64(role.TTL.Seconds()),
            "max_ttl":  int64(role.MaxTTL.Seconds()),
            "policies": role.Policies,
            "renewable": role.Renewable,
        },
    }, nil
}
```

Type mapping: `int64(seconds)` → `TypeDurationSecond` for TTL fields; `[]string` → `TypeSlice`; `bool` → `TypeBool`.

**Before** (gap — no `Responses` block):

```go
logical.ReadOperation: &framework.PathOperation{
    Summary:  "Return the named role configuration.",
    Callback: b.pathRoleRead,
},
```

**After** (fixed):

```go
logical.ReadOperation: &framework.PathOperation{
    Summary:  "Return the named role configuration.",
    Callback: b.pathRoleRead,
    Responses: map[int][]framework.Response{
        http.StatusOK: {{
            Description: "OK",
            Fields: map[string]*framework.FieldSchema{
                "ttl":      {Type: framework.TypeDurationSecond, Description: "Token TTL in seconds."},
                "max_ttl":  {Type: framework.TypeDurationSecond, Description: "Maximum token TTL in seconds."},
                "policies": {Type: framework.TypeSlice,          Description: "List of token policies."},
                "renewable": {Type: framework.TypeBool,          Description: "Whether the token is renewable."},
            },
        }},
    },
},
```

Note the `http` import — add `"net/http"` to the file's import block if it is not already present.

> **Note:** The gap files (`no_operation_summary.txt`, `no_path_descriptions.txt`, `no_response_schema.txt`) live in the **workspace repo root** — they are not bundled with this skill. See `README.md` for the full repo file layout and validation sequence.
