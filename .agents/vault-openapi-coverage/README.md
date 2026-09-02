# Vault OpenAPI Coverage

An AI skill for Bob that you install once globally and run against any Vault repo to fix
straightforward OpenAPI coverage gaps under `builtin/logical/`. It finds which Go source files
need editing, derives the correct values from context, and iterates until the remaining gaps
must be fixed outside the current builtin logical backend scope.

---

## Background

Instead of patching the JSON directly, you fix the **Go source** (`HelpSynopsis`, `Summary`,
`Responses` fields). The repo then picks up those changes the next time it regenerates the spec.

Three gap files track what is currently missing from the committed spec:

| Gap file | Missing field in spec | Go source field to set |
|---|---|---|
| `no_path_descriptions.txt` | `paths["/foo"].description` | `framework.Path.HelpSynopsis` |
| `no_operation_summary.txt` | `paths["/foo"].post.summary` | `framework.PathOperation.Summary` |
| `no_response_schema.txt` | typed `200` response schema | `framework.PathOperation.Responses` with `Fields:` |

`parse_json.go` reads `scripts/openapi.json` and regenerates all three gap files on demand.

> **Important:** `scripts/gen_openapi.sh` starts a `vault` binary from `$PATH` — it does **not**
> recompile from source. After editing Go source, you must rebuild the binary before running the
> script or gap counts will not change. See [Testing & Validation](#testing--validation) below.

### Supported Vault repo layouts

The primary workflow still targets [`builtin/logical/`](vault-enterprise/builtin/logical), but the skill should first recognize which Vault repo layout it is running in before searching for source files.

- **Vault core layout** — repo contains [`builtin/logical/`](vault-enterprise/builtin/logical), gap files like [`no_operation_summary.txt`](vault-enterprise/no_operation_summary.txt), and often [`parse_json.go`](vault-enterprise/parse_json.go).
- **Individual plugin layout** — repo keeps backend source at the root, like [`backend.go`](Plugin_Directories/vault-plugin-secrets-kubernetes-main/backend.go) and [`path_roles.go`](Plugin_Directories/vault-plugin-secrets-kubernetes-main/path_roles.go), with no [`builtin/logical/`](vault-enterprise/builtin/logical) tree.
- **Mixed repo-local tooling** — repo may have [`scripts/`](vault-enterprise/scripts) or other generation helpers, but the skill still edits only Go source that exists in the current repository.

If the repo is not a Vault core layout, adapt source discovery to the repo's actual file layout instead of assuming [`builtin/logical/`](vault-enterprise/builtin/logical).

---

## What the skill does

When you describe a coverage problem, Bob will:

1. Read the raw gap files (`no_operation_summary.txt`, `no_path_descriptions.txt`,
   `no_response_schema.txt`) as the authoritative work list.
2. For Vault core layouts, limit edits to `builtin/logical/aws/`, `consul/`, `database/`,
   `nomad/`, `pki/`, `pkiext/`, `rabbitmq/`, `ssh/`, `totp/`, and `transit/`.
3. First recognize the current repo layout so source discovery can adapt when the repo does
   not use the standard `builtin/logical/` tree.
4. Grep the relevant backend directories in a single pass to find every `Pattern`,
   `HelpSynopsis`, `Summary`, and handler name needed.
5. Derive the correct field values from context (no unnecessary file reads).
6. **Apply all edits in one batch** — one `apply_diff` call per file, all changes combined.
7. Run compile + vet immediately; fix any failures before stopping.
8. **Prompt the engineer to review `git diff`** before opening a PR.
9. Provide the full validation sequence (binary rebuild + spec regeneration + gap recount)
   for the engineer to run after the diff review.

It never patches `scripts/openapi.json` directly.

> **Spreadsheets are optional for Bob** — Bob does not read or require them to apply fixes. However, updating `openapi_path_gaps.xlsx` and `openapi_operation_gaps.xlsx` after a PR is merged is **required** — they are the ground truth for tracking overall gap progress across all plugins. See [Step 6](#step-6--update-the-spreadsheets-required) in the validation sequence.

---

## Installation

Install the skill once into your global Bob directory so it is available in every project:

```bash
npx skills add https://github.com/hashicorp/vault-tools/tree/main/teams/eco/ai/.agents/skills/vault-openapi-coverage
```

This copies the skill into `~/.bob/skills/vault-openapi-coverage/`. Bob picks it up
automatically in every workspace — no per-repo clone required.

---

## How to use it

Open any Vault repo in your editor, then use the spreadsheets (`openapi_path_gaps.xlsx`,
`openapi_operation_gaps.xlsx`) to identify which plugin or path has gaps and tell Bob what to
fix. If the spreadsheets are not present, run `go run generate_report.go` to regenerate them —
but this is for your reference only; Bob does not require them.

Talk to Bob naturally. Example phrases that activate the skill:

| Intent | Example |
|---|---|
| Fix builtin logical coverage | `fix the gaps` · `fix coverage` · `openapi coverage` |
| Fix one backend | `fix coverage for pki` · `fix gaps for transit` |
| Fix one endpoint | `fix /database/roles` · `fix /transit/keys` |

You can also invoke it directly as a slash command:

```
/vault-openapi-coverage [backend-or-endpoint]
```

---

## File layout

The skill should account for multiple Vault repo layouts before it starts source discovery.

The skill itself lives in your global Bob directory — the Vault repo trees no longer contain it.

### Layout 1 — Vault core repo

```
~/.bob/skills/vault-openapi-coverage/
    ├── SKILL.md                    # Full skill reference (instructions Bob follows)
    ├── README.md                   # This file
    └── references/
        ├── type-mapping.md         # Go-type → framework.TypeXxx table for Responses blocks
        └── response-helpers.md     # Naming, placement, and extraction rules for response helper functions

<vault-core-repo-root>/
├── parse_json.go                   # Reads openapi.json and writes the three gap files
├── generate_report.go              # Generates openapi_coverage_gaps.xlsx from the gap files
├── no_operation_summary.txt        # Missing Summary fields
├── no_path_descriptions.txt        # Missing HelpSynopsis fields
├── no_response_schema.txt          # Missing typed 200 responses
├── openapi_coverage_gaps.xlsx      # Prioritised gap report — ground truth for fix order
├── builtin/
│   └── logical/
│       ├── aws/
│       ├── consul/
│       ├── database/
│       ├── nomad/
│       ├── pki/
│       ├── pkiext/
│       ├── rabbitmq/
│       ├── ssh/
│       ├── totp/
│       └── transit/
├── scripts/
│   ├── gen_openapi.sh              # Repo-local OpenAPI generation flow
│   └── openapi.json                # Committed spec — source of truth for gap files
```

### Layout 2 — Individual plugin repo

```
~/.bob/skills/vault-openapi-coverage/
    ├── SKILL.md
    └── README.md

<plugin-repo-root>/
├── backend.go                      # Backend entrypoint
├── path_check.go                   # Path definitions at repo root
├── path_config.go
├── path_creds.go
├── path_roles.go
├── go.mod
├── scripts/                        # Optional repo-local tooling
```

For non-core layouts, keep the same OpenAPI field-mapping rules, but discover source files from the repo's actual structure instead of assuming `builtin/logical/`.

---

## How Bob applies changes

Bob derives all values for every gap in scope, applies all edits in one batch (one
`apply_diff` per file), then immediately runs compile + vet. No per-item approval prompt is
shown before edits are applied.

After the batch is applied and compiles cleanly, Bob shows:

```
All N edits applied. Please review the diff before opening a PR:

  git diff

Let me know if anything looks wrong and I will correct it.
```

The engineer reviews the diff, requests corrections if needed, then runs the full validation
sequence and opens a PR.

### Requesting corrections after the fact

If the diff shows something wrong, tell Bob what to fix (e.g. "the summary for `/pki/tidy`
should say X not Y") and it will apply a targeted correction.

---

## Reflecting plugin repo edits in the spec

When you edit OpenAPI fields in an **individual plugin repo** (e.g. `vault-plugin-auth-cf`,
`vault-plugin-secrets-gcp`), those changes live outside the Vault core repo. The
`scripts/gen_openapi.sh` script starts a Vault binary that embeds plugins through the module
graph, so your local edits must be wired into that graph before the spec can reflect them.

### Step 1 — Add `replace` directives to `go.mod`

Open `go.mod` in the Vault core repo and add a `replace` directive for each locally edited
plugin near the other `replace` entries (before the `require` block):

```
// Local plugin repos — point at edited source to regenerate OpenAPI spec
replace github.com/hashicorp/<plugin-module-name> => /path/to/local/clone
```

The module path on the left must match the `module` line in the plugin's own `go.mod` exactly.
Only add a directive for repos you have actually edited.

### Step 2 — Tidy the module graph

```bash
go mod tidy
```

### Step 3 — Verify the plugin compiles against the core repo

```bash
go build github.com/hashicorp/<plugin-module-name>
# If the plugin source is in a subdirectory (e.g. plugin/), build that package path:
go build github.com/hashicorp/<plugin-module-name>/plugin
```

Both should produce no output.

### Step 4 — Rebuild the vault binary and regenerate the spec

Continue with the standard validation sequence from [Step 2](#step-2--rebuild-the-vault-binary)
below. The rebuilt binary embeds your local plugin source, and `gen_openapi.sh` produces a spec
that reflects your edits.

### Reverting after the PR is merged

Once your plugin changes are released and the Vault core `go.mod` is bumped to the new version,
remove the `replace` directives and run `go mod tidy` again to restore the published dependency.
**Do not commit the `replace` directives** — they are local-only scaffolding for spec
regeneration.

---

## Testing & Validation

After Bob applies source edits, follow these steps in order.
**Skipping step 2 is the most common reason gap counts do not drop.**

### Step 1 — Verify the source compiles

```bash
go build ./builtin/logical/aws/...   # replace aws with the edited backend
go vet  ./builtin/logical/aws/...
```

Both should produce no output.

### Step 2 — Rebuild the vault binary

`scripts/gen_openapi.sh` runs whatever `vault` binary is on `$PATH`. It does **not** recompile
from source. You must rebuild the binary after editing Go source, otherwise the script starts
a server from the old code and the spec — and the gap files — remain unchanged.

```bash
# Replaces the binary in $GOPATH/bin (typically ~/go/bin/vault)
go build -o "$(go env GOPATH)/bin/vault" .
```

This step takes 2–5 minutes on a typical laptop. Wait for it to complete before continuing.

### Step 3 — Regenerate the OpenAPI spec

```bash
bash scripts/gen_openapi.sh
```

This starts a dev-mode Vault server using the newly built binary, mounts all builtin plugins,
calls `/v1/sys/internal/specs/openapi`, and writes `scripts/openapi.json`.
A few `Error enabling` lines for enterprise-only or unlicensed plugins are normal and expected.

### Step 4 — Regenerate the gap files

```bash
go run parse_json.go
```

This reads `scripts/openapi.json` and rewrites all three gap files.

### Step 5 — Confirm gap counts dropped

```bash
wc -l no_operation_summary.txt no_path_descriptions.txt no_response_schema.txt
```

Lines that were in the gap files before the edit should now be gone. Empty files (1 blank line
each, reported as `1` by `wc -l`) means all gaps for that file are resolved.

### Quick one-liner (steps 3–5 combined)

```bash
bash scripts/gen_openapi.sh && go run parse_json.go && \
  wc -l no_operation_summary.txt no_path_descriptions.txt no_response_schema.txt
```

### Step 6 — Update the spreadsheets (**required**)

After the PR is merged, update the spreadsheets to reflect the fixed rows:

1. Open `openapi_path_gaps.xlsx` and `openapi_operation_gaps.xlsx`.
2. Change each fixed cell from `No` → `Yes`.
3. Update the "Total Gaps" count for each fixed row.
4. Update the matching plugin row in the "Plugin Summary" sheet.
5. Commit and push the updated spreadsheets to the main branch.

Do not skip this step — the spreadsheets are the ground truth for tracking overall gap progress across all plugins.

### Optional — run the backend unit tests

```bash
go test ./builtin/logical/aws/... -count=1   # replace aws with the edited backend
```

---

## Key points about the tool

- **Do not edit `scripts/openapi.json` directly.** Gap counts will not drop until the repo
  regenerates the spec from the updated Go source.
- **Rebuild the binary before regenerating the spec.** `gen_openapi.sh` uses the `vault` binary
  from `$PATH`. Source changes are invisible to it until you run `go build -o "$(go env GOPATH)/bin/vault" .`.
- **Primary target is `builtin/logical/`.** This skill currently targets `aws`, `consul`, `database`,
  `nomad`, `pki`, `pkiext`, `rabbitmq`, `ssh`, `totp`, and `transit` in Vault core repos.
- **Detect alternate layouts before grepping.** If the repo does not have `builtin/logical/`, adapt to repo-root files like `backend.go` and `path_*.go`, or other repo-local backend layouts.
- A `Responses:` block with no `Fields:` map still counts as a gap — the spec needs
  `content.application/json.schema` to be present.
- A whitespace-only `HelpSynopsis` becomes `""` after `cleanString()` and is dropped by
  `omitempty` → still recorded as a gap.
- **Input schema ≠ response schema.** The `Fields:` map on `framework.Path` is for input parameters; the `Fields:` map inside a `Responses` block is for output fields. They are different — response fields may include derived/computed values not in the input schema, and may use different types (`TypeSlice` not `TypeCommaStringSlice`, `TypeInt` not `TypeDurationSecond`).
- **Extract repeated response `Fields:` blocks to a local helper.** If the same response schema appears on two or more operations within the same file, extract it to a file-local function (e.g. `responseFieldsRoleSetKey()`). See [`references/response-helpers.md`](.agents/skills/vault-openapi-coverage/references/response-helpers.md) for naming and placement rules. Do not share helpers across files — each path file owns its response contract independently.
