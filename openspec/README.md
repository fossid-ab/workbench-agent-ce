# OpenSpec for Workbench Agent CE

OpenSpec is the collaboration surface for Workbench Agent CE behavior. Humans and agents use it to agree on what a command, service, or utility does before changing code.

## Scope

In scope:

- `src/workbench_agent/handlers/`
- `src/workbench_agent/services/`
- `src/workbench_agent/utilities/`
- the CLI dispatch and error behavior those modules depend on

Out of scope:

- `src/workbench_agent/api/` request and response schemas
- the future `workbench-sdk` package split

API wire contracts stay in `src/workbench_agent/api/clients/*/schema.md` and `tests/api/`. A CE spec may name the client operation a handler calls, but it does not duplicate field-level server contracts.

## Layout

```text
openspec/
  config.yaml                         # schema and project context
  specs/<capability>/spec.md          # current baseline behavior
  changes/<change-name>/              # an active proposal
    proposal.md
    design.md
    tasks.md
    specs/<capability>/spec.md        # delta only
  changes/archive/YYYY-MM-DD-<name>/  # completed proposals
```

Command capabilities use the directory name `<command>-command`, for example `scan-command`. Shared capabilities describe behavior used by more than one command, such as `scan-execution-workflow`. A command spec references a shared capability instead of copying it.

| Module | Spec |
| --- | --- |
| `handlers/scan.py` | `scan-command` |
| `handlers/scan_git.py` | `scan-git-command` |
| `handlers/blind_scan.py` | `blind-scan-command` |
| `handlers/analyze.py` | `analyze-command` |
| `handlers/quick_scan.py` | `quick-scan-command` |
| `handlers/import_da.py` | `import-da-command` |
| `handlers/import_sbom.py` | `import-sbom-command` |
| `handlers/show_results.py` | `show-results-command` |
| `handlers/download_reports.py` | `download-reports-command` |
| `handlers/evaluate_gates.py` | `evaluate-gates-command` |
| `handlers/delete_scan.py` | `delete-scan-command` |
| `services/resolver_service.py`, `services/types.py`, `utilities/resolve_project_scan.py` | `target-resolution-and-scan-reuse` |
| `utilities/pre_flight_checks.py` | `preflight-and-status-waiting` |
| `utilities/scan_workflows.py`, `utilities/resolve_id_reuse.py`, `utilities/post_scan_summary.py` | `scan-execution-workflow` |
| `utilities/upload_data_prep.py` | `upload-and-temporary-data` |
| `utilities/toolbox_wrapper.py` | `toolbox-runtime`, `toolbox-hash-generation`, `toolbox-dependency-analysis` |
| `utilities/analyze/` | `analyze-ecosystems-and-first-party` |
| `utilities/sbom_validator.py`, `utilities/result_utilities.py`, `utilities/vulnerability_display.py`, `utilities/post_import_summary.py`, `utilities/post_report_summary.py` | `report-validation-and-results` |
| `utilities/error_handling.py`, `utilities/redaction.py`, `utilities/section.py` | `handler-errors-and-redaction` |

`utilities/config_display.py` is startup output owned by `main.py`, not a command handler. It stays outside the handler capability set.

## Baseline and changes

`openspec/specs/` describes the product as it is. Do not edit a baseline spec directly for new work.

An active change lives in `openspec/changes/<change-name>/`. Its spec files contain only the delta: added, modified, removed, or renamed requirements. Archiving a change moves that directory to `openspec/changes/archive/` and syncs accepted deltas into the baseline.

## Local CLI

OpenSpec is pinned as a private dev dependency in the repository root `package.json`. From the repository root:

```bash
npm install
npx openspec --help
npm run openspec:validate
```

`npm run openspec:validate` checks every baseline spec and active change in strict mode.

## Working on a command

1. Read `openspec/specs/<command>-command/spec.md` and the shared specs it names.
2. Propose a change with `/opsx-propose` or `npx openspec new change "<kebab-name>"`.
3. Add the delta under `openspec/changes/<change-name>/specs/<capability>/spec.md`.
4. Implement with `/opsx-apply`.
5. Archive with `/opsx-archive` after the tasks and tests pass.

Cursor workflow guidance lives in `.cursor/commands/opsx-*.md` and `.cursor/skills/openspec-*/SKILL.md`.
