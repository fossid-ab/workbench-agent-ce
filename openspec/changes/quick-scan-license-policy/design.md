# Design

## Context

See proposal.md. Today `handlers/quick_scan.py` calls `client.quick_scan.scan_one_file` and formats each result as one sentence. A live response shows each result carries `type`, `snippet` (`remote_size`, `local_coverage`), `file.path`, and a `component` with `artifact`, `version`, `author`, `purl`, `license`, `licenses[]` (each with `id`), and an optional `copyright[]` (each with `default`). Workbench project license policies are already downloadable through `PolicyService.download_project_policy_json`, which returns a list of rules with `id`, `blocked`, and `reason`.

## Goals / Non-Goals

**Goals:**
- Readable, structured per-match output that tolerates missing fields.
- Optional, lookup-only project policy evaluation with clear warnings.

**Non-Goals:**
- Local policy files, category rules, exit-code gating, API changes.

## Decisions

1. **Policy classification utility** — `utilities/license_policy.py` exposes `LicensePolicy.from_workbench_rules(rules)` and `classify(license_id)` returning `allowed`, `conditional`, `prohibited`, or `None` (not covered). Mapping mirrors the FossID toolbox legacy derivation so IDE plugin, MCP server, and CLI agree: `blocked` false → allowed; `blocked` true with a reason starting "conditionally approved" or "approved with condition" (case-insensitive) → conditional; otherwise prohibited. `blocked` is parsed tolerantly (bool, `1`/`0`, `"true"`/`"false"`). Matching is case-sensitive on the license id.

2. **Which licenses are evaluated** — every distinct id from `component.license` and `component.licenses[].id`, in first-seen order. The block displays the primary `license` plus "also detected" ids, so a secondary detected license cannot hide behind the declared one.

3. **Project resolution** — the handler calls `ResolverService.find_project(name=..., code=...)` directly (lookup-only). It does not use `resolve_project_and_scan`, which builds scan-create data irrelevant to quick-scan. `ProjectNotFoundError` propagates through `handler_error_wrapper`. The policy is downloaded once, before the scan, so a bad project fails fast without spending a scan.

4. **Exit status** — policy findings never change the return value; the handler returns true after a completed scan.

5. **API boundary** — only existing calls: `client.quick_scan.scan_one_file`, `client.projects` / `client.scans` through `ResolverService`, and `client.policy.download_project_policy_json`.

## Risks / Trade-offs

- [Output format change] → Scripts parsing the old sentence break. `--raw` remains the stable machine-readable path.
- [Empty policy] → Every license shows "not covered"; acceptable and accurate.
