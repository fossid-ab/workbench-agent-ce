---
name: openspec-archive-change
description: Archive a completed change in the experimental workflow. Use when the user wants to finalize and archive a change after implementation is complete.
license: MIT
compatibility: Requires the Agent-CE root npx openspec CLI.
metadata:
  author: openspec
  version: "1.0"
---

Archive a completed Agent-CE OpenSpec change and optionally sync its deltas into the baseline.

**Scope:** Update `openspec/specs/` only. Do not copy API wire schemas into baseline specs during sync.

**Steps**

1. If no change name is given, run `npx openspec list --json` and ask the user to choose. Do not auto-select.
2. Run `npx openspec status --change "<name>" --json`. Warn about artifacts that are not `done` and ask before continuing.
3. Read `tasks.md`. Warn about remaining `- [ ]` tasks and ask before continuing.
4. If delta specs exist, compare them with `openspec/specs/<capability>/spec.md` and summarize the sync. Ask whether to sync now or archive without syncing.
5. When syncing, edit the baseline requirements in place. Keep command-only behavior in `<command>-command` and shared behavior in the shared capability.
6. Move the change:
   ```bash
   mkdir -p openspec/changes/archive
   mv openspec/changes/<name> openspec/changes/archive/YYYY-MM-DD-<name>
   ```
   Stop if the target directory already exists.
7. Report the archive path, schema, sync result, and warnings.

**Guardrails**
- Preserve `.openspec.yaml` by moving the whole directory.
- Do not block archive after the user confirms a warning.
- Do not modify product code during archive.
