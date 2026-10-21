---
name: /opsx-archive
id: opsx-archive
category: Workflow
description: Archive a completed change and sync accepted deltas into the baseline
---

Archive a completed change.

**Repository:** From the Agent-CE root, run `npx openspec`.

**Scope:** Sync deltas only into `openspec/specs/`. Do not archive by copying API wire schemas into CE specs.

**Input**: Optionally specify a change name after `/opsx-archive`. If omitted and the choice is ambiguous, ask the user. Do not guess.

**Steps**

1. **Select the change**

   Run `npx openspec list --json`. Show only active changes. If the user did not name one, ask them to choose.

2. **Check artifact completion**

   Run `npx openspec status --change "<name>" --json`.
   If any artifact is not `done`, warn and ask whether to continue.

3. **Check task completion**

   Read `tasks.md`. If any task is still `- [ ]`, warn with the count and ask whether to continue.

4. **Assess delta sync**

   If `openspec/changes/<name>/specs/` has no delta specs, skip sync.
   Otherwise compare each delta with `openspec/specs/<capability>/spec.md` and summarize adds, modifications, removals, and renames.
   Ask the user to sync now or archive without syncing.
   When syncing, apply the delta into the baseline spec. Keep command requirements in the command spec and shared requirements in the shared capability.

5. **Archive**

   ```bash
   mkdir -p openspec/changes/archive
   ```

   Target name: `YYYY-MM-DD-<change-name>`. If that directory exists, stop and ask the user how to resolve it. Otherwise:

   ```bash
   mv openspec/changes/<name> openspec/changes/archive/YYYY-MM-DD-<name>
   ```

6. **Display the summary**

   Include the change name, schema, archive path, whether specs were synced, and any warnings.

**Guardrails**
- Always prompt for change selection if not provided
- Don't block archive on warnings - just inform and confirm
- Preserve `.openspec.yaml` by moving the whole change directory
- Do not edit `src/workbench_agent/api/` during archive
