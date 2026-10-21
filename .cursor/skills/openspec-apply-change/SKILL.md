---
name: openspec-apply-change
description: Implement tasks from an OpenSpec change. Use when the user wants to start implementing, continue implementation, or work through tasks.
license: MIT
compatibility: Requires the Agent-CE root npx openspec CLI.
metadata:
  author: openspec
  version: "1.0"
---

Implement tasks from an Agent-CE OpenSpec change.

**Scope:** Change `handlers/`, `services/`, and `utilities/` to satisfy the delta. Do not modify `src/workbench_agent/api/` unless the change explicitly includes that scope and the user confirmed it.

**Steps**

1. Select the named change, the change inferred from context, or the only active change. If ambiguous, run `npx openspec list --json` and ask. Announce the selected name.
2. Run `npx openspec status --change "<name>" --json` and `npx openspec instructions apply --change "<name>" --json`.
3. If apply is blocked, stop and say which artifacts are missing. If all tasks are done, suggest archive.
4. Read every context file and the baseline specs the delta modifies.
5. Implement pending tasks one at a time. Mark each `- [ ]` as `- [x]` immediately after it is done.
6. Pause for an unclear task, a design contradiction, a test failure you cannot fix inside scope, or an unexpected need to change the API layer.

**Output**

Report the schema, tasks completed this session, and overall `N/M` progress. When finished, suggest archive.

**Guardrails**
- Keep each edit scoped to the current task.
- Preserve the command/shared-spec split while implementing.
- Use the repository test layer named by the task. Do not require a live Workbench run for a unit-level task.
