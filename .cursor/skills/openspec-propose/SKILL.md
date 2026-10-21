---
name: openspec-propose
description: Propose a new change with all artifacts generated in one step. Use when the user wants to quickly describe what they want to build and get a complete proposal with design, specs, and tasks ready for implementation.
license: MIT
compatibility: Requires the Agent-CE root npx openspec CLI.
metadata:
  author: openspec
  version: "1.0"
---

Propose a new Workbench Agent CE change and generate all artifacts in one step.

**Scope:** Handlers, CE services, and utilities only. Do not specify `src/workbench_agent/api/` wire contracts unless the user explicitly expands scope. Read `openspec/README.md` first.

Artifacts:
- proposal.md (what & why)
- design.md (how)
- tasks.md (implementation steps)

When ready to implement, use the apply skill.

**Input**: A kebab-case change name or a description of the desired behavior.

**Steps**

1. If the request is unclear, ask what behavior should change before creating files.
2. Derive a kebab-case name. If `openspec/changes/<name>/` already exists, ask whether to continue it.
3. Create the change:
   ```bash
   npx openspec new change "<name>"
   ```
4. Read `npx openspec status --change "<name>" --json` for `applyRequires` and artifact order.
5. For each ready artifact, run `npx openspec instructions <artifact-id> --change "<name>" --json`.
   - Use `template` as the file structure.
   - Apply `context` and `rules` as constraints. Do not copy them into the file.
   - Read completed dependency artifacts first.
   - Re-run status after each artifact.
6. Stop when every `applyRequires` artifact is `done`.
7. Show `npx openspec status --change "<name>"` and tell the user they can apply the change.

**Guardrails**
- Command-specific deltas go in `<command>-command`. Shared behavior goes in the shared capability named by `openspec/README.md`.
- Do not restate a shared requirement inside a command delta.
- Do not invent API request or response fields.
