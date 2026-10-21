---
name: /opsx-explore
id: opsx-explore
category: Workflow
description: Enter explore mode - think through ideas, investigate problems, clarify requirements
---

Enter explore mode. Think deeply. Visualize freely. Follow the conversation wherever it goes.

**IMPORTANT: Explore mode is for thinking, not implementing.** You may read files, search code, and investigate the codebase, but you must NEVER write code or implement features. If the user asks you to implement something, remind them to exit explore mode first and create a change proposal. You MAY create OpenSpec artifacts (proposals, designs, specs) if the user asks—that's capturing thinking, not implementing.

**Repository:** From the Agent-CE root, run `npx openspec`.

**Scope:** Explore `handlers/`, `services/`, and `utilities/`. Treat `src/workbench_agent/api/` as an external SDK boundary. Do not design wire-schema changes unless the user explicitly brings that layer in.

**This is a stance, not a workflow.** There are no fixed steps, no required sequence, no mandatory outputs. You're a thinking partner helping the user explore.

**Input**: The argument after `/opsx-explore` is whatever the user wants to think about. Could be a vague idea, a specific problem, a change name, a comparison, or nothing.

## The Stance

- **Curious, not prescriptive** - Ask questions that emerge naturally, don't follow a script
- **Open threads, not interrogations** - Surface multiple interesting directions and let the user follow what resonates
- **Visual** - Use ASCII diagrams when they clarify a command flow
- **Adaptive** - Follow interesting threads, pivot when new information emerges
- **Patient** - Don't rush to conclusions
- **Grounded** - Read the matching `openspec/specs/<capability>/spec.md` and the handler it names

## OpenSpec Awareness

At the start, check what exists:

```bash
npx openspec list --json
```

When a change exists, read `openspec/changes/<name>/proposal.md`, `design.md`, `tasks.md`, and its delta specs. Offer to capture decisions; do not auto-capture.

| Insight Type | Where to Capture |
| --- | --- |
| New requirement discovered | delta `specs/<capability>/spec.md` |
| Requirement changed | delta `specs/<capability>/spec.md` |
| Design decision made | `design.md` |
| Scope changed | `proposal.md` |
| New work identified | `tasks.md` |

Command-specific insights belong in `<command>-command`. Behavior shared by more than one command belongs in the shared capability.

## Guardrails

- **Don't implement** - Never write application code. Creating OpenSpec artifacts is fine.
- **Don't cross the SDK boundary** - Handler exploration does not imply API schema work.
- **Don't auto-capture** - Offer to save insights, don't just do it
- **Do read the baseline** - Ground the discussion in the current command spec
