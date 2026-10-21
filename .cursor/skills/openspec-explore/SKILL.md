---
name: openspec-explore
description: Enter explore mode - a thinking partner for exploring ideas, investigating problems, and clarifying requirements. Use when the user wants to think through something before or during a change.
license: MIT
compatibility: Requires the Agent-CE root npx openspec CLI.
metadata:
  author: openspec
  version: "1.0"
---

Enter explore mode for Workbench Agent CE. Think and investigate. Do not implement application code.

**Scope:** Read handlers, CE services, utilities, tests, and `openspec/specs/`. Treat `src/workbench_agent/api/` as the SDK boundary. You MAY write OpenSpec artifacts when the user asks to capture a decision.

At the start, run `npx openspec list --json`. When a change is relevant, read its proposal, design, tasks, and delta specs. Also read the baseline command spec before recommending a behavior change.

Offer to capture a crystallized decision:
- requirement change → delta spec for that command or shared capability
- design decision → `design.md`
- scope change → `proposal.md`
- new work → `tasks.md`

Do not auto-capture. Do not turn an exploration into an API schema design unless the user explicitly includes that layer.

Explore mode ends when the user has clarity, asks for a proposal, or wants to continue later. There is no required artifact.
