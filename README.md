# About the Workbench Agent
The **Workbench-Agent** is a CLI that interacts with **FossID Workbench**. 

This is the Community Edition (CE) of the Workbench Agent maintained by the Customer Success Team. We will do our best to stay on top of any GitHub Issues opened and review any Pull Requests with fixes and improvements (thank you in advance!).

If you prefer a solution with a contracted SLA, please use the official Workbench Agent, which lives in the [Workbench Agent Repo](https://github.com/fossid-ab/workbench-agent). Reach out if you have any questions!

## General Usage
This repo publishes a container image to GitHub Container Registry (GHCR).

- **`latest`** — points at the **last stable release** (published via the *Publish Stable Release to GHCR* workflow). Use this or a **pinned semver tag** (for example `0.8.0`) when you need reproducible, client-facing behavior.
- **`edge`** — rebuilt on every push to `main`. Use this for **contributors and internal CI**; it may break between releases.

```bash
docker run ghcr.io/fossid-ab/workbench-agent-ce:latest --help
```

This shows the general Help message and lets you know the container is ready! Each command has its own help:

```bash
docker run ghcr.io/fossid-ab/workbench-agent-ce:latest scan --help
docker run ghcr.io/fossid-ab/workbench-agent-ce:latest evaluate-gates --help
docker run ghcr.io/fossid-ab/workbench-agent-ce:latest download-reports --help
```

The [Workbench Agent Wiki](https://github.com/fossid-ab/workbench-agent-ce/wiki) has more information on each command. 

## Quick Start
The [Getting Started Guide](https://github.com/fossid-ab/workbench-agent-ce/wiki/Getting-Started) walks through initial setup and running your first scan.

## Available Scan Settings
The scanning-related commands (scan, scan-git, blind-scan) support the same scan settings available in the Workbench UI. Visit [Customizing Scan Operations](https://github.com/fossid-ab/workbench-agent-ce/wiki/Customizing-Scan-Operations) for details.

## Contributing
Thank you for considering contributing to Workbench Agent CE! The easiest way to contribute is by reporting bugs or by
sending improvement suggestions. Please create an Issue in this GitHub repository with bugs or improvement ideas.

Pull requests are also welcomed. Please note that the Workbench-Agent is licensed under MIT license.
The submission of your contribution implies that you agree with MIT licensing terms.
