# About the Workbench Agent
The **Workbench-Agent** is a CLI to interact with and automate **FossID Workbench**. 

This is the Community Edition (CE) of the Workbench Agent maintained by the Customer Success Team. We use GitHub Issues for this repo; thank you in advance for reporting any issues! We will do our best to stay on top of any GitHub Issues opened.

The official [Workbench Agent](https://github.com/fossid-ab/workbench-agent) is maintained by Engineering and has contracted SLA.

## Container Image Tags
This repo publishes container images to [GitHub Container Registry](https://github.com/fossid-ab/workbench-agent-ce/pkgs/container/workbench-agent-ce) (`ghcr.io/fossid-ab/workbench-agent-ce`) with several tags:

- **latest** - the latest stable release - use this tag when you want to run the newest stable release
- **version tag** - a tagged release (for example `0.8.0`) - use this tag in CI for reproducibility
- **edge** - the latest and greatest in between releases - use this tag carefully, as it may break between releases

## General Usage

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
Thank you for considering contributing to Workbench Agent CE! The best way to contribute is by reporting bugs or by
sending improvement suggestions. Please create an Issue in this GitHub repository with bugs or improvement ideas.

Pull requests are also welcomed. Please note that the Workbench-Agent is licensed under MIT license.
The submission of your contribution implies that you agree with MIT licensing terms.
