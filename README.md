# About the Workbench Agent
The **Workbench-Agent** is a CLI to interact with **FossID Workbench**. 

We use GitHub Issues for this repo; thank you in advance for reporting issues!

## Container Image Tags
This repo publishes container images to [GitHub Container Registry](https://github.com/fossid-ab/workbench-agent-ce/pkgs/container/workbench-agent-ce) (`ghcr.io/fossid-ab/workbench-agent-ce`) with several tags:

- **latest** - the latest stable release - use this tag when you want to run the newest stable release
- **version tag** - a tagged stable release (for example `0.10.0`) - use this tag in CI for reproducibility
- **edge** - the latest and greatest in between releases - use this tag carefully, as it may break between releases

## General Usage

```bash
docker run ghcr.io/fossid-ab/workbench-agent-ce:latest --help
```

This shows the Help message and lets you know the container is ready! Each command has its own help:

```bash
docker run ghcr.io/fossid-ab/workbench-agent-ce:latest scan --help
docker run ghcr.io/fossid-ab/workbench-agent-ce:latest analyze --help
docker run ghcr.io/fossid-ab/workbench-agent-ce:latest evaluate-gates --help
docker run ghcr.io/fossid-ab/workbench-agent-ce:latest download-reports --help
```

The [Workbench Agent Wiki](https://github.com/fossid-ab/workbench-agent-ce/wiki) has information on each command and Getting Started guides. 

## Available Scan Settings
The scanning commands (`scan`, `scan-git`, `blind-scan`, and the first-party KB scan in `analyze`) support the settings available in the Workbench UI. Visit [Customizing Scan Operations](https://github.com/fossid-ab/workbench-agent-ce/wiki/Customizing-Scan-Operations) for details.

## Contributing
We welcome contributions to Workbench Agent CE! The best way to contribute is by reporting bugs or by suggesting improvements. Please create an Issue in this repository with bugs or improvement ideas.

We also welcome Pull requests! Please note that the Workbench-Agent is licensed under MIT license.
The submission of your contribution implies that you agree with MIT licensing terms.
