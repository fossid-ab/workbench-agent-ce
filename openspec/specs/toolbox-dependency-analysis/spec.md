# toolbox-dependency-analysis Specification

## Purpose
Run FossID Toolbox dependency analysis for managed dependencies and leave behind the report that `analyze` imports into Workbench. Callers MUST follow `toolbox-runtime` before invoking Toolbox.

## Requirements

### Requirement: Dependency-analysis modes
`analyze` SHALL use `run_da_pipeline` by default and `run_da_manifest_scan` when `--buildless` is set. Pipeline mode MUST emit the first-party source sidecar only for a sidecar strategy when a KB scan will run. Both modes MUST honor `--fossid-conf-path` and `--da-timeout`, whose default is 3600 seconds. Success MUST produce `analyzer-result.json` under a temporary Toolbox output directory.

#### Scenario: Buildless analysis
- **WHEN** `analyze` is invoked with `--buildless`
- **THEN** Toolbox scans manifests instead of running the build pipeline

#### Scenario: Sidecar emission
- **WHEN** pipeline mode runs for a sidecar ecosystem and a KB scan will follow
- **THEN** Toolbox is asked to emit the first-party source sidecar

#### Scenario: Dependency-analysis-only skips sidecar emit
- **WHEN** `analyze --dependency-analysis-only` runs pipeline mode
- **THEN** Toolbox is not asked to emit the first-party source sidecar

### Requirement: Toolbox output cleanup
`analyze` SHALL remove the Toolbox output directory after the command finishes, including when a later step fails. Cleanup MUST NOT delete the user-supplied project path.

#### Scenario: Import fails after Toolbox succeeds
- **WHEN** dependency-analysis import raises after Toolbox wrote its output
- **THEN** the Toolbox output directory is still removed
