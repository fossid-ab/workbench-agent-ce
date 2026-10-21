# toolbox-runtime Specification

## Purpose
Locate the FossID Toolbox executable and enforce the minimum supported version before any hash or dependency-analysis call.

## Requirements

### Requirement: Toolbox discovery
CE SHALL resolve Toolbox from `--fossid-toolbox-path` when set, otherwise from `PATH` via `fossid-toolbox`. A missing executable MUST raise `ValidationError` before Workbench is called. The resolved path MUST exist and be executable, or CE MUST raise `FileSystemError`.

#### Scenario: Toolbox is not installed
- **WHEN** a Toolbox command runs without a configured path and `fossid-toolbox` is absent from `PATH`
- **THEN** the command fails with `ValidationError` before calling Workbench

### Requirement: Minimum version
Before hashing or dependency analysis, the wrapper MUST reject a Toolbox version older than `1.7.11` with `ProcessError`. An unparseable version MUST be logged as a warning and MUST NOT by itself fail the command.

#### Scenario: Toolbox is too old
- **WHEN** the reported Toolbox version is older than 1.7.11
- **THEN** the command fails before generating hashes or running dependency analysis

#### Scenario: Version string cannot be parsed
- **WHEN** Toolbox reports a version that cannot be compared
- **THEN** CE logs a warning and continues with the requested Toolbox operation
