# analyze-ecosystems-and-first-party Specification

## Purpose
Select an analyze ecosystem plugin, validate its required flags, and choose which first-party files are knowledge-base scanned before the Toolbox dependency graph is imported.

## Requirements

### Requirement: Ecosystem plugin registry
An analyze ecosystem SHALL be an `AnalyzeEcosystem` plugin registered from `utilities/analyze/ecosystems/`. The handler MUST stay generic and obtain manifests, required flags, pipeline arguments, and first-party strategy from the registry. Bazel MUST require `--bazel-target` and use the sidecar strategy. Maven MUST detect `pom.xml`, require no extra flag, and use the path strategy.

#### Scenario: Bazel target is missing
- **WHEN** `analyze -e bazel` is run without `--bazel-target`
- **THEN** validation raises `ValidationError` before Toolbox starts

#### Scenario: Ecosystem omitted
- **WHEN** `--ecosystem` is omitted
- **THEN** CE detects the ecosystem from registered manifest filenames in the project path

### Requirement: Buildless overrides ecosystem strategy
`--buildless` SHALL force the path first-party strategy and MUST NOT require an ecosystem plugin. An optional `--ecosystem` value MAY be forwarded to the Toolbox manifest scan.

#### Scenario: Buildless Maven tree
- **WHEN** `analyze --buildless` points at a tree without a registered ecosystem
- **THEN** Toolbox manifest scanning still runs and first-party selection uses the project path

### Requirement: First-party strategies
`resolve_first_party` SHALL support sidecar, path, and none. Sidecar MUST stage files named by the Toolbox source list into an owned temporary directory. Path upload MUST scan the project path with archive exclusions. Path blind-scan MUST stage a filtered tree so hashes include only the selected files. None, or a sidecar list with no files, MUST return no scan root.

#### Scenario: Sidecar list is empty
- **WHEN** the sidecar strategy produces no first-party files
- **THEN** `analyze` skips the KB scan and imports the dependency graph only

#### Scenario: Owned staging directory
- **WHEN** sidecar resolution creates a temporary tree
- **THEN** `analyze` deletes that tree after success or failure

### Requirement: Dependency-analysis-only shortcut
`--dependency-analysis-only` SHALL skip first-party discovery and the KB scan. The command MUST still import the Toolbox dependency report.

#### Scenario: Dependencies only
- **WHEN** `analyze --dependency-analysis-only` completes Toolbox analysis
- **THEN** no source upload or hash upload occurs and the dependency report is imported

### Requirement: Combined summary
After the optional KB scan and dependency import, `analyze` SHALL print one analysis summary through `print_analysis_summary`. The summary MUST record whether a KB scan ran and whether dependency import was waited for.

#### Scenario: No-wait import
- **WHEN** dependency import is started with `--no-wait`
- **THEN** the summary records that dependency import was not waited for
