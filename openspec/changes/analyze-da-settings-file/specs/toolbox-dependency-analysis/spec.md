# Spec Delta

## ADDED Requirements

### Requirement: Project FDA settings file
When the analyzed path is a directory with a `fossid-settings.toml` at its root, both dependency-analysis modes SHALL pass that file to Toolbox with `da -s <absolute path>` and print the path applied. Only the root SHALL be checked. A file that sets `da_host`, `da_artifactory_*`, `da_nexus_*` or `da_private_repo_*`, or that cannot be read, MUST NOT be passed; the agent SHALL log a warning and continue without it.

#### Scenario: Settings file at the project root
- **WHEN** `analyze` runs on a directory containing `fossid-settings.toml`
- **THEN** Toolbox is invoked with `da -s <that file>`

#### Scenario: No settings file
- **WHEN** the analyzed directory has no `fossid-settings.toml` at its root
- **THEN** Toolbox is invoked without `-s`

#### Scenario: Settings file sets untrusted keys
- **WHEN** the root `fossid-settings.toml` sets `da_host` or a private-repository key
- **THEN** the file is not passed and a warning names the keys
