# toolbox-hash-generation Specification

## Purpose
Generate and validate `.fossid` hash files so a knowledge-base scan can run without uploading source. Callers MUST follow `toolbox-runtime` before invoking Toolbox.

## Requirements

### Requirement: Hash generation
`generate_hashes` SHALL write a `.fossid` file for the requested path under the system temporary directory. Additional scan operations can be bolted on to a blind scan.

To collect manifests for dependency analysis, `blind-scan` MUST forward `--run-dependency-analysis` as the Toolbox manifest-hash flag. File-Level Licenses and Copyrights are collected unless `--skip-lac-extraction` is set. 

The `analyze` blind-scan leg MUST request hashes without dependency analysis because managed dependencies come from a separate Toolbox dependency-analysis import.

#### Scenario: Blind scan of a directory
- **WHEN** `blind-scan` receives a directory
- **THEN** it generates hashes with Toolbox after runtime checks and validates the generated file before upload

#### Scenario: Analyze blind first-party hashes
- **WHEN** `analyze --blind-scan` hashes a first-party staging directory
- **THEN** hash generation runs with dependency analysis disabled

#### Scenario: Blind-scan enables manifest hashing
- **WHEN** `blind-scan` is invoked with `--run-dependency-analysis`
- **THEN** Toolbox hash generation enables the manifest-hash flag

### Requirement: FossID file validation
Hash generation creates a FossID file. `validate_fossid_file` SHALL require UTF-8 text, at least one non-empty line, and a JSON object per line containing `path`, integer `size`, and `hashes_ffm`. An empty, non-UTF-8, or schema-invalid file MUST raise `ValidationError`.

#### Scenario: Pre-generated hash file
- **WHEN** `blind-scan` receives a path ending in `.fossid`
- **THEN** it validates that file and does not run Toolbox hash generation

### Requirement: Generated hash cleanup
A Toolbox-generated hash file SHALL be removed with the temporary-path cleanup rules after the command finishes, including when a later step fails. A user-supplied `.fossid` path MUST NOT be deleted.

#### Scenario: Upload fails after hash generation
- **WHEN** hash upload raises after Toolbox created the hash file
- **THEN** the generated file is still cleaned up
