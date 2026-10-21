# upload-and-temporary-data Specification

## Purpose
Turn a local scan target into a file Workbench can accept, and delete only temporary files and directories that Agent CE created under the system temporary directory.

## Requirements

### Requirement: Directory targets become archives
`prepare_scan_target` SHALL compress a directory into a temporary ZIP and yield that ZIP path. A file target MUST be yielded unchanged and MUST NOT be deleted when the context exits.

#### Scenario: Directory upload
- **WHEN** `scan` prepares a directory path
- **THEN** Workbench receives a ZIP and the temporary archive directory is removed after the upload attempt

#### Scenario: Archive file upload
- **WHEN** `scan` prepares an existing archive file
- **THEN** that same file path is uploaded and is not deleted afterward

### Requirement: Archive exclusions
Directory compression SHALL exclude the default development, VCS, and OS paths in `UploadArchivePrep.DEFAULT_EXCLUSIONS`, plus patterns from a top-level `.gitignore` when one exists. Callers MAY pass additional exclusion names. Extra exclusions MUST be honored for that archive only.

#### Scenario: Gitignored file
- **WHEN** a directory contains a file matched by its `.gitignore`
- **THEN** that file is omitted from the ZIP

#### Scenario: Analyze path exclusions
- **WHEN** `analyze` uploads a path-strategy tree
- **THEN** the archive also excludes `target`, `build`, `out`, `dist`, and names supplied with `--exclude`

### Requirement: Temporary cleanup boundary
`cleanup_temp_path` SHALL delete a file or directory only when its path is under `tempfile.gettempdir()`. Any other path MUST be left in place and logged.

#### Scenario: User-supplied hash file
- **WHEN** cleanup is asked to remove a `.fossid` file outside the system temp directory
- **THEN** the file remains on disk

#### Scenario: Generated hash file
- **WHEN** cleanup is asked to remove a hash file created under the system temp directory
- **THEN** that file is removed and a cleanup failure is logged without replacing the original command error
