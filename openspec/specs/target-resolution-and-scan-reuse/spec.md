# target-resolution-and-scan-reuse Specification

## Purpose
Some commands require a Project and Scan in Workbench to work against. Resolve CLI project and scan names or codes to Workbench identifiers, create them only for commands that write, and reject reuse of an existing scan whose type or Git target does not match the command.

## Requirements

### Requirement: Identifier exclusivity
Workbench supports both Names and Codes for Projects and Scans. Names are preferred since Codes are internal identifiers Workbench uses for various operations. `ResolverService` SHALL accept exactly one of name or code for a project, and exactly one of name or code for a scan. Supplying both or neither MUST raise `ValueError`.

#### Scenario: Both project identifiers are supplied
- **WHEN** project resolution receives a name and a code
- **THEN** resolution fails before any Workbench lookup

#### Scenario: A scan identifier is missing
- **WHEN** scan resolution is required and neither scan name nor scan code is supplied
- **THEN** resolution fails before creating a scan

### Requirement: Create versus lookup
Write commands (scan, scan-git, blind-scan, analyze, import-sbom, import-da) SHALL resolve through `find_or_create_project_and_scan`, which MAY create a missing project or scan. Read commands (show-results, download-reports) SHALL call `resolve_project_and_scan` with `allow_create=False` and MUST NOT create a project or scan.

#### Scenario: Write command finds neither target
- **WHEN** a write command names a project and scan that do not exist
- **THEN** both are created and the caller receives `scan_is_new=True`

#### Scenario: Read command misses a scan
- **WHEN** a read command names a scan that does not exist
- **THEN** resolution raises a scan-not-found error and creates nothing

#### Scenario: Scan code belongs to another project
- **WHEN** a scan code exists but not in the requested project
- **THEN** resolution raises `ScanWrongProjectError` and does not create a scan in the requested project

### Requirement: Project-only resolution
When `scan_required` is false, resolution SHALL return the project code and an empty scan code. It MUST NOT look up or create a scan.

#### Scenario: Project-scoped report
- **WHEN** download-reports resolves a project-scoped target
- **THEN** the result contains the project code and an empty scan code

### Requirement: Scan reuse compatibility
After finding an existing scan for a write command, CE SHALL check compatibility before mutation. `scan`, `blind-scan`, and `analyze` require an upload scan. `scan-git` requires a Git scan with the same repository, ref type, and ref value. `import-sbom` requires an SBOM scan. `import-da` MUST reject an SBOM scan and MAY reuse other existing scan types. A mismatch MUST raise `CompatibilityError` with command-specific advice.

#### Scenario: Upload command reuses a Git scan
- **WHEN** `scan` resolves an existing Git scan
- **THEN** the command stops with `CompatibilityError` and does not upload content

#### Scenario: Git ref differs
- **WHEN** `scan-git` resolves a Git scan whose repository or ref does not match the request
- **THEN** the command stops with `CompatibilityError` and does not clone

#### Scenario: Dependency import reuses an SBOM scan
- **WHEN** `import-da` resolves an existing SBOM scan
- **THEN** the command stops with `CompatibilityError` and does not upload results

### Requirement: SBOM creation flag
`import-sbom` SHALL pass `import_from_report=True` when creating a scan so the new scan is an SBOM scan.

#### Scenario: New SBOM scan
- **WHEN** `import-sbom` creates a scan
- **THEN** the create payload sets `import_from_report` to `"1"`

### Requirement: Resolution metadata
`ResolvedTargets` SHALL expose project code, scan code, whether each was created, and scan information for an existing scan. `target_label` SHALL prefer the user-supplied name and fall back to the code for log and error text.

#### Scenario: Existing scan is resolved
- **WHEN** lookup finds an existing scan
- **THEN** `scan_is_new` is false and `scan_info` contains the listing metadata
