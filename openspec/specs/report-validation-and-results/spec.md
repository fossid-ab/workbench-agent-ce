# report-validation-and-results Specification

## Purpose
Validate and prepare SBOMs for import, fetch and present scan results, and print import and report summaries without defining Workbench wire schemas.

## Requirements

### Requirement: SBOM validation before side effects
`SBOMValidator` SHALL accept CycloneDX JSON and SPDX JSON, RDF, XML, or `.spdx` files. `import-sbom` MUST validate and prepare the file before resolving or creating a project or scan. An invalid SBOM MUST raise `ValidationError` or `FileSystemError` and MUST NOT create Workbench objects.

#### Scenario: Invalid SBOM
- **WHEN** `import-sbom` receives a file that is not a supported SBOM
- **THEN** the command fails before project and scan resolution

### Requirement: Supported SBOM versions
CycloneDX upload SHALL accept spec versions 1.4, 1.5, and 1.6 only. SPDX validation MUST accept document versions 2.0, 2.1, 2.2, and 2.3 only. Any other detected version MUST fail validation before project or scan resolution.

#### Scenario: Unsupported CycloneDX version
- **WHEN** the file is CycloneDX 1.3
- **THEN** validation fails and no scan is created

### Requirement: SPDX JSON conversion
SPDX JSON SHALL be uploaded unchanged when the connected Workbench version is at least `2025.2.0`. Older, empty, or unparseable versions MUST cause a temporary SPDX RDF conversion. CycloneDX and non-JSON SPDX inputs MUST keep their original path. A temporary conversion MUST be removed with the temporary-path cleanup rules.

#### Scenario: Older Workbench receives SPDX JSON
- **WHEN** Workbench is older than 2025.2.0 and the file is SPDX JSON
- **THEN** CE uploads a converted RDF file and deletes that temporary file afterward

#### Scenario: Current Workbench receives SPDX JSON
- **WHEN** Workbench is 2025.2.0 or newer and the file is SPDX JSON
- **THEN** CE uploads the original file and creates no conversion temporary

### Requirement: Selected result sections
`fetch_display_save_results` SHALL fetch only the result sections enabled by `--show-licenses`, `--show-components`, `--show-matches`, `--show-dependencies`, `--show-scan-metrics`, `--show-policy-warnings`, `--show-project-policy-warnings`, and `--show-vulnerabilities`. Vulnerability rows MUST use `utilities/vulnerability_display.py`. When `--result-save-path` is set, collected JSON MUST be written there, and a write failure MUST warn without failing a successful fetch.

#### Scenario: One section requested
- **WHEN** `show-results` is called with only `--show-components`
- **THEN** the displayed output contains the component section and does not require the other sections

#### Scenario: Save path is not writable
- **WHEN** results are fetched and the save path cannot be written
- **THEN** the command prints a warning and still returns success

### Requirement: Import and report summaries
A completed `import-da` or `import-sbom` SHALL call `print_import_summary` and honor `--show-summary`. `download-reports` SHALL call `print_report_summary` with the attempted types, success count, and failed types. Scan-scoped summaries MUST include the Workbench link when one can be built. Summary generation MUST NOT change the command's success result.

#### Scenario: Import summary requested
- **WHEN** an import completes with `--show-summary`
- **THEN** the import summary includes the requested detail and the command result remains the import result
