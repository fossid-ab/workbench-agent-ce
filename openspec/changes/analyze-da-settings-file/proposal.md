# Proposal

## Why

`analyze` runs `fossid-toolbox da`, but there is no way to tune what FDA keeps, such as which Maven scopes (test, provided, runtime, optional) reach the report. FDA reads these from a `fossid-settings.toml` overlay. Recent FDA builds find that file in the scanned tree on their own, but Toolbox 1.7.11 does not, so a file committed to the repository is silently ignored.

## What Changes

- When the path given to `analyze` is a directory with a `fossid-settings.toml` at its root, the agent passes it to Toolbox with `da -s <path>`, in pipeline and `--buildless` mode alike, and prints the path it applied.
- A detected file that sets `da_host`, `da_artifactory_*`, `da_nexus_*` or `da_private_repo_*` is not passed, with a warning. FDA refuses those keys from settings found in scanned code; passing the file explicitly would bypass that rule.
- A file that cannot be read is skipped with a warning; the analysis continues.

## Capabilities

### Modified Capabilities

- `toolbox-dependency-analysis`: Root `fossid-settings.toml` detection and forwarding.

## Non-goals

- A CLI flag naming a settings file elsewhere.
- Searching subdirectories (only the analyzed root is checked).
- Parsing or validating `da_*` keys; FDA owns that.
- Changing `--fossid-conf-path` behavior.

## Impact

- `utilities/toolbox_wrapper.py` (`find_da_settings_file`, `-s` in `_execute_da`)
- `tests/unit/utilities/test_toolbox_da_pipeline.py`
