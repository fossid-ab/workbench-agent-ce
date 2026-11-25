# Tasks

## 1. Detection and forwarding

- [x] 1.1 Add `find_da_settings_file` to `utilities/toolbox_wrapper.py` (root only, untrusted-key and unreadable-file skips)
- [x] 1.2 Pass the detected file as `da -s <path>` from `_execute_da` for pipeline and manifest runs

## 2. Tests

- [x] 2.1 Unit tests for detection, skips, and `-s` placement in both modes
- [x] 2.2 Manual run on a Maven sample: test scope reaches the report when the file enables it
