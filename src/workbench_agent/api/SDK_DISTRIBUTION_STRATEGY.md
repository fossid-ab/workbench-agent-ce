# SDK Distribution Strategy

## Architecture Overview

```
┌─────────────────────────────────────────────────────────┐
│  Workbench Agent CLI (workbench-agent)                 │
│  - Version: independent (0.8.0, 0.9.0, etc.)           │
│  - Depends on: workbench-sdk>=24.3.0                   │
│  - pyproject.toml enforces SDK version requirement      │
└───────────────────┬─────────────────────────────────────┘
                    │ requires
                    ↓
┌─────────────────────────────────────────────────────────┐
│  Workbench SDK (workbench-sdk)                          │
│  - Version: matches Workbench API (24.3.0, 25.1.0)     │
│  - Located in: src/workbench_agent/api/                │
│  - Checks server compatibility on init                  │
└───────────────────┬─────────────────────────────────────┘
                    │ connects to
                    ↓
┌─────────────────────────────────────────────────────────┐
│  Workbench Server                                       │
│  - Version: 24.3.0, 25.1.0, etc.                       │
│  - SDK validates compatibility automatically            │
└─────────────────────────────────────────────────────────┘
```

## Version Correspondence

### SDK Versions Match Workbench Versions
- `workbench-sdk==24.3.0` → Works with Workbench 24.3.x servers
- `workbench-sdk==25.1.0` → Works with Workbench 25.1.x servers
- SDK checks server compatibility at initialization time

### CLI Application Specifies SDK Requirements
The CLI application (`workbench-agent`) specifies its SDK dependency in `pyproject.toml`:
```toml
dependencies = [
    "workbench-sdk>=24.3.0",  # CLI requires SDK 24.3.0 or newer
    "requests",
    # ... other deps
]
```

## Current Setup (Monorepo)

Currently, both SDK and CLI are in the same repository:

```
workbench-agent-ce/
├── pyproject.toml              # CLI application config
├── src/
│   └── workbench_agent/
│       ├── api/                # ← SDK code (will be extracted)
│       │   ├── __init__.py    # Exports WorkbenchClient, exceptions
│       │   ├── exceptions.py
│       │   ├── workbench_client.py
│       │   ├── clients/
│       │   ├── services/
│       │   └── helpers/
│       ├── cli/                # CLI code (stays here)
│       ├── handlers/           # CLI code (stays here)
│       └── main.py            # CLI entry point (stays here)
```

## Future Setup (Separate Packages)

###  Step 1: Create SDK Package

```
workbench-sdk/
├── pyproject.toml              # SDK-specific config
│   [project]
│   name = "workbench-sdk"
│   version = "24.3.0"         # Matches Workbench version!
│   dependencies = [
│       "requests",
│       "packaging>=21.0",
│   ]
├── src/
│   └── workbench_sdk/          # Renamed from workbench_agent.api
│       ├── __init__.py
│       ├── exceptions.py
│       ├── workbench_client.py
│       ├── clients/
│       ├── services/
│       └── helpers/
└── README.md                   # SDK-specific docs
```

### Step 2: Update CLI to Use SDK Package

```
workbench-agent/
├── pyproject.toml
│   [project]
│   name = "workbench-agent"
│   version = "1.0.0"           # CLI version (independent!)
│   dependencies = [
│       "workbench-sdk>=24.3.0",  # ← Declares SDK requirement
│       "python-dotenv",
│       "GitPython",
│   ]
├── src/
│   └── workbench_agent/
│       ├── cli/
│       ├── handlers/
│       ├── utilities/
│       └── main.py
│           # Changed import:
│           from workbench_sdk import WorkbenchClient  # ← External package
```

## Implementation Steps

### Phase 1: Prepare SDK for Extraction (Current)
- ✅ SDK has its own exception module (`api/exceptions.py`)
- ✅ SDK exports all public APIs via `api/__init__.py`
- ✅ SDK checks Workbench version compatibility
- ✅ Clear boundary between SDK (`api/`) and CLI (everything else)

### Phase 2: Test SDK Independence
- [ ] Add `src/workbench_agent/api/pyproject.toml` (optional - for testing)
- [ ] Verify SDK has no dependencies on CLI code
- [ ] Test SDK can be imported standalone

### Phase 3: Extract SDK to Separate Repo
- [ ] Create `workbench-sdk` repository
- [ ] Move `src/workbench_agent/api/` → `src/workbench_sdk/`
- [ ] Create SDK-specific pyproject.toml with version matching Workbench
- [ ] Publish to PyPI as `workbench-sdk`

### Phase 4: Update CLI to Use External SDK
- [ ] Update `workbench-agent/pyproject.toml` to depend on `workbench-sdk`
- [ ] Change imports from `workbench_agent.api` → `workbench_sdk`
- [ ] Remove `src/workbench_agent/api/` from CLI repo

## Benefits

### For SDK Consumers
```python
# Anyone can use the SDK directly
from workbench_sdk import WorkbenchClient
from workbench_sdk.exceptions import ApiError

client = WorkbenchClient(url, user, token)
projects = client.projects.list()
```

### For CLI Users
- CLI version evolves independently from API version
- CLI declares which SDK versions it supports
- Users get appropriate SDK automatically via pip

### For Maintainers
- SDK releases match Workbench releases (24.3.0, 25.1.0)
- CLI releases are independent (1.0.0, 1.1.0, 2.0.0)
- Clear separation of concerns

## Version Management

### SDK Releases
- **When**: When Workbench API changes (new Workbench release)
- **Version**: Matches Workbench version (24.3.0, 25.1.0)
- **Breaking Changes**: Expected when Workbench API changes

### CLI Releases
- **When**: When CLI features change (new commands, bug fixes)
- **Version**: Semantic versioning (1.0.0, 1.1.0, 2.0.0)
- **SDK Dependency**: Update when new Workbench features needed
  ```toml
  # workbench-agent v1.0.0
  dependencies = ["workbench-sdk>=24.3.0"]
  
  # workbench-agent v2.0.0 (needs new Workbench features)
  dependencies = ["workbench-sdk>=25.1.0"]
  ```

## Example: Version Evolution

```
Timeline:

Workbench 24.3.0 released
  └─> workbench-sdk==24.3.0 released
      └─> workbench-agent==1.0.0 (requires workbench-sdk>=24.3.0)

Workbench 25.1.0 released (new APIs!)
  └─> workbench-sdk==25.1.0 released (supports new APIs)
      ├─> workbench-agent==1.0.0 still works (uses old APIs)
      └─> workbench-agent==2.0.0 released (uses new APIs, requires workbench-sdk>=25.1.0)
```

## Current State

✅ **SDK is Ready for Extraction**
- Clean API boundary
- Self-contained exception handling  
- Version checking built-in
- No dependencies on CLI code

🎯 **Next Steps**
1. Add SDK-specific documentation
2. Create separate pyproject.toml for SDK
3. Test standalone SDK installation
4. Extract to separate repository when ready

This architecture follows Python best practices (like `requests`, `boto3`, etc.) where:
- SDK versions match the API they support
- Applications declare their SDK requirements
- Clear separation enables independent evolution

