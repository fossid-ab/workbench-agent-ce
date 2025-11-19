"""
Functional tests for workbench-agent.

These tests run actual CLI commands against a real Workbench server to validate
end-to-end workflows. They require:
- WORKBENCH_URL environment variable
- WORKBENCH_USER environment variable
- WORKBENCH_TOKEN environment variable

Run with: pytest -v -m functional
Run in parallel: pytest -v -m functional -n 4
"""

