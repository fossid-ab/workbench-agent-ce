# tests/integration/conftest.py

from unittest.mock import MagicMock, Mock, call, patch

import pytest
import requests

# Add a fallback mocker fixture for environments where pytest-mock is not installed
try:
    import pytest_mock
except ImportError:

    @pytest.fixture
    def mocker():
        """Provides a simple mock factory when pytest-mock is not available."""

        class SimpleMocker:
            def MagicMock(self, *args, **kwargs):
                return MagicMock(*args, **kwargs)

            def Mock(self, *args, **kwargs):
                return Mock(*args, **kwargs)

            def patch(self, *args, **kwargs):
                return patch(*args, **kwargs)

            def spy(self, obj, name):
                original = getattr(obj, name)
                mock = MagicMock(wraps=original)
                setattr(obj, name, mock)
                return mock

            def patch_object(self, target, attribute, *args, **kwargs):
                return patch.object(target, attribute, *args, **kwargs)

            def patch_multiple(self, target, **kwargs):
                return patch.multiple(target, **kwargs)

            def call(self, *args, **kwargs):
                return call(*args, **kwargs)

            def ANY(self):
                from unittest.mock import ANY

                return ANY

        return SimpleMocker()


@pytest.fixture
def mock_api_post(mocker):
    """
    Fixture to mock requests.Session.post calls made by the Workbench API client with smarter API simulation.

    This fixture internally tracks project and scan creation to better handle complex API interactions.
    """
    # Store state between API calls
    state = {
        "projects": {},  # Will store project_name -> project_code mapping
        "scans": {},  # Will store (project_code, scan_name) -> scan_id mapping
        "latest_project_code": "PRJ001",
        "latest_scan_id": "100",
        "expected_responses": [],  # The specified mock responses
        "call_log": [],  # Record of all calls made
        "debug_mode": True,  # Enable verbose logging
    }

    def setup_responses(responses):
        """Sets the sequence of mock responses for the test."""
        state["expected_responses"] = responses.copy()
        state["call_log"] = []
        state["projects"] = {}
        state["scans"] = {}

    def get_next_project_code():
        """Generate a unique project code"""
        current = state["latest_project_code"]
        # Increment for next use
        number = int(current[3:]) + 1
        state["latest_project_code"] = f"PRJ{number:03d}"
        return current

    def get_next_scan_id():
        """Generate a unique scan ID"""
        current = state["latest_scan_id"]
        # Increment for next use
        number = int(current) + 1
        state["latest_scan_id"] = str(number)
        return current

    def smart_response(url, payload):
        """Generate appropriate responses based on the action and state"""
        try:
            group = payload.get("group", "")
            action = payload.get("action", "")
            data = payload.get("data", {})

            # Check first if we should use a predefined response based on group/action
            if state["expected_responses"]:
                # For scan status responses, check if the predefined response matches
                if group == "scans" and action == "get_scan_status":
                    for idx, resp in enumerate(state["expected_responses"]):
                        resp_data = resp.get("json_data", {}).get("data", {})
                        if resp_data.get("status") in ["RUNNING", "FINISHED"]:
                            # Found matching scan status response, remove it and return
                            return state["expected_responses"].pop(idx)

            # Common response for projects.list_projects
            if group == "projects" and action == "list_projects":
                project_name = data.get("project_name")
                # If specific project is requested and exists
                if project_name and project_name in state["projects"]:
                    # Return specific project
                    return {
                        "json_data": {
                            "status": "1",
                            "data": [
                                {"name": project_name, "code": state["projects"][project_name]}
                            ],
                        }
                    }
                # If specific project requested but not found
                elif project_name:
                    return {"json_data": {"status": "1", "data": []}}
                # List all projects
                else:
                    projects_list = [
                        {"name": name, "code": code} for name, code in state["projects"].items()
                    ]
                    return {"json_data": {"status": "1", "data": projects_list}}

            # Projects.create - register the project
            elif group == "projects" and action == "create":
                project_name = data.get("project_name")
                if project_name:
                    # Check if project already exists
                    if project_name in state["projects"]:
                        # Return error that project exists
                        return {
                            "json_data": {
                                "status": "0",
                                "message": f"Project '{project_name}' already exists",
                            }
                        }

                    # Create new project
                    project_code = get_next_project_code()
                    state["projects"][project_name] = project_code
                    return {"json_data": {"status": "1", "data": {"project_code": project_code}}}

            # Scans management
            elif group == "scans":
                project_code = data.get("project_code")

                # List scans for project
                if action == "get_all_scans":
                    scans_for_project = []
                    scan_idx = 0

                    for (proj_code, scan_name), scan_id in state["scans"].items():
                        if proj_code == project_code:
                            scans_for_project.append(
                                {"name": scan_name, "code": f"SC{scan_idx}", "id": scan_id}
                            )
                            scan_idx += 1

                    return {"json_data": {"status": "1", "data": scans_for_project}}

                # Create scan
                elif action == "create_webapp_scan":
                    scan_name = data.get("scan_name")
                    scan_id = get_next_scan_id()
                    if project_code and scan_name:
                        state["scans"][(project_code, scan_name)] = scan_id
                        return {"json_data": {"status": "1", "data": {"scan_id": scan_id}}}

                # Get scan status
                elif action == "get_scan_status":
                    scan_id = data.get("scan_id")
                    status_type = data.get("status_type", "SCAN")

                    # For extract archives, always return finished
                    if status_type == "EXTRACT_ARCHIVES":
                        return {
                            "json_data": {
                                "status": "1",
                                "data": {"status": "FINISHED", "is_finished": "1"},
                            }
                        }

                    # For normal scan status, check the scan_id
                    if scan_id and any(scan_id == s_id for (_, _), s_id in state["scans"].items()):
                        # Default to NEW for new scans
                        return {
                            "json_data": {
                                "status": "1",
                                "data": {"status": "NEW", "is_finished": "0"},
                            }
                        }

            # Default for common actions
            if action == "upload_files":
                return {"status_code": 200, "json_data": {"status": "1"}}
            elif action == "extract_archives":
                return {"json_data": {"status": "1"}}
            elif action == "start_scan":
                return {"json_data": {"status": "1"}}
            elif action == "get_pending_files":
                return {"json_data": {"status": "1", "data": {}}}

            # Fallback to predefined responses
            if state["expected_responses"]:
                return state["expected_responses"].pop(0)

            # Default success
            return {"json_data": {"status": "1", "data": {}}}

        except Exception as e:
            print(f"Error in smart_response: {e}")
            import traceback

            traceback.print_exc()
            # When in doubt, return success
            return {"json_data": {"status": "1", "data": {}}}

    def mock_post_side_effect(*args, **kwargs):
        """Side effect function for the mocked requests.Session.post"""
        url = args[0] if args else "unknown_url"
        request_payload = kwargs.get("data", {})

        # Convert string payload to dict if needed
        if isinstance(request_payload, str):
            try:
                import json

                request_payload = json.loads(request_payload)
            except:
                request_payload = {"raw_data": request_payload}

        # Get response based on the request
        if state["expected_responses"]:
            # Try to find a matching predefined response first
            response_config = state["expected_responses"].pop(0)
        else:
            # Generate a smart response based on the request
            response_config = smart_response(url, request_payload)

        # Log the call
        call_info = {"request": request_payload, "response": response_config}
        state["call_log"].append(call_info)

        if state["debug_mode"]:
            print(f"\n[DEBUG] API Call #{len(state['call_log'])}:")
            print(f"[DEBUG] Request URL: {url}")
            print(f"[DEBUG] Request payload: {request_payload}")
            print(f"[DEBUG] Response: {response_config}")

        # Create mock response
        mock_response = MagicMock(spec=requests.Response)
        mock_response.status_code = response_config.get("status_code", 200)
        mock_response.request = MagicMock(
            body=json.dumps(request_payload) if request_payload else None
        )

        headers = response_config.get("headers", {"content-type": "application/json"})
        mock_response.headers = headers

        if headers.get("content-type") == "application/json":
            json_data = response_config.get("json_data", {"status": "1", "data": {}})
            mock_response.json = MagicMock(return_value=json_data)
            mock_response.text = json.dumps(json_data)
            mock_response.content = mock_response.text.encode("utf-8")
        else:
            content_data = response_config.get("content", b"")
            mock_response.content = content_data
            mock_response.text = content_data.decode("utf-8", errors="ignore")
            mock_response.json.side_effect = requests.exceptions.JSONDecodeError("Not JSON", "", 0)

        # Raise for status simulation
        if 400 <= mock_response.status_code < 600:
            mock_response.raise_for_status.side_effect = requests.exceptions.HTTPError(
                f"{mock_response.status_code} Client/Server Error", response=mock_response
            )
        else:
            mock_response.raise_for_status = MagicMock()

        return mock_response

    # Patch requests.Session.post globally for the test
    patcher = patch("requests.Session.post", side_effect=mock_post_side_effect)
    mock_post = patcher.start()

    yield setup_responses  # Provide the setup function to the test

    patcher.stop()  # Stop the patch after the test finishes

    # Debug output after test finishes
    if state["debug_mode"]:
        if state["expected_responses"]:
            print("\nWarning: Not all expected API responses were consumed.")
            print("Remaining responses:", state["expected_responses"])

        print("\n[DEBUG] Final state:")
        print(f"[DEBUG] Projects: {state['projects']}")
        print(f"[DEBUG] Scans: {state['scans']}")
        print(f"[DEBUG] API Calls: {len(state['call_log'])}")


@pytest.fixture(scope="function")
def mock_workbench_api(mocker):
    """Provides a fully mocked WorkbenchClient instance with compositional structure."""

    # Import dataclasses for return values
    from workbench_agent.api.utils.process_waiter import StatusResult, WaitResult

    # Create a mock instance of WorkbenchClient
    mock_client = MagicMock()

    # Mock version compatibility check to avoid API calls during init
    mock_client._check_version_compatibility = MagicMock()

    # --- Mock Resolver Service ---
    mock_client.resolver = MagicMock()
    mock_client.resolver.resolve_project_and_scan.return_value = ("PRJ-MOCK", "SCN-MOCK", False)
    mock_client.resolver.find_project.return_value = "PRJ-MOCK"
    mock_client.resolver.find_scan.return_value = ("SCN-MOCK", 12345)
    mock_client.resolver.resolve_id_reuse.return_value = (None, None)
    mock_client.resolver.ensure_scan_compatible = MagicMock()

    # --- Mock Scans Client ---
    mock_client.scans = MagicMock()
    mock_client.scans.download_content_from_git.return_value = True
    mock_client.scans.remove_uploaded_content.return_value = True
    mock_client.scans.get_information.return_value = {"status": "NEW", "usage": "git"}
    mock_client.scans.get_dependency_analysis_results.return_value = {}
    mock_client.scans.get_scan_identified_licenses.return_value = []
    mock_client.scans.get_all_scans.return_value = []  # Empty list for scan lookup
    mock_client.scans.create.return_value = {"scan_id": 12345}

    # --- Mock Projects Client ---
    mock_client.projects = MagicMock()
    mock_client.projects.list.return_value = []  # Empty list for project lookup
    mock_client.projects.create.return_value = {"project_code": "PRJ-MOCK"}

    # --- Mock Upload Service ---
    mock_client.upload_service = MagicMock()
    mock_client.upload_service.upload_scan_target.return_value = None
    mock_client.upload_service.upload_da_results.return_value = None
    mock_client.upload_service.upload_sbom_file.return_value = None

    # --- Mock Vulnerabilities Client ---
    mock_client.vulnerabilities = MagicMock()
    mock_client.vulnerabilities.list_vulnerabilities.return_value = []

    # --- Mock Status Check Service ---
    mock_client.status_check = MagicMock()
    mock_client.status_check.check_git_clone_status.return_value = StatusResult(
        status="FINISHED", is_finished=True, raw_data={"status": "FINISHED", "is_finished": "1"}
    )
    mock_client.status_check.check_scan_status.return_value = StatusResult(
        status="FINISHED", is_finished=True, raw_data={"status": "FINISHED", "is_finished": "1"}
    )
    mock_client.status_check.check_dependency_analysis_status.return_value = StatusResult(
        status="FINISHED", is_finished=True, raw_data={"status": "FINISHED", "is_finished": "1"}
    )

    # --- Mock Waiting Service ---
    mock_client.waiting = MagicMock()
    mock_client.waiting.wait_for_git_clone.return_value = WaitResult(
        status_data={"status": "FINISHED", "is_finished": "1"}, duration=2.0, success=True
    )
    mock_client.waiting.wait_for_scan.return_value = WaitResult(
        status_data={"status": "FINISHED", "is_finished": "1"}, duration=10.0, success=True
    )
    mock_client.waiting.wait_for_da.return_value = WaitResult(
        status_data={"status": "FINISHED", "is_finished": "1"}, duration=5.0, success=True
    )

    # --- Mock Scan Operations Service ---
    mock_client.scan_operations = MagicMock()
    mock_client.scan_operations.run_scan = MagicMock()
    mock_client.scan_operations.run_da_only = MagicMock()

    # --- Mock Results Service ---
    mock_client.results = MagicMock()
    mock_client.results.fetch_results.return_value = {
        "dependency_analysis": {},
        "kb_licenses": [],
        "vulnerabilities": [],
    }
    mock_client.results.links = MagicMock()

    # --- Mock Reports Service ---
    mock_client.reports = MagicMock()

    # --- Mock Internal Client (for version check) ---
    mock_client.internal = MagicMock()
    mock_client.internal.get_config.return_value = {"version": "24.3.0"}

    # Patch WorkbenchClient to return our mock when instantiated
    # Use patch.object with context manager for proper cleanup
    import workbench_agent.api.workbench_client

    # Store the original __new__ before patching
    original_new = workbench_agent.api.workbench_client.WorkbenchClient.__new__

    def mock_new(cls, *args, **kwargs):
        """Return the mock client instead of creating a real instance."""
        if cls == workbench_agent.api.workbench_client.WorkbenchClient:
            return mock_client
        # For other classes, use the original __new__
        return original_new(cls, *args, **kwargs)

    # Patch both where it's imported and where it's defined
    # Use context managers to ensure proper cleanup
    with (
        patch.object(
            workbench_agent.api.workbench_client.WorkbenchClient, "__new__", side_effect=mock_new
        ),
        patch("workbench_agent.main.WorkbenchClient", return_value=mock_client),
    ):
        yield mock_client
