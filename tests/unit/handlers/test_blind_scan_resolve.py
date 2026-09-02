"""Tests for FossID Toolbox path resolution in blind-scan."""

from unittest.mock import patch

import pytest

from workbench_agent.exceptions import ValidationError
from workbench_agent.utilities.toolbox_wrapper import resolve_fossid_toolbox_path


class TestResolveFossidToolboxPath:
    def test_returns_configured_path_unchanged(self):
        path = "/opt/fossid/bin/fossid-toolbox"
        assert resolve_fossid_toolbox_path(path) == path

    def test_uses_path_lookup_when_not_configured(self):
        with patch(
            "workbench_agent.utilities.toolbox_wrapper.shutil.which",
            return_value="/usr/local/bin/fossid-toolbox",
        ) as mock_which:
            expected = "/usr/local/bin/fossid-toolbox"
            assert resolve_fossid_toolbox_path(None) == expected
            mock_which.assert_called_once_with("fossid-toolbox")

    def test_raises_when_not_on_path(self):
        with patch(
            "workbench_agent.utilities.toolbox_wrapper.shutil.which",
            return_value=None,
        ):
            with pytest.raises(ValidationError, match="fossid-toolbox not found"):
                resolve_fossid_toolbox_path(None)
