"""Tests for .fossid file validation in blind-scan."""

import json

import pytest

from workbench_agent.exceptions import ValidationError
from workbench_agent.handlers.blind_scan import validate_fossid_file


def _write_valid_entry(path) -> None:
    """Write a single minimally-valid JSONL entry to ``path``."""
    entry = {
        "path": "src/main.c",
        "size": 1234,
        "hashes_ffm": [{"format": 1, "data": "deadbeef"}],
    }
    path.write_text(json.dumps(entry) + "\n", encoding="utf-8")


class TestValidateFossidFileEncoding:
    """The UTF-8 charset check on pre-generated .fossid files."""

    def test_accepts_valid_utf8(self, tmp_path):
        fossid = tmp_path / "ok.fossid"
        _write_valid_entry(fossid)
        validate_fossid_file(str(fossid))

    def test_accepts_utf8_with_non_ascii_path(self, tmp_path):
        """Non-ASCII bytes are fine as long as they are valid UTF-8."""
        entry = {
            "path": "src/café/módulo.c",
            "size": 42,
            "hashes_ffm": [{"format": 1, "data": "abc"}],
        }
        fossid = tmp_path / "utf8.fossid"
        fossid.write_text(json.dumps(entry) + "\n", encoding="utf-8")
        validate_fossid_file(str(fossid))

    def test_rejects_non_utf8_file_with_clear_error(self, tmp_path):
        """A Latin-1-encoded file should be rejected with a UTF-8 message."""
        fossid = tmp_path / "latin1.fossid"
        fossid.write_bytes(
            json.dumps(
                {
                    "path": "src/main.c",
                    "size": 1,
                    "hashes_ffm": [{"format": 1, "data": "a"}],
                }
            ).encode("utf-8")
            + b"\n"
            + b"\xff\xfe garbage non-utf8 bytes"
        )

        with pytest.raises(ValidationError, match="not valid UTF-8"):
            validate_fossid_file(str(fossid))
