"""Tests for the CLI-layer log redaction helper."""

from types import SimpleNamespace

import pytest

from workbench_agent.utilities.redaction import (
    REDACTED_VALUE,
    SENSITIVE_FIELDS,
    SENSITIVE_SUFFIXES,
    redact_cli_args_for_logging,
)


# --- Module constants ---


def test_redacted_value_is_unified_placeholder():
    """The CLI layer uses the same human-readable placeholder as the API."""
    assert REDACTED_VALUE == "***REDACTED***"


def test_sensitive_fields_covers_known_names():
    """Guard against accidental removal of well-known sensitive names."""
    expected = {
        "api_key",
        "api_token",
        "authorization",
        "key",
        "password",
        "secret",
        "token",
    }
    assert expected.issubset(SENSITIVE_FIELDS)


def test_sensitive_suffixes_include_common_secret_endings():
    """Suffix policy keeps future *_token / *_key flags safe by default."""
    for suffix in ("_token", "_password", "_secret", "_key"):
        assert suffix in SENSITIVE_SUFFIXES


# --- redact_cli_args_for_logging ---


class TestRedactCliArgsForLogging:
    """argparse Namespace redaction used by the CLI entrypoint."""

    def test_redacts_api_token(self):
        ns = SimpleNamespace(
            command="scan",
            api_token="secret-value",
            api_user="user@example.com",
        )
        out = redact_cli_args_for_logging(ns)
        assert out["api_token"] == REDACTED_VALUE
        assert out["api_user"] == "user@example.com"
        assert out["command"] == "scan"

    def test_redacts_api_key_by_exact_match(self):
        """Future --api-key flag should be redacted via SENSITIVE_FIELDS."""
        ns = SimpleNamespace(api_key="abc", normal="ok")
        out = redact_cli_args_for_logging(ns)
        assert out["api_key"] == REDACTED_VALUE
        assert out["normal"] == "ok"

    def test_redacts_suffix_style_secrets(self):
        ns = SimpleNamespace(
            oauth_refresh_token="x",
            db_password="y",
            client_secret="z",
            signing_key="k",
            normal_field="ok",
        )
        out = redact_cli_args_for_logging(ns)
        assert out["oauth_refresh_token"] == REDACTED_VALUE
        assert out["db_password"] == REDACTED_VALUE
        assert out["client_secret"] == REDACTED_VALUE
        assert out["signing_key"] == REDACTED_VALUE
        assert out["normal_field"] == "ok"

    def test_leaves_none_values_unchanged(self):
        """Preserves the 'flag was not provided' signal."""
        ns = SimpleNamespace(api_token=None, other="v")
        out = redact_cli_args_for_logging(ns)
        assert out["api_token"] is None
        assert out["other"] == "v"

    def test_does_not_mutate_input_namespace(self):
        ns = SimpleNamespace(api_token="secret")
        redact_cli_args_for_logging(ns)
        assert ns.api_token == "secret"

    @pytest.mark.parametrize(
        "field",
        ["API_TOKEN", "Api_Token", "OAUTH_REFRESH_TOKEN"],
    )
    def test_case_insensitive_field_matching(self, field):
        ns = SimpleNamespace(**{field: "value", "safe": "ok"})
        out = redact_cli_args_for_logging(ns)
        assert out[field] == REDACTED_VALUE
        assert out["safe"] == "ok"
