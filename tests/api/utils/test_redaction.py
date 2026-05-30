"""Tests for the API-layer log redaction helpers."""

import json

from workbench_agent.api.utils.redaction import (
    REDACTED_VALUE,
    SENSITIVE_FIELDS,
    SENSITIVE_SUFFIXES,
    redact_response_text,
    redact_sensitive_data,
    redact_text,
)


# --- Module constants ---


def test_redacted_value_is_unified_placeholder():
    """The canonical placeholder is the human-readable one, not bare stars."""
    assert REDACTED_VALUE == "***REDACTED***"


def test_sensitive_fields_covers_known_names():
    """Guard against accidental removal of the well-known sensitive names."""
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


# --- redact_sensitive_data ---


class TestRedactSensitiveData:
    """Behaviour of the dict/list redactor used for payloads and responses."""

    def test_redacts_top_level_sensitive_fields(self):
        payload = {
            "username": "alice",
            "key": "secret-key",
            "token": "secret-token",
            "password": "hunter2",
        }
        result = redact_sensitive_data(payload)
        assert result["username"] == "alice"
        assert result["key"] == REDACTED_VALUE
        assert result["token"] == REDACTED_VALUE
        assert result["password"] == REDACTED_VALUE

    def test_redacts_nested_dicts(self):
        payload = {"data": {"username": "alice", "key": "secret"}}
        result = redact_sensitive_data(payload)
        assert result["data"]["username"] == "alice"
        assert result["data"]["key"] == REDACTED_VALUE

    def test_redacts_inside_list_of_dicts(self):
        payload = {
            "items": [
                {"name": "one", "token": "abc"},
                {"name": "two", "secret": "xyz"},
            ]
        }
        result = redact_sensitive_data(payload)
        assert result["items"][0]["token"] == REDACTED_VALUE
        assert result["items"][0]["name"] == "one"
        assert result["items"][1]["secret"] == REDACTED_VALUE

    def test_field_match_is_case_insensitive(self):
        """Server-supplied keys can arrive in any case; redact regardless."""
        payload = {"API_TOKEN": "abc", "Authorization": "Bearer x"}
        result = redact_sensitive_data(payload)
        assert result["API_TOKEN"] == REDACTED_VALUE
        assert result["Authorization"] == REDACTED_VALUE

    def test_suffix_match_redacts_unknown_secret_fields(self):
        """A new *_token field should be redacted without code changes."""
        payload = {"refresh_token": "abc", "api_key": "def", "name": "ok"}
        result = redact_sensitive_data(payload)
        assert result["refresh_token"] == REDACTED_VALUE
        assert result["api_key"] == REDACTED_VALUE
        assert result["name"] == "ok"

    def test_leaves_non_sensitive_values_untouched(self):
        payload = {"name": "alice", "count": 3, "active": True}
        assert redact_sensitive_data(payload) == payload

    def test_returns_scalars_unchanged(self):
        assert redact_sensitive_data("hello") == "hello"
        assert redact_sensitive_data(42) == 42
        assert redact_sensitive_data(None) is None

    def test_does_not_mutate_input(self):
        payload = {"key": "secret", "nested": {"token": "t"}}
        redact_sensitive_data(payload)
        assert payload == {"key": "secret", "nested": {"token": "t"}}


# --- redact_text ---


class TestRedactText:
    """Substring replacement used for non-JSON response bodies."""

    def test_replaces_token_substring(self):
        text = "Hello secret-token world"
        assert (
            redact_text(text, "secret-token")
            == f"Hello {REDACTED_VALUE} world"
        )

    def test_replaces_multiple_sensitive_values(self):
        text = "user=alice pwd=hunter2 token=abc"
        result = redact_text(text, "hunter2", "abc")
        assert "hunter2" not in result
        assert "abc" not in result
        assert result.count(REDACTED_VALUE) == 2

    def test_empty_sensitive_value_does_not_pollute_text(self):
        """Unset token must not turn empty positions into the placeholder."""
        text = "no secrets here"
        assert redact_text(text, "") == text

    def test_returns_text_unchanged_when_no_sensitive_values(self):
        assert redact_text("plain text") == "plain text"


# --- redact_response_text ---


class TestRedactResponseText:
    """Combined JSON-aware and substring-fallback response redactor."""

    def test_parses_json_and_redacts_by_field_name(self):
        body = json.dumps({"data": {"key": "k", "user": "alice"}})
        out = json.loads(redact_response_text(body, "k"))
        assert out["data"]["key"] == REDACTED_VALUE
        assert out["data"]["user"] == "alice"

    def test_falls_back_to_text_replace_for_non_json(self):
        body = "plain text containing supersecret value"
        result = redact_response_text(body, "supersecret")
        assert "supersecret" not in result
        assert REDACTED_VALUE in result

    def test_handles_invalid_json_gracefully(self):
        body = "{not valid json: secret-token}"
        result = redact_response_text(body, "secret-token")
        assert "secret-token" not in result
        assert REDACTED_VALUE in result
