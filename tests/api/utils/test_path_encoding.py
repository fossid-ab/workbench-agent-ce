"""Tests for workbench_agent.api.utils.path_encoding."""

import pytest

from workbench_agent.api.utils.path_encoding import decode_path, encode_path


def test_encode_path_simple():
    assert encode_path("src/main.c") == "c3JjL21haW4uYw=="


def test_encode_path_roundtrip():
    path = "Files with Snippets/kernel-snippet.c"
    assert decode_path(encode_path(path)) == path


def test_encode_path_unicode():
    path = "café/file.txt"
    encoded = encode_path(path)
    assert decode_path(encoded) == path


def test_encode_path_empty():
    assert encode_path("") == ""


def test_encode_path_nested():
    path = "OpenFastPath/src/ofp_subr_hash.c"
    assert decode_path(encode_path(path)) == path
