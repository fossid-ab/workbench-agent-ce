"""Tests for files_and_folders path encoding."""

from workbench_agent.api.clients.files_and_folders import FilesAndFoldersClient
from workbench_agent.api.clients.files_and_folders.helpers import (
    decode_path,
    encode_path,
)


def test_encode_path_simple():
    assert encode_path("src/main.c") == "c3JjL21haW4uYw=="
    assert FilesAndFoldersClient.encode_path("src/main.c") == "c3JjL21haW4uYw=="


def test_encode_path_roundtrip():
    path = "OpenFastPath/src/ofp_uma.c"
    assert decode_path(encode_path(path)) == path
    assert FilesAndFoldersClient.decode_path(
        FilesAndFoldersClient.encode_path(path)
    ) == path


def test_encode_path_unicode():
    path = "Files with Snippets/über.c"
    encoded = encode_path(path)
    assert decode_path(encoded) == path


def test_encode_path_empty():
    assert encode_path("") == ""


def test_encode_path_nested():
    path = "a/b/c/d/file.txt"
    assert decode_path(encode_path(path)) == path
