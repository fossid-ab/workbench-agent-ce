"""Path encoding helpers for Workbench files_and_folders API calls."""

import base64


def encode_path(path: str) -> str:
    """
    Base64-encode a relative file or folder path for the Workbench API.

    Most ``files_and_folders`` actions expect an encoded path. The exception is
    ``remove_component_identification``, which sends a plain relative path
    (see ``FilesAndFoldersClient.remove_component_identification``).

    Args:
        path: Relative path within the scan (UTF-8).

    Returns:
        Base64-encoded path string (no padding issues; standard b64).
    """
    return base64.b64encode(path.encode("utf-8")).decode("ascii")


def decode_path(encoded: str) -> str:
    """
    Decode a base64-encoded path returned by or sent to the API.

    Args:
        encoded: Base64 path from the API.

    Returns:
        Decoded relative path.
    """
    return base64.b64decode(encoded.encode("ascii")).decode("utf-8")
