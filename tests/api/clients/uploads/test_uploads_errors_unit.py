"""Tests for upload response validation helpers."""

import pytest
import requests

from workbench_agent.api.clients.uploads.errors import (
    validate_chunk_upload_response,
    validate_standard_upload_response,
)
from workbench_agent.api.exceptions import ApiError


def test_validate_standard_upload_accepts_http_200_without_json():
    response = requests.Response()
    response.status_code = 200
    response._content = b"OK"
    validate_standard_upload_response(response)


def test_validate_standard_upload_rejects_failed_status():
    response = requests.Response()
    response.status_code = 200
    response._content = b'{"status":"0","error":"bad"}'
    with pytest.raises(ApiError, match="Upload failed"):
        validate_standard_upload_response(response)


def test_validate_chunk_upload_retries_on_non_200():
    response = requests.Response()
    response.status_code = 500
    with pytest.raises(ApiError, match="Chunk 2 upload failed"):
        validate_chunk_upload_response(
            response, 2, 0, max_retries=3
        )
