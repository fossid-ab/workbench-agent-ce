"""UploadsClient - raw HTTP upload transport for Workbench."""

from __future__ import annotations

import io
import logging
import os
import time
from typing import Generator

import requests

from workbench_agent.api.exceptions import ApiError, NetworkError
from workbench_agent.exceptions import FileSystemError

from . import errors

logger = logging.getLogger("workbench-agent")


class UploadsClient:
    """
    Uploads API client (raw HTTP POST to ``api.php``).

    Request headers and upload types: ``clients/uploads/schema.md``.
    Transport quirks: ``clients/uploads/quirks.md``.

    Business logic (header building, chunked vs standard) lives in
    ``UploadService``.

    Example:
        >>> uploads = UploadsClient(base_api)
        >>> headers = {
        ...     "FOSSID-SCAN-CODE": base64.b64encode(scan_code.encode()).decode(),
        ...     "FOSSID-FILE-NAME": base64.b64encode(filename.encode()).decode(),
        ... }
        >>> uploads.upload_file_standard("/path/to/file.zip", headers)
    """

    CHUNK_SIZE = 7 * 1024 * 1024  # 7MB
    MAX_CHUNK_RETRIES = 3
    PROGRESS_UPDATE_INTERVAL = 20
    SMALL_FILE_CHUNK_THRESHOLD = 5
    UPLOAD_TIMEOUT_SECONDS = 1800

    def __init__(self, base_api):
        self._api = base_api
        logger.debug("UploadsClient initialized")

    def upload_file_standard(self, file_path: str, headers: dict) -> None:
        """Upload a file in a single HTTP POST body."""
        if not os.path.exists(file_path):
            raise FileSystemError(f"File not found: {file_path}")

        filename = os.path.basename(file_path)
        file_size = os.path.getsize(file_path)
        logger.debug(
            "Uploading %s (%.2f MB)", filename, file_size / (1024 * 1024)
        )

        try:
            with open(file_path, "rb") as f:
                file_data = f.read()

            response = requests.post(
                self._api.api_url,
                headers=headers,
                data=file_data,
                auth=(self._api.api_user, self._api.api_token),
                timeout=self.UPLOAD_TIMEOUT_SECONDS,
            )
            logger.debug(
                "Standard upload response code: %s", response.status_code
            )
            logger.debug(
                "Standard upload response: %s", response.text[:500]
            )
            errors.validate_standard_upload_response(response)
        except requests.exceptions.RequestException as e:
            logger.error("Network error during standard upload: %s", e)
            raise NetworkError(f"Network error during upload: {e}") from e
        except Exception as e:
            if isinstance(e, (ApiError, NetworkError)):
                raise
            logger.error("Unexpected error during standard upload: %s", e)
            raise ApiError(f"Unexpected error during upload: {e}") from e

        logger.info("Upload complete for %s", filename)

    def upload_file_chunked(self, file_path: str, headers: dict) -> None:
        """Upload a file using chunked ``Transfer-Encoding``."""
        if not os.path.exists(file_path):
            raise FileSystemError(f"File not found: {file_path}")

        filename = os.path.basename(file_path)
        file_size = os.path.getsize(file_path)
        logger.debug(
            "Starting chunked upload for %s (%.2f MB)",
            filename,
            file_size / (1024 * 1024),
        )

        total_chunks = (file_size + self.CHUNK_SIZE - 1) // self.CHUNK_SIZE
        headers_copy = headers.copy()
        headers_copy["Transfer-Encoding"] = "chunked"
        headers_copy["Content-Type"] = "application/octet-stream"

        show_progress = total_chunks <= self.SMALL_FILE_CHUNK_THRESHOLD
        last_printed_progress = 0

        try:
            with open(file_path, "rb") as f:
                for i, chunk in enumerate(
                    self._read_in_chunks(f, self.CHUNK_SIZE), start=1
                ):
                    logger.debug("Uploading chunk %s/%s", i, total_chunks)
                    self._upload_single_chunk(chunk, i, headers_copy)

                    progress = int((i / total_chunks) * 100)
                    if (
                        show_progress
                        or progress
                        >= last_printed_progress
                        + self.PROGRESS_UPDATE_INTERVAL
                    ):
                        print(f"Upload progress: {progress}%")
                        last_printed_progress = progress
        except Exception:
            logger.error("Error during chunked upload for %s", filename)
            raise

        logger.info("Upload complete for %s", filename)

    def _read_in_chunks(
        self,
        file_object: io.BufferedReader,
        chunk_size: int,
    ) -> Generator[bytes, None, None]:
        while True:
            data = file_object.read(chunk_size)
            if not data:
                break
            yield data

    def _upload_single_chunk(
        self, chunk: bytes, chunk_number: int, headers: dict
    ) -> None:
        retry_count = 0

        while retry_count <= self.MAX_CHUNK_RETRIES:
            try:
                req = requests.Request(
                    "POST",
                    self._api.api_url,
                    headers=headers,
                    data=chunk,
                    auth=(self._api.api_user, self._api.api_token),
                )
                prepped = self._api.session.prepare_request(req)
                if "Content-Length" in prepped.headers:
                    del prepped.headers["Content-Length"]

                resp_chunk = self._api.session.send(
                    prepped, timeout=self.UPLOAD_TIMEOUT_SECONDS
                )
                errors.validate_chunk_upload_response(
                    resp_chunk,
                    chunk_number,
                    retry_count,
                    max_retries=self.MAX_CHUNK_RETRIES,
                )
                return

            except ApiError:
                retry_count += 1
                if retry_count <= self.MAX_CHUNK_RETRIES:
                    time.sleep(1)
                    continue
                raise
            except requests.exceptions.RequestException as e:
                if retry_count < self.MAX_CHUNK_RETRIES:
                    logger.warning(
                        "Chunk %s network error (attempt %s/%s): %s",
                        chunk_number,
                        retry_count + 1,
                        self.MAX_CHUNK_RETRIES + 1,
                        e,
                    )
                    retry_count += 1
                    time.sleep(2)
                    continue
                raise NetworkError(
                    f"Network error for chunk {chunk_number} after "
                    f"{self.MAX_CHUNK_RETRIES + 1} attempts: {e}"
                ) from e
