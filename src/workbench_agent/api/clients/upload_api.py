"""
UploadsClient - Handles low-level file upload operations to Workbench.

This client provides:
- Low-level file upload operations (upload_file)
- Chunked upload support with progress tracking
- Standard upload support

The client handles the actual HTTP communication with the Workbench API.
Business logic (preparing files, setting headers based on context) is handled
by UploadService in the services layer.

Example:
        >>> uploads = UploadsClient(base_api)
        >>> headers = {"FOSSID-SCAN-CODE": "...", "FOSSID-FILE-NAME": "..."}
        >>> uploads.upload_file("/path/to/file.zip", headers)
"""

import io
import logging
import os
import time
from typing import Generator

import requests

from workbench_agent.api.exceptions import ApiError, NetworkError
from workbench_agent.exceptions import FileSystemError

logger = logging.getLogger("workbench-agent")


class UploadsClient:
    """
    Uploads API client using composition pattern.

    Handles low-level HTTP operations for file uploads:
    - File upload with automatic chunking for large files
    - Progress tracking
    - Retry logic for chunked uploads

    This client focuses on the HTTP communication layer. For business logic
    (preparing files, setting headers based on upload type), use UploadService.

    Example:
        >>> uploads = UploadsClient(base_api)
        >>> headers = {
        ...     "FOSSID-SCAN-CODE": base64.b64encode(scan_code.encode()).decode(),
        ...     "FOSSID-FILE-NAME": base64.b64encode(filename.encode()).decode(),
        ... }
        >>> uploads.upload_file_standard("/path/to/file.zip", headers)
        >>> # Or for large files:
        >>> uploads.upload_file_chunked("/path/to/large_file.zip", headers)
    """

    # Upload Constants (HTTP implementation details)
    CHUNK_SIZE = 5 * 1024 * 1024  # 5MB
    MAX_CHUNK_RETRIES = 3
    PROGRESS_UPDATE_INTERVAL = 20  # Percent
    SMALL_FILE_CHUNK_THRESHOLD = 5  # Always show progress for ≤5 chunks

    def __init__(self, base_api):
        """
        Initialize UploadsClient.

        Args:
            base_api: BaseAPI instance for HTTP requests
        """
        self._api = base_api
        logger.debug("UploadsClient initialized")

    # ===== PUBLIC UPLOAD METHODS =====

    def upload_file_standard(self, file_path: str, headers: dict) -> None:
        """
        Upload a file using standard (non-chunked) HTTP POST.

        This is the low-level upload method for standard uploads. Business logic
        (deciding when to use chunked vs standard, preparing files, setting headers)
        should be handled by the service layer.

        Args:
            file_path: Path to the file to upload
            headers: HTTP headers for the upload (must include FOSSID-SCAN-CODE
                and FOSSID-FILE-NAME, both base64 encoded)

        Raises:
            FileSystemError: If file doesn't exist or can't be read
            ApiError: If upload fails
            NetworkError: If there are network issues

        Example:
            >>> headers = {
            ...     "FOSSID-SCAN-CODE": base64.b64encode(scan_code.encode()).decode(),
            ...     "FOSSID-FILE-NAME": base64.b64encode(filename.encode()).decode(),
            ...     "Accept": "*/*",
            ... }
            >>> uploads.upload_file_standard("/path/to/file.zip", headers)
        """
        if not os.path.exists(file_path):
            raise FileSystemError(f"File not found: {file_path}")

        filename = os.path.basename(file_path)
        file_size = os.path.getsize(file_path)

        logger.debug(
            f"Starting standard upload for file: {filename} ({file_size / (1024 * 1024):.2f} MB)"
        )

        try:
            with open(file_path, "rb") as f:
                file_data = f.read()

            # Use BaseAPI's session but with HTTP Basic Auth
            response = requests.post(
                self._api.api_url,
                headers=headers,
                data=file_data,
                auth=(self._api.api_user, self._api.api_token),
                timeout=1800,
            )

            logger.debug(
                f"Standard upload response code: {response.status_code}"
            )
            logger.debug(f"Standard upload response: {response.text[:500]}")

            # Check for errors
            if response.status_code != 200:
                raise ApiError(
                    f"Upload failed with status {response.status_code}: {response.text}"
                )

            # Parse response
            try:
                response_data = response.json()
                status = str(response_data.get("status", "0"))
                if status != "1":
                    error_msg = response_data.get("error", "Unknown error")
                    raise ApiError(f"Upload failed: {error_msg}")
            except ValueError:
                # Some successful uploads may not return JSON
                logger.debug("Standard upload completed (no JSON response)")

        except requests.exceptions.RequestException as e:
            logger.error(f"Network error during standard upload: {e}")
            raise NetworkError(f"Network error during upload: {e}") from e
        except Exception as e:
            if isinstance(e, (ApiError, NetworkError)):
                raise
            logger.error(f"Unexpected error during standard upload: {e}")
            raise ApiError(f"Unexpected error during upload: {e}") from e

        logger.info(f"Upload complete for {filename}")

    def upload_file_chunked(self, file_path: str, headers: dict) -> None:
        """
        Upload a file using chunked HTTP POST.

        This is the low-level upload method for chunked uploads. Business logic
        (deciding when to use chunked vs standard, preparing files, setting headers)
        should be handled by the service layer.

        Args:
            file_path: Path to the file to upload
            headers: HTTP headers for the upload (must include FOSSID-SCAN-CODE
                and FOSSID-FILE-NAME, both base64 encoded)

        Raises:
            FileSystemError: If file doesn't exist or can't be read
            ApiError: If upload fails
            NetworkError: If there are network issues

        Example:
            >>> headers = {
            ...     "FOSSID-SCAN-CODE": base64.b64encode(scan_code.encode()).decode(),
            ...     "FOSSID-FILE-NAME": base64.b64encode(filename.encode()).decode(),
            ...     "Accept": "*/*",
            ... }
            >>> uploads.upload_file_chunked("/path/to/large_file.zip", headers)
        """
        if not os.path.exists(file_path):
            raise FileSystemError(f"File not found: {file_path}")

        filename = os.path.basename(file_path)
        file_size = os.path.getsize(file_path)

        logger.debug(
            f"Starting chunked upload for file: {filename} ({file_size / (1024 * 1024):.2f} MB)"
        )

        total_chunks = (file_size + self.CHUNK_SIZE - 1) // self.CHUNK_SIZE
        logger.debug(
            f"Chunked upload: {total_chunks} chunks of {self.CHUNK_SIZE / (1024 * 1024):.2f} MB each"
        )

        # Add chunked upload headers (required by Workbench API)
        headers_copy = headers.copy()
        headers_copy["Transfer-Encoding"] = "chunked"
        headers_copy["Content-Type"] = "application/octet-stream"
        logger.debug(
            "Added Transfer-Encoding: chunked header for chunked upload"
        )

        show_progress = total_chunks <= self.SMALL_FILE_CHUNK_THRESHOLD
        last_printed_progress = 0

        try:
            with open(file_path, "rb") as f:
                for i, chunk in enumerate(
                    self._read_in_chunks(f, self.CHUNK_SIZE), start=1
                ):
                    logger.debug(f"Uploading chunk {i}/{total_chunks}")
                    self._upload_single_chunk(chunk, i, headers_copy)

                    # Progress tracking
                    progress = int((i / total_chunks) * 100)
                    if (
                        show_progress
                        or progress
                        >= last_printed_progress
                        + self.PROGRESS_UPDATE_INTERVAL
                    ):
                        print(f"Upload progress: {progress}%")
                        last_printed_progress = progress

        except Exception as e:
            logger.error(f"Error during chunked upload: {e}")
            raise

        logger.info(f"Upload complete for {filename}")

    # ===== INTERNAL UPLOAD HELPERS =====

    def _read_in_chunks(
        self, file_object: io.BufferedReader, chunk_size: int = 5 * 1024 * 1024
    ) -> Generator[bytes, None, None]:
        """
        Generator to read a file piece by piece.

        Args:
            file_object: The file object to read
            chunk_size: Size of each chunk (default: 5MB)

        Yields:
            Chunks of file data
        """
        while True:
            data = file_object.read(chunk_size)
            if not data:
                break
            yield data

    def _upload_single_chunk(
        self, chunk: bytes, chunk_number: int, headers: dict
    ) -> None:
        """
        Upload a single chunk with retry logic.

        Args:
            chunk: The chunk data to upload
            chunk_number: The chunk number (for logging)
            headers: Headers for the upload request

        Raises:
            NetworkError: If there are network issues after all retries
            ApiError: If the upload fails after all retries
        """
        retry_count = 0

        while retry_count <= self.MAX_CHUNK_RETRIES:
            try:
                # Create request manually to remove Content-Length header
                req = requests.Request(
                    "POST",
                    self._api.api_url,
                    headers=headers,
                    data=chunk,
                    auth=(self._api.api_user, self._api.api_token),
                )

                # Reuse BaseAPI session for connection pooling and keepalive
                # This avoids expensive TLS handshakes for each chunk
                prepped = self._api.session.prepare_request(req)
                if "Content-Length" in prepped.headers:
                    del prepped.headers["Content-Length"]
                    logger.debug(
                        f"Removed Content-Length header for chunk {chunk_number}"
                    )

                # Send the request using the shared session
                resp_chunk = self._api.session.send(prepped, timeout=1800)

                # Validate response
                self._validate_chunk_response(
                    resp_chunk, chunk_number, retry_count
                )
                return  # Success!

            except requests.exceptions.RequestException as e:
                if retry_count < self.MAX_CHUNK_RETRIES:
                    logger.warning(
                        f"Chunk {chunk_number} network error (attempt {retry_count + 1}/{self.MAX_CHUNK_RETRIES + 1}): {e}"
                    )
                    retry_count += 1
                    time.sleep(2)  # Longer delay for network issues
                    continue
                else:
                    logger.error(
                        f"Chunk {chunk_number} failed after {self.MAX_CHUNK_RETRIES + 1} attempts: {e}"
                    )
                    raise NetworkError(
                        f"Network error for chunk {chunk_number} after {self.MAX_CHUNK_RETRIES + 1} attempts: {e}"
                    )

    def _validate_chunk_response(
        self, response: requests.Response, chunk_number: int, retry_count: int
    ) -> None:
        """
        Validate the response from a chunk upload.

        Args:
            response: The HTTP response
            chunk_number: The chunk number
            retry_count: Current retry attempt

        Raises:
            ApiError: If validation fails and retries exhausted
        """
        if response.status_code != 200:
            if retry_count < self.MAX_CHUNK_RETRIES:
                logger.warning(
                    f"Chunk {chunk_number} returned status {response.status_code}, retrying... "
                    f"(attempt {retry_count + 1}/{self.MAX_CHUNK_RETRIES + 1})"
                )
                time.sleep(1)
                raise ApiError(
                    f"Chunk {chunk_number} upload failed with status {response.status_code}"
                )
            else:
                logger.error(
                    f"Chunk {chunk_number} failed after {self.MAX_CHUNK_RETRIES + 1} attempts "
                    f"with status {response.status_code}"
                )
                raise ApiError(
                    f"Chunk {chunk_number} upload failed with status {response.status_code} "
                    f"after {self.MAX_CHUNK_RETRIES + 1} attempts"
                )

        logger.debug(f"Chunk {chunk_number} uploaded successfully")
