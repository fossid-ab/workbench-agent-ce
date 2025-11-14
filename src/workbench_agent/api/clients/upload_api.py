"""
UploadsClient - Handles file and directory uploads to Workbench.

This client provides:
- Upload scan targets (files/directories)
- Upload dependency analysis results
- Upload SBOM files
- Chunked upload support with progress tracking
"""
import base64
import io
import json
import logging
import os
import shutil
import time
from typing import Generator

import requests

from workbench_agent.exceptions import ApiError, FileSystemError, NetworkError, WorkbenchAgentError
from workbench_agent.utilities.prep_upload_archive import UploadArchivePrep

logger = logging.getLogger("workbench-agent")


class UploadsClient:
    """
    Uploads API client using composition pattern.
    
    Handles all file upload operations including:
    - Scan target uploads (files and directories)
    - Dependency analysis result uploads
    - SBOM file uploads
    - Chunked uploads with progress tracking
    
    Example:
        >>> uploads = UploadsClient(base_api)
        >>> uploads.upload_scan_target(scan_code, "/path/to/source")
        >>> uploads.upload_dependency_analysis_results(scan_code, "results.json")
    """
    
    # Upload Constants
    CHUNKED_UPLOAD_THRESHOLD = 16 * 1024 * 1024  # 16MB
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
    
    def upload_scan_target(self, scan_code: str, path: str):
        """
        Uploads a file or directory (as zip) to a scan.
        
        Args:
            scan_code: Code of the scan to upload to
            path: Path to the file or directory to upload
            
        Raises:
            FileSystemError: If path doesn't exist
            ApiError: If upload fails
            NetworkError: If there are network issues
        """
        if not os.path.exists(path):
            raise FileSystemError(f"Path does not exist: {path}")
        
        archive_path = None
        temp_dir = None
        
        try:
            upload_path = path
            if os.path.isdir(path):
                print("The path provided is a directory. Compressing for upload...")
                archive_path = UploadArchivePrep.create_zip_archive(path)
                upload_path = archive_path
                temp_dir = os.path.dirname(archive_path)
            
            upload_basename = os.path.basename(upload_path)
            name_b64 = base64.b64encode(upload_basename.encode()).decode("utf-8")
            scan_code_b64 = base64.b64encode(scan_code.encode()).decode("utf-8")
            
            headers = {
                "FOSSID-SCAN-CODE": scan_code_b64,
                "FOSSID-FILE-NAME": name_b64,
                "Accept": "*/*",
            }
            
            self._perform_upload(upload_path, headers)
        
        except (ApiError, NetworkError) as e:
            # Re-raise known exceptions
            raise
        except Exception as e:
            # Wrap unexpected exceptions
            raise WorkbenchAgentError(
                f"An unexpected error occurred during the upload process: {e}"
            ) from e
        
        finally:
            if archive_path and os.path.exists(archive_path):
                os.remove(archive_path)
            if temp_dir and os.path.exists(temp_dir):
                shutil.rmtree(temp_dir, ignore_errors=True)
    
    def upload_dependency_analysis_results(self, scan_code: str, path: str):
        """
        Uploads a dependency analysis result file to a scan.
        
        Args:
            scan_code: Code of the scan to upload to
            path: Path to the dependency analysis results file
            
        Raises:
            FileSystemError: If file doesn't exist
            ApiError: If upload fails
            NetworkError: If there are network issues
        """
        if not os.path.exists(path) or not os.path.isfile(path):
            raise FileSystemError(f"Dependency analysis results file does not exist: {path}")
        
        upload_basename = os.path.basename(path)
        name_b64 = base64.b64encode(upload_basename.encode()).decode("utf-8")
        scan_code_b64 = base64.b64encode(scan_code.encode()).decode("utf-8")
        
        headers = {
            "FOSSID-SCAN-CODE": scan_code_b64,
            "FOSSID-FILE-NAME": name_b64,
            "FOSSID-UPLOAD-TYPE": "dependency_analysis",
            "Accept": "*/*",
        }
        
        self._perform_upload(path, headers)
    
    def upload_sbom_file(self, scan_code: str, path: str):
        """
        Uploads an SBOM file to a scan.
        
        Args:
            scan_code: Code of the scan to upload to
            path: Path to the SBOM file to upload
            
        Raises:
            FileSystemError: If file doesn't exist
            ApiError: If upload fails
            NetworkError: If there are network issues
        """
        if not os.path.exists(path) or not os.path.isfile(path):
            raise FileSystemError(f"SBOM file does not exist: {path}")
        
        upload_basename = os.path.basename(path)
        name_b64 = base64.b64encode(upload_basename.encode()).decode("utf-8")
        scan_code_b64 = base64.b64encode(scan_code.encode()).decode("utf-8")
        
        headers = {"FOSSID-SCAN-CODE": scan_code_b64, "FOSSID-FILE-NAME": name_b64, "Accept": "*/*"}
        
        self._perform_upload(path, headers)
    
    # ===== INTERNAL UPLOAD HELPERS =====
    
    def _perform_upload(self, file_path: str, headers: dict) -> None:
        """
        Perform file upload with chunking and progress tracking.
        
        Args:
            file_path: Path to the file to upload
            headers: HTTP headers for the upload
            
        Raises:
            FileSystemError: If file doesn't exist or can't be read
            ApiError: If upload fails
            NetworkError: If there are network issues
        """
        if not os.path.exists(file_path):
            raise FileSystemError(f"File not found: {file_path}")
        
        file_size = os.path.getsize(file_path)
        filename = os.path.basename(file_path)
        
        # Log upload initiation
        logger.debug(f"Starting upload for file: {filename} ({file_size / (1024 * 1024):.2f} MB)")
        
        # Decide between chunked and standard upload
        if file_size > self.CHUNKED_UPLOAD_THRESHOLD:
            logger.debug(f"File size exceeds {self.CHUNKED_UPLOAD_THRESHOLD / (1024 * 1024):.0f} MB, using chunked upload.")
            self._chunked_upload(file_path, file_size, headers)
        else:
            logger.debug("Using standard (non-chunked) upload.")
            self._standard_upload(file_path, headers)
        
        logger.info(f"Upload complete for {filename}")
    
    def _standard_upload(self, file_path: str, headers: dict) -> None:
        """
        Perform standard (non-chunked) file upload.
        
        Args:
            file_path: Path to the file to upload
            headers: HTTP headers for the upload
            
        Raises:
            NetworkError: If there are network issues
            ApiError: If upload fails
        """
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
            
            logger.debug(f"Standard upload response code: {response.status_code}")
            logger.debug(f"Standard upload response: {response.text[:500]}")
            
            # Check for errors
            if response.status_code != 200:
                raise ApiError(f"Upload failed with status {response.status_code}: {response.text}")
            
            # Parse response
            try:
                response_data = response.json()
                status = str(response_data.get("status", "0"))
                if status != "1":
                    error_msg = response_data.get("error", "Unknown error")
                    raise ApiError(f"Upload failed: {error_msg}")
            except (ValueError, json.JSONDecodeError):
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
    
    def _chunked_upload(self, file_path: str, file_size: int, headers: dict) -> None:
        """
        Perform chunked file upload with progress tracking.
        
        Args:
            file_path: Path to the file to upload
            file_size: Size of the file in bytes
            headers: HTTP headers for the upload
            
        Raises:
            NetworkError: If there are network issues
            ApiError: If upload fails
        """
        total_chunks = (file_size + self.CHUNK_SIZE - 1) // self.CHUNK_SIZE
        logger.debug(f"Chunked upload: {total_chunks} chunks of {self.CHUNK_SIZE / (1024 * 1024):.2f} MB each")
        
        # Add chunked upload headers (required by Workbench API)
        headers_copy = headers.copy()
        headers_copy["Transfer-Encoding"] = "chunked"
        headers_copy["Content-Type"] = "application/octet-stream"
        logger.debug("Added Transfer-Encoding: chunked header for chunked upload")
        
        show_progress = total_chunks <= self.SMALL_FILE_CHUNK_THRESHOLD
        last_printed_progress = 0
        
        try:
            with open(file_path, "rb") as f:
                for i, chunk in enumerate(self._read_in_chunks(f, self.CHUNK_SIZE), start=1):
                    logger.debug(f"Uploading chunk {i}/{total_chunks}")
                    self._upload_single_chunk(chunk, i, headers_copy)
                    
                    # Progress tracking
                    progress = int((i / total_chunks) * 100)
                    if show_progress or progress >= last_printed_progress + self.PROGRESS_UPDATE_INTERVAL:
                        print(f"Upload progress: {progress}%")
                        last_printed_progress = progress
        
        except Exception as e:
            logger.error(f"Error during chunked upload: {e}")
            raise
    
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
    
    def _upload_single_chunk(self, chunk: bytes, chunk_number: int, headers: dict) -> None:
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
                    logger.debug(f"Removed Content-Length header for chunk {chunk_number}")
                
                # Send the request using the shared session
                resp_chunk = self._api.session.send(prepped, timeout=1800)
                
                # Validate response
                self._validate_chunk_response(resp_chunk, chunk_number, retry_count)
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
                raise ApiError(f"Chunk {chunk_number} upload failed with status {response.status_code}")
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

