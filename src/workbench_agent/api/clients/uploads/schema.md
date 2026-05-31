# Uploads transport schema

Uploads are **not** JSON ``group``/``action`` calls. The client POSTs raw file
bytes to the Workbench ``api.php`` URL with FossID-specific HTTP headers.
``UploadService`` builds headers; ``UploadsClient`` performs transport.

Auth: HTTP Basic Auth (``api_user``, ``api_token``) on every request.

## HTTP headers

| Header | Required | Encoding | Purpose |
|--------|----------|----------|---------|
| `FOSSID-SCAN-CODE` | Yes | base64(scan code) | Target scan |
| `FOSSID-FILE-NAME` | Yes | base64(basename) | Uploaded filename on server |
| `FOSSID-UPLOAD-TYPE` | DA only | plain string | `dependency_analysis` |
| `Accept` | Yes | plain | `*/*` |
| `Transfer-Encoding` | Chunked only | plain | `chunked` |
| `Content-Type` | Chunked only | plain | `application/octet-stream` |

## Upload kinds (service layer)

| Method | Headers | Follow-up |
|--------|---------|-----------|
| Scan target (zip/hash) | scan code + file name | `scans.extract_archives` |
| Dependency analysis | + `FOSSID-UPLOAD-TYPE: dependency_analysis` | `run_dependency_analysis` import |
| SBOM | scan code + file name | `scans.import_report` |

## Standard upload response

HTTP **200**. Body may be JSON with ``status: "1"`` or empty/non-JSON on success.

## Chunked upload

- Chunk size: 7 MiB (``UploadsClient.CHUNK_SIZE``)
- Each chunk: POST with ``Transfer-Encoding: chunked``; ``Content-Length`` removed
- Per-chunk HTTP **200** indicates success; JSON body not required per chunk
