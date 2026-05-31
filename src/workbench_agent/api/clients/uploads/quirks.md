# Uploads client quirks

## Transport vs JSON API

- Uploads bypass ``BaseAPI._send_request`` JSON envelope and POST directly to
  ``api.php`` with Basic Auth.
- Standard uploads use a standalone ``requests.post``; chunked uploads reuse
  ``BaseAPI.session`` for connection pooling.

## Chunked uploads

- ``Content-Length`` must be stripped from prepared chunk requests.
- Non-200 chunk responses are retried up to ``MAX_CHUNK_RETRIES`` (3).
- Service layer switches to chunked mode above ~7 MiB
  (``UploadService.CHUNKED_UPLOAD_THRESHOLD``).

## Standard upload JSON

- Some successful uploads return non-JSON bodies; client treats HTTP 200 as
  success when JSON parsing fails.
- When JSON is returned, ``status`` must be ``"1"``.
