# Uploads client test coverage

Upload behavior is covered by end-to-end functional tests. This package has unit tests only.

| Operation | Unit |
|-----------|------|
| `upload_file_standard` | Yes |
| `upload_file_chunked` | Yes |
| Response validation (`errors.py`) | Yes |

```bash
pytest tests/api/clients/uploads -m "not requires_workbench" -v
```
