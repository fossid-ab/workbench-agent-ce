# Files and folders API quirks (Workbench 2026.1)

Full field lists: [`schema.md`](schema.md) (from `files-and-folders-api.txt`).  
Validated on cs-demo / `tests/api/clients/files_and_folders/` and
`tests/api/services/identification/` (Test Project / Test Scan).

## Spec vs observed behavior

| Area | Official spec | Observed / client behavior |
|------|---------------|----------------------------|
| `path` encoding | base64 for most actions | **`remove_component_identification`**: plain relative path |
| `remove_component_identification` path | “Relative path” (no base64 called out) | Plain path required on 2026.1 live server |
| Read responses `message` | Often present on `get_*` | Client returns **only `data`** for read methods |
| `get_file_comments` empty | Array in samples | `data: null` → client normalizes to `[]` |
| `is_directory` | Required (`0`/`1`) | Client defaults to `"0"` when omitted |
| `preserve_existing_identifications` | Default `1` | Client default `True` → `"1"` |

## Paths

- Encoding rules: `errors.path_for_action` / `PLAIN_PATH_ACTIONS`.
- Pending file paths: `scans.get_pending_files` returns `{file_id: relative_path}` —
  use **values** (e.g. `Android-Bluetooth/Foo.java`), **not keys** (e.g. `1830925`).
  Passing a file id produces errors such as
  ``The provided file path '1830925' does not exists currently in the scan``.

## `get_folder_content`

Folder browser for a KB-scanned scan. Not a substitute for
``scans.get_pending_files`` (which returns all pending paths); this API lists
one directory level at a time.

| Topic | Observed (2026.1 cs-demo) |
|-------|---------------------------|
| Root path | Use ``"."`` — empty string and ``"/"`` are rejected |
| ``show_all`` / ``source_code_only`` | **Required** on the server despite optional-looking docs; client always sends them |
| ``is_directory``, ``children`` | String ``"0"`` / ``"1"``, not JSON booleans |
| Directory ``id`` | Base64-encoded relative path (e.g. ``./Android-Bluetooth``); pass decoded path to list subfolders |
| File ``id`` | Base64-encoded relative file path |
| ``children`` | ``"1"`` when the directory has entries; use as a hint before drilling down |
| File path as ``path`` | Returns ``data: []`` (HTTP success), not an error |
| Missing folder | ``The provided file path '…' does not exists currently in the scan`` |
| Pending filter | ``show_all="0"`` returns fewer files than ``"1"`` at the same path (pending-only) |
| Source filter | ``source_code_only="1"`` omits non-source files (e.g. ``configure.ac``, ``README``) |

## `get_folder_content_metrics`

Identification counters for a **folder** in a KB-scanned scan — same shape as
``scans.get_folder_metrics`` but scoped to a path.

| Topic | Observed (2026.1 cs-demo) |
|-------|---------------------------|
| Root path | Use ``"."`` — same path rules as ``get_folder_content`` |
| Root totals | On Test Scan, ``"."`` totals (**100** files) differ from ``scans.get_folder_metrics`` (**200**) — folder metrics count the folder scope, not the full extracted archive tree |
| Subfolder | Counts are scoped to the folder subtree (e.g. ``OpenFastPath/`` < root) |
| Sum invariant | ``total`` ≈ ``pending_identification`` + ``identified_files`` + ``without_matches`` (observed on cs-demo) |
| Numeric fields | ``total``, ``pending_identification``, etc. may arrive as **strings** |
| File path | Not validated on Test Scan — expect ``false`` or error like other folder APIs |

## `get_folder_components_ranking`

Component occurrence ranking for a **folder** in a KB-scanned scan — which
identified third-party components appear most often under that path.

| Topic | Observed (2026.1 cs-demo) |
|-------|---------------------------|
| Purpose | Ranked list of identified artifacts in the folder subtree, by ``amount`` (descending) |
| Root path | Use ``"."`` — same path rules as ``get_folder_content`` |
| ``amount`` | Total component hits scoped to the folder (root ``ofp`` → 43; ``OpenFastPath/`` → 21) |
| ``amount_per_artifact_version`` | Hits for that specific ``artifact`` + ``version`` pair within the folder |
| ``fcrid`` | Internal catalog/component reference id (string on live server) |
| ``rownum`` | Always ``"0"`` in samples — spec says integer; treat as unreliable |
| Numeric fields | ``amount``, ``amount_per_artifact_version``, ``fcrid``, ``rownum`` arrive as **strings** |
| File path | Returns ``data: false`` (not an error) — use ``is False`` to detect |
| Empty folder | Not observed on Test Scan; expect ``[]`` or ``false`` — validate if needed |
| KB scan required | Same as ``get_folder_content`` — needs scanned, identified content |

## `get_folder_extensions_ranking`

File-extension breakdown for a **folder** in a KB-scanned scan — how many files
of each extension appear under that path.

| Topic | Observed (2026.1 cs-demo) |
|-------|---------------------------|
| Purpose | Count of files per extension, sorted by ``amount`` descending |
| Root path | Use ``"."`` — empty path fails; ``"/"`` and missing paths error |
| ``file_extension`` | Extension without dot (``c``, ``java``, ``sh``); empty string = extensionless files |
| ``amount`` | File count for that extension within the folder scope |
| ``id`` | Opaque row id (string on live server, not useful for clients) |
| Numeric fields | ``id`` and ``amount`` arrive as **strings** |
| File path | Returns ``data: false`` (e.g. ``LICENSE``) |
| ``current_view`` | Optional filter; omit → same as ``show_all`` / ``all_items`` |
| ``show_all`` / ``all_items`` | Full folder counts (root sum = 100 on Test Scan) |
| ``pending_items`` | Pending-identification files only (root sum = 63) |
| ``without_matches`` | Files without KB matches (root sum = 37) |
| ``mark_as_identified`` | Returns ``false`` on Test Scan (no marked files in view) |
| Invalid ``current_view`` | Request parse error |

## `get_identification`

Top-level `data` keys observed: `component_identification`, `licenses`, `copyright`.

| Field | Observed shapes (2026.1 cs-demo) |
|-------|-------------------------------------|
| `component_identification` | Empty list `[]` when unset; **single dict** when a component ID exists (not always a list) |
| Linked catalog rows | Nested under ``component_identification.components`` (id → component dict with ``name``, ``version``) |
| `licenses` | Boolean `false` when none; otherwise a **dict** keyed by id strings (e.g. `{"1": {...}}`) |
| `copyright` | `null` or a plain **string** (manual or autoid from scan) |

When set, the component dict includes fields such as `id`, `scan_file_id`,
`identifying_done` (`"0"` / `"1"`), and **`is_distributed`** (`"0"` / `"1"`).

**Pending identification ≠ empty identification.** Files listed in
`get_pending_files` may already have component, license, and/or copyright data
after autoid or partial review. Always read before writing.

**Distribution status** is on `component_identification.is_distributed`, not a
top-level field. ``IdentificationService.set_distribution_status`` and
``parse_distribution_status`` read this nested value when present.

## `get_fossid_results`

- Returns a map of match id → match object; **max 10** items per file.
- `match_type` values observed: **`partial`** (snippet), **`full`** (whole-file
  match). Map `full` to whole-file / component identification in agents; map
  `partial` to snippet license + comment.
- For catalog field mapping: `artifact` → component name, `author` → supplier,
  `version` → component version, `artifact_license` → component license,
  `url` → component download URL. 

## `get_matched_lines`

- Spec describes `local_file` and `mirror_file` as line id maps.
- On cs-demo partial matches, **`local_file` is often an empty list**; usable
  line numbers frequently appear under **`mirror_file`** (dict of id → line).
  Consumers should fall back when `local_file` is empty (see
  ``line_range_from_matched_lines``).

## `change_distribution_status`

- Toggles distributed / not-distributed; not idempotent set-by-value.
- Prefer reading `get_identification` → `component_identification.is_distributed`
  before calling, or use ``IdentificationService.set_distribution_status``.

## Write responses

- Mutations with `include_message=True` return `{"data", "message"}`.
- Many writes return `data: null` on success (see contract `write_null_data`).

## `add_license_identification`

- `identification_on` must be exactly `'file'` or `'snippet'`.

## Errors (`status: "0"`)

- ``BaseAPI`` returns ``status: "0"`` for all ``files_and_folders`` actions so the
  client prefixes ``Failed to …`` (live-validated).
- Typical missing file: `The provided file path does not exist`.
- Missing catalog component: ``Component not found`` on ``set_identification_component``.
