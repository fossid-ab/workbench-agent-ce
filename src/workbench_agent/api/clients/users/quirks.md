# Users API quirks (Workbench 2026.1)

Field reference: [`schema.md`](schema.md).  
Validated via unit tests and optional live probes in `tests/api/clients/users/`.

## Spec vs observed behavior

| Area | Documented / expected | Observed / client behavior |
|------|---------------------|----------------------------|
| Missing user `get_information` | Parsing error payload | ``status: "0"``, ``error``: ``RequestData.Base.issues_while_parsing_request``, ``data[0].code``: ``UserTrait.username_not_valid`` |
| Missing user `get_user_permissions_list` | ``User not found`` | ``status: "0"``, ``data``: ``null``, ``error``: ``User not found`` |
| Permissions ``data`` shape | Array | May be **array** or **map** keyed by id — normalized to list |
| Success + ``data: null`` (permissions) | — | Returns ``[]`` (logs warning) |
| ``surename`` | API spelling | Not a client typo — matches server JSON |
| PII fields | Optional | ``email``, ``phone``, ``mobile``, ``language``, ``is_deleted`` omitted without ``USERS_EDIT_ANY`` |

## ``BaseAPI`` status ``0``

For ``group: users``, ``BaseAPI`` returns the JSON body (does not raise) for:

- ``get_information``
- ``get_user_permissions_list``

so ``UsersClient`` can prefix errors as ``Failed to …: <error>``.

## Errors

All failures surface as :class:`~workbench_agent.api.exceptions.ApiError` (no
``UserNotFoundError`` type). Use ``errors.is_user_not_found()`` to classify
messages when needed.
