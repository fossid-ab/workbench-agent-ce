# Users API schema reference

Derived from `UsersClient` implementation, unit tests, and live validation.
Auth fields (`username`, `key`) are added by `BaseAPI`.

Legend: **R** = required in API `data`, **O** = optional.

## Actions overview

| Action | Client method | Implemented |
|--------|---------------|-------------|
| `get_information` | `get_information()` | Yes |
| `get_user_permissions_list` | `get_user_permissions_list()` | Yes |

---

## `get_information`

### Request (`data`)

| Field | API | Client param |
|-------|-----|--------------|
| `searched_username` | **R** | `searched_username` |

### Response `data` (typical keys)

| Field | Notes |
|-------|-------|
| `id` | int |
| `username` | str |
| `name`, `surename` | str (API spelling **surename**) |
| `avatar` | str |
| `email`, `language`, `phone`, `mobile` | Omitted without sufficient permission |
| `is_deleted` | bool when present |

### Errors

| Condition | Typical `error` / `data` |
|-----------|--------------------------|
| Unknown username | `RequestData.Base.issues_while_parsing_request` + `UserTrait.username_not_valid` |

---

## `get_user_permissions_list`

### Request (`data`)

Provide **exactly one** of:

| Field | API | Client param |
|-------|-----|--------------|
| `searched_username` | **R** (xor) | `searched_username` |
| `user_id` | **R** (xor) | `user_id` |

Client raises `ValueError` if both or neither are set.

### Response `data`

Normalized to a **list** of permission objects. Typical keys:

| Field | Notes |
|-------|-------|
| `id` | int |
| `group`, `code`, `name`, `description` | str |
| `created`, `updated` | str timestamps |
| `role_id`, `status` | may be `null` |

Shapes before normalization:

- Array of objects
- Map of id → object
- Single object

### Errors

| Condition | Typical response |
|-----------|------------------|
| Unknown user | `error`: `User not found`, `data`: `null` |
