"""Expected API ``data`` keys for UsersClient methods."""

from typing import Dict, FrozenSet, Tuple

USERS_REQUEST_MANIFEST: Dict[str, Tuple[FrozenSet[str], FrozenSet[str]]] = {
    "get_information": (frozenset({"searched_username"}), frozenset()),
    "get_user_permissions_list": (
        frozenset(),
        frozenset(),
    ),
}
