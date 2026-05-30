"""UsersClient - user lookup and permissions (group: users)."""

import logging
from typing import Any, Dict, List, Optional

from . import errors

logger = logging.getLogger("workbench-agent")

_GROUP = "users"


class UsersClient:
    """
    User lookup and permission listing (``group: users``).

    Request/response fields: ``clients/users/schema.md``.
    Server quirks: ``clients/users/quirks.md``.
    """

    def __init__(self, base_api):
        """
        Args:
            base_api: BaseAPI instance for HTTP requests.
        """
        self._api = base_api
        logger.debug("UsersClient initialized")

    def get_information(self, searched_username: str) -> Dict[str, Any]:
        """
        Look up a user by username (``searched_username``).

        See ``schema.md`` for response fields and permission-dependent omissions.
        """
        logger.debug("users.get_information: %s", searched_username)
        response = self._api._send_request(
            {
                "group": _GROUP,
                "action": "get_information",
                "data": {"searched_username": searched_username},
            }
        )

        if response.get("status") == "1" and "data" in response:
            return response["data"]

        errors.raise_on_failed_response(
            response,
            error_context=(
                f"Failed to get information for user '{searched_username}'"
            ),
        )

    def get_user_permissions_list(
        self,
        *,
        searched_username: Optional[str] = None,
        user_id: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        """
        List permissions for a user.

        Provide exactly one of ``searched_username`` or ``user_id``.
        """
        has_username = searched_username is not None
        has_user_id = user_id is not None
        if has_username == has_user_id:
            raise ValueError(
                "Provide exactly one of searched_username or user_id."
            )

        action = "get_user_permissions_list"
        if searched_username is not None:
            logger.debug("users.%s: username=%s", action, searched_username)
            data = {"searched_username": searched_username}
        else:
            logger.debug("users.%s: user_id=%s", action, user_id)
            data = {"user_id": user_id}

        response = self._api._send_request(
            {"group": _GROUP, "action": action, "data": data}
        )

        if response.get("status") == "1":
            items = errors.normalize_permissions_list_data(
                response.get("data"),
                operation=action,
            )
            logger.debug("users.%s: %d item(s)", action, len(items))
            return items

        errors.raise_on_failed_response(
            response,
            error_context="Failed to list user permissions",
        )
