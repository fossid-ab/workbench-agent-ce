"""
InternalClient - Handles internal Workbench API operations.

This client provides access to internal configuration and system information.
"""
import logging
from typing import Any, Dict

from workbench_agent.exceptions import ApiError

logger = logging.getLogger("workbench-agent")


class InternalClient:
    """
    Internal API client using composition pattern.
    
    Handles internal Workbench operations including:
    - Configuration retrieval (version info, server settings, feature flags)
    
    Example:
        >>> internal = InternalClient(base_api)
        >>> config = internal.get_config()
        >>> version = config.get("version")
    """
    
    def __init__(self, base_api):
        """
        Initialize InternalClient.
        
        Args:
            base_api: BaseAPI instance for making HTTP requests
        """
        self._api = base_api
        logger.debug("InternalClient initialized")
    
    def get_config(self) -> Dict[str, Any]:
        """
        Retrieves the Workbench configuration including version information.
        
        Returns:
            Dict[str, Any]: Configuration data including version,
                          server settings, and feature flags
            
        Raises:
            ApiError: If there are API issues
            NetworkError: If there are network issues
        """
        logger.debug("Getting Workbench configuration...")
        payload = {"group": "internal", "action": "getConfig", "data": {}}
        response = self._api._send_request(payload)
        
        if response.get("status") == "1" and "data" in response:
            data = response["data"]
            if isinstance(data, dict):
                logger.debug("Successfully retrieved Workbench configuration.")
                return data
            else:
                logger.warning(
                    f"API returned success for getConfig but 'data' was not "
                    f"a dict: {type(data)}"
                )
                return {}
        else:
            error_msg = response.get("error", f"Unexpected response: {response}")
            raise ApiError(f"Failed to get configuration: {error_msg}", details=response)

