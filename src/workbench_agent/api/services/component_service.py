"""
ComponentService - Operate on the Workbench component catalog.

Shared catalog lifecycle (find, resolve, update) for identification and
dependency analysis workflows. ``resolve`` follows the same find-or-create
contract as ``ResolverService`` for projects and scans.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional, Union

logger = logging.getLogger("workbench-agent")


class ComponentService:
    """
    Service for Workbench component catalog workflows.

    Example:
        >>> svc = ComponentService(client.components)
        >>> svc.resolve("abbrev", "1.1.1", "ISC", purl="pkg:npm/abbrev@1.1.1")
    """

    def __init__(self, components_client) -> None:
        self._components = components_client
        logger.debug("ComponentService initialized")

    def find(
        self,
        component_name: str,
        component_version: Optional[str] = None,
    ) -> Optional[Union[Dict[str, Any], List[Dict[str, Any]]]]:
        """Return catalog component information, or ``None`` if missing."""
        return self._components.get_information(
            component_name, component_version
        )

    def exists(self, component_name: str, component_version: str) -> bool:
        """Return whether a name/version pair exists in the catalog."""
        return self.find(component_name, component_version) is not None

    def resolve(
        self,
        component_name: str,
        component_version: str,
        license_identifier: str,
        *,
        supplier_name: Optional[str] = None,
        purl: Optional[str] = None,
        url: Optional[str] = None,
        cpe: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Resolve a catalog component by name and version; create when absent.

        Returns:
            Dict with component_name, component_version, created bool,
            and optional create_response.
        """
        name = component_name.strip()
        version = component_version.strip()
        license_id = license_identifier.strip()
        if not name or not version:
            raise ValueError("component_name and component_version are required")
        if not license_id:
            raise ValueError("license_identifier is required to create a component")

        existing = self.find(name, version)
        if existing is not None:
            catalog_supplier = (
                existing.get("supplier_name")
                if isinstance(existing, dict)
                else None
            )
            resolved_supplier = catalog_supplier or supplier_name
            logger.debug(
                "Component '%s' v%s already exists in catalog (supplier=%r)",
                name,
                version,
                resolved_supplier,
            )
            return {
                "component_name": name,
                "component_version": version,
                "supplier_name": resolved_supplier,
                "license_identifier": license_id,
                "created": False,
            }

        logger.info("Creating catalog component '%s' v%s", name, version)
        create_kwargs: Dict[str, Any] = {
            "name": name,
            "version": version,
            "license_identifier": license_id,
        }
        if supplier_name:
            create_kwargs["sup_com_name"] = supplier_name
        if purl:
            create_kwargs["purl"] = purl
        if url:
            create_kwargs["url"] = url
        if cpe:
            create_kwargs["cpe"] = cpe

        create_response = self._components.create(**create_kwargs)
        return {
            "component_name": name,
            "component_version": version,
            "supplier_name": supplier_name,
            "license_identifier": license_id,
            "created": True,
            "create_response": create_response,
        }

    def update(
        self,
        component_name: str,
        component_version: str,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """Update an existing catalog component (delegates to ``ComponentsClient``)."""
        return self._components.update(
            component_name, component_version, **kwargs
        )
