"""RBAC - Role-Based Access Control.

Maps roles to permissions using data/roles.json.
Provides helpers to resolve permissions for a given role.
"""

import json
from pathlib import Path
from typing import Any

_THIS_DIR = Path(__file__).parent
_PROJECT_ROOT = _THIS_DIR.parent.parent
ROLES_PATH = Path(_PROJECT_ROOT / "data" / "roles.json")


def load_roles() -> list[dict[str, Any]]:
    with ROLES_PATH.open("r", encoding="utf-8") as f:
        return json.load(f)


def get_role(role_name: str) -> dict[str, Any] | None:
    for role in load_roles():
        if role["name"] == role_name:
            return role
    return None


def get_permissions_for_role(role_name: str) -> list[str]:
    """Return list of permissions granted by a role. Returns empty list if role not found."""
    role = get_role(role_name)
    if role is None:
        return []
    return role.get("permissions", [])


def resolve_applications_for_role(role_name: str, applications: list[dict[str, Any]]) -> list[str]:
    """Return app IDs where the role is listed as required/allowed."""
    app_ids = []
    for app in applications:
        if role_name in app.get("required_roles", []):
            app_ids.append(app["id"])
    return app_ids
