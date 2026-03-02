"""JML - Joiner, Mover, Leaver lifecycle management.

Handles provisioning and de-provisioning of access based on HR events.
"""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from iam_governance import rbac, abac
from iam_governance.state import get_entitlement, set_entitlement, remove_entitlement

_THIS_DIR = Path(__file__).parent
_PROJECT_ROOT = _THIS_DIR.parent.parent
USERS_PATH = _PROJECT_ROOT / "data" / "users.json"
APPS_PATH = _PROJECT_ROOT / "data" / "applications.json"


def _load_users() -> list[dict[str, Any]]:
    with USERS_PATH.open("r", encoding="utf-8") as f:
        return json.load(f)


def _load_applications() -> list[dict[str, Any]]:
    with APPS_PATH.open("r", encoding="utf-8") as f:
        return json.load(f)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _get_user(user_id: str) -> dict[str, Any] | None:
    for u in _load_users():
        if u["id"] == user_id:
            return u
    return None


def simulate_joiner(user_id: str) -> dict[str, Any]:
    """
    Simulate a new hire (Joiner) event.

    Looks up the user in data/users.json, provisions access based on their
    role (RBAC) and attributes (ABAC), and saves to state.

    Returns a summary dict with provisioning details.
    """
    user = _get_user(user_id)
    if user is None:
        return {
            "success": False,
            "error": f"User '{user_id}' not found in data/users.json",
        }

    if user.get("status") == "inactive":
        return {
            "success": False,
            "error": f"User '{user_id}' is already marked as inactive.",
        }

    applications = _load_applications()
    role_name = user["role"]
    permissions = rbac.get_permissions_for_role(role_name)
    provisioned_apps = []
    denied_apps = []

    for app in applications:
        # RBAC check: role must be in app's required_roles
        if role_name not in app.get("required_roles", []):
            continue
        # ABAC check
        result = abac.evaluate_user_app_access(user, app)
        if result["allowed"]:
            provisioned_apps.append(app["id"])
        else:
            denied_apps.append({"app_id": app["id"], "reasons": result["violations"]})

    record = {
        "user_id": user_id,
        "name": user["name"],
        "email": user["email"],
        "department": user["department"],
        "role": role_name,
        "status": "active",
        "applications": provisioned_apps,
        "permissions": permissions,
        "attributes": user.get("attributes", {}),
        "granted_at": _now(),
    }

    set_entitlement(user_id, record)

    return {
        "success": True,
        "event": "joiner",
        "user_id": user_id,
        "name": user["name"],
        "role": role_name,
        "provisioned_applications": provisioned_apps,
        "denied_applications": denied_apps,
        "permissions": permissions,
    }


def simulate_mover(user_id: str, new_dept: str, new_role: str) -> dict[str, Any]:
    """
    Simulate an internal transfer (Mover) event.

    De-provisions current access, re-provisions based on new role/department.
    Follows least-privilege: old entitlements are replaced, not accumulated.

    Returns a summary dict with before/after comparison.
    """
    existing = get_entitlement(user_id)
    if existing is None:
        return {
            "success": False,
            "error": f"User '{user_id}' not found in current state. Run simulate-joiner first.",
        }

    old_role = existing["role"]
    old_apps = list(existing.get("applications", []))
    old_perms = list(existing.get("permissions", []))

    applications = _load_applications()
    new_permissions = rbac.get_permissions_for_role(new_role)

    if not new_permissions:
        return {
            "success": False,
            "error": f"Role '{new_role}' not found in data/roles.json",
        }

    new_attrs = existing.get("attributes", {})
    user_for_abac = {
        "id": user_id,
        "role": new_role,
        "attributes": new_attrs,
    }

    provisioned_apps = []
    denied_apps = []

    for app in applications:
        if new_role not in app.get("required_roles", []):
            continue
        result = abac.evaluate_user_app_access(user_for_abac, app)
        if result["allowed"]:
            provisioned_apps.append(app["id"])
        else:
            denied_apps.append({"app_id": app["id"], "reasons": result["violations"]})

    updated = {
        **existing,
        "department": new_dept,
        "role": new_role,
        "applications": provisioned_apps,
        "permissions": new_permissions,
        "moved_at": _now(),
    }

    set_entitlement(user_id, updated)

    return {
        "success": True,
        "event": "mover",
        "user_id": user_id,
        "name": existing["name"],
        "old_department": existing["department"],
        "new_department": new_dept,
        "old_role": old_role,
        "new_role": new_role,
        "old_applications": old_apps,
        "new_applications": provisioned_apps,
        "revoked_permissions": [p for p in old_perms if p not in new_permissions],
        "granted_permissions": [p for p in new_permissions if p not in old_perms],
        "denied_applications": denied_apps,
    }


def simulate_leaver(user_id: str) -> dict[str, Any]:
    """
    Simulate an employee departure (Leaver) event.

    Revokes ALL access immediately and marks user as inactive in state.

    Returns a summary of what was revoked.
    """
    existing = get_entitlement(user_id)
    if existing is None:
        return {
            "success": False,
            "error": f"User '{user_id}' not found in current state.",
        }

    revoked_apps = list(existing.get("applications", []))
    revoked_perms = list(existing.get("permissions", []))

    # Mark as inactive instead of deleting - preserves audit trail
    deprovisioned = {
        **existing,
        "status": "inactive",
        "applications": [],
        "permissions": [],
        "deprovisioned_at": _now(),
    }

    set_entitlement(user_id, deprovisioned)

    return {
        "success": True,
        "event": "leaver",
        "user_id": user_id,
        "name": existing["name"],
        "revoked_applications": revoked_apps,
        "revoked_permissions": revoked_perms,
        "deprovisioned_at": deprovisioned["deprovisioned_at"],
    }
