"""SoD - Segregation of Duties.

Validates user entitlements against the SoD conflict matrix (data/sod_matrix.json).
Detects when a single user holds two conflicting permissions.
"""

import json
from pathlib import Path
from typing import Any

_THIS_DIR = Path(__file__).parent
_PROJECT_ROOT = _THIS_DIR.parent.parent
SOD_MATRIX_PATH = _PROJECT_ROOT / "data" / "sod_matrix.json"


def load_sod_matrix() -> dict[str, Any]:
    with SOD_MATRIX_PATH.open("r", encoding="utf-8") as f:
        return json.load(f)


def check_sod_violations(user_id: str, permissions: list[str]) -> dict[str, Any]:
    """
    Check a user's permissions against the SoD conflict matrix.

    Args:
        user_id: The ID of the user to check.
        permissions: List of permissions currently held by the user.

    Returns:
        Dict with keys:
          - user_id: str
          - violations: list of conflict dicts
          - clean: bool (True if no violations found)
    """
    matrix = load_sod_matrix()
    conflicts = matrix.get("conflicts", [])
    permission_set = set(permissions)

    violations = []
    for conflict in conflicts:
        perm_a = conflict["permission_a"]
        perm_b = conflict["permission_b"]
        if perm_a in permission_set and perm_b in permission_set:
            violations.append(
                {
                    "conflict_id": conflict["id"],
                    "permission_a": perm_a,
                    "permission_b": perm_b,
                    "risk_level": conflict["risk_level"],
                    "rationale": conflict["rationale"],
                }
            )

    return {
        "user_id": user_id,
        "permissions_checked": sorted(permissions),
        "violations": violations,
        "clean": len(violations) == 0,
        "critical_count": sum(1 for v in violations if v["risk_level"] == "critical"),
        "high_count": sum(1 for v in violations if v["risk_level"] == "high"),
    }


def run_sod_for_all(entitlements: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Run SoD check across all active users. Returns list of results with violations only."""
    results = []
    for ent in entitlements:
        if ent.get("status") != "active":
            continue
        result = check_sod_violations(ent["user_id"], ent.get("permissions", []))
        result["name"] = ent.get("name", "")
        results.append(result)
    return results
