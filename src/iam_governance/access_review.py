"""Access Review - Campaign management for periodic access certifications.

Simulates an access review campaign where managers/owners
review and approve or deny user entitlements.
"""

import json
import random
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from iam_governance.state import list_entitlements

_THIS_DIR = Path(__file__).parent
_PROJECT_ROOT = _THIS_DIR.parent.parent
CAMPAIGNS_DIR = _PROJECT_ROOT / "state"

SIMULATED_REVIEWERS = [
    "manager.silva@example.com",
    "manager.costa@example.com",
    "owner.it@example.com",
    "compliance@example.com",
]


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _campaign_path(campaign_name: str) -> Path:
    safe_name = campaign_name.replace(" ", "_").lower()
    return CAMPAIGNS_DIR / f"campaign_{safe_name}.json"


def run_access_review(campaign_name: str) -> dict[str, Any]:
    """
    Run a new access review campaign.

    For each active user, generates review items for each application/permission.
    Simulates reviewer assignment and auto-generates approve/deny decisions
    (simulated: 85% approve rate to reflect realistic review outcomes).

    Saves campaign results to state/campaign_<name>.json.
    Returns campaign summary.
    """
    entitlements = list_entitlements()
    active_users = [e for e in entitlements if e.get("status") == "active"]

    items: list[dict[str, Any]] = []

    for user in active_users:
        reviewer = random.choice(SIMULATED_REVIEWERS)
        for app_id in user.get("applications", []):
            decision = "approve" if random.random() < 0.85 else "deny"
            item = {
                "item_id": f"{user['user_id']}-{app_id}",
                "user_id": user["user_id"],
                "user_name": user.get("name", ""),
                "user_role": user.get("role", ""),
                "department": user.get("department", ""),
                "application": app_id,
                "permissions": user.get("permissions", []),
                "reviewer": reviewer,
                "decision": decision,
                "decision_timestamp": _now(),
                "justification": (
                    "Access is appropriate for current role."
                    if decision == "approve"
                    else "Access is no longer required - pending removal."
                ),
            }
            items.append(item)

    approved = [i for i in items if i["decision"] == "approve"]
    denied = [i for i in items if i["decision"] == "deny"]

    campaign = {
        "campaign_name": campaign_name,
        "started_at": _now(),
        "status": "completed",
        "total_items": len(items),
        "approved": len(approved),
        "denied": len(denied),
        "users_reviewed": len(active_users),
        "items": items,
    }

    campaign_path = _campaign_path(campaign_name)
    campaign_path.parent.mkdir(parents=True, exist_ok=True)
    with campaign_path.open("w", encoding="utf-8") as f:
        json.dump(campaign, f, indent=2, ensure_ascii=False)

    return campaign


def load_campaign(campaign_name: str) -> dict[str, Any] | None:
    """Load a previously run campaign from state."""
    path = _campaign_path(campaign_name)
    if not path.exists():
        return None
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def list_campaigns() -> list[str]:
    """Return list of all campaign names in state/."""
    return [
        p.stem.replace("campaign_", "")
        for p in CAMPAIGNS_DIR.glob("campaign_*.json")
    ]
