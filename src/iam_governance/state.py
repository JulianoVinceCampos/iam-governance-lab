"""State management - persists entitlements to state/entitlements.json."""

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# Resolve the state file relative to the project root (two levels up from src/iam_governance/)
_THIS_DIR = Path(__file__).parent
_PROJECT_ROOT = _THIS_DIR.parent.parent
STATE_PATH = Path(os.environ.get("IAM_STATE_PATH", _PROJECT_ROOT / "state" / "entitlements.json"))


def load_state() -> dict[str, Any]:
    """Load the current entitlements state from disk."""
    if not STATE_PATH.exists():
        return {"last_updated": _now(), "entitlements": {}}
    with STATE_PATH.open("r", encoding="utf-8") as f:
        return json.load(f)


def save_state(state: dict[str, Any]) -> None:
    """Persist entitlements state to disk."""
    state["last_updated"] = _now()
    STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
    with STATE_PATH.open("w", encoding="utf-8") as f:
        json.dump(state, f, indent=2, ensure_ascii=False)


def get_entitlement(user_id: str) -> dict[str, Any] | None:
    """Return entitlement record for a given user ID, or None if not found."""
    state = load_state()
    return state["entitlements"].get(user_id)


def set_entitlement(user_id: str, record: dict[str, Any]) -> None:
    """Upsert an entitlement record for a user."""
    state = load_state()
    state["entitlements"][user_id] = record
    save_state(state)


def remove_entitlement(user_id: str) -> None:
    """Remove a user's entitlement record (leaver)."""
    state = load_state()
    state["entitlements"].pop(user_id, None)
    save_state(state)


def list_entitlements() -> list[dict[str, Any]]:
    """Return all active entitlement records."""
    state = load_state()
    return list(state["entitlements"].values())


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()
