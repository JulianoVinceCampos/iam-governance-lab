"""Shared test fixtures and configuration."""

import json

import pytest


@pytest.fixture(autouse=True)
def isolated_state(tmp_path, monkeypatch):
    """
    Redirect all state/data reads to temporary directories so tests
    never mutate the real state/entitlements.json.
    """
    # Create temp state file with baseline entitlements
    state_dir = tmp_path / "state"
    state_dir.mkdir()
    state_file = state_dir / "entitlements.json"

    baseline = {
        "last_updated": "2024-01-01T00:00:00Z",
        "entitlements": {
            "U001": {
                "user_id": "U001",
                "name": "Alice Souza",
                "email": "alice.souza@example.com",
                "department": "Finance",
                "role": "analyst",
                "status": "active",
                "applications": ["APP001"],
                "permissions": ["read:reports", "read:dashboards", "read:invoices"],
                "attributes": {
                    "location": "BR",
                    "clearance": "standard",
                    "contract_type": "full_time",
                },
                "granted_at": "2024-01-01T00:00:00Z",
            },
            "U002": {
                "user_id": "U002",
                "name": "Bruno Martins",
                "email": "bruno.martins@example.com",
                "department": "IT",
                "role": "admin",
                "status": "active",
                "applications": ["APP001", "APP004"],
                "permissions": [
                    "read:reports",
                    "write:users",
                    "delete:users",
                    "manage:systems",
                    "read:invoices",
                    "approve:payments",
                ],
                "attributes": {"location": "BR", "clearance": "high", "contract_type": "full_time"},
                "granted_at": "2024-01-01T00:00:00Z",
            },
            "U004": {
                "user_id": "U004",
                "name": "Diego Ferreira",
                "email": "diego.ferreira@example.com",
                "department": "Finance",
                "role": "approver",
                "status": "active",
                "applications": ["APP001", "APP003"],
                "permissions": [
                    "read:reports",
                    "approve:payments",
                    "approve:purchase_orders",
                    "read:invoices",
                ],
                "attributes": {"location": "BR", "clearance": "high", "contract_type": "full_time"},
                "granted_at": "2024-01-01T00:00:00Z",
            },
        },
    }

    state_file.write_text(json.dumps(baseline, indent=2))
    monkeypatch.setenv("IAM_STATE_PATH", str(state_file))

    # We need to patch the module-level STATE_PATH variable after env var is set
    import iam_governance.state as state_module

    monkeypatch.setattr(state_module, "STATE_PATH", state_file)

    yield tmp_path
