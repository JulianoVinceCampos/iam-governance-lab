"""Tests for JML (Joiner, Mover, Leaver) lifecycle operations."""

import pytest
from iam_governance import jml
from iam_governance.state import get_entitlement


class TestJoiner:
    def test_joiner_known_user(self):
        """Existing user in users.json should be provisioned successfully."""
        result = jml.simulate_joiner("U001")
        assert result["success"] is True
        assert result["event"] == "joiner"
        assert result["user_id"] == "U001"
        assert result["name"] == "Alice Souza"
        assert isinstance(result["provisioned_applications"], list)
        assert isinstance(result["permissions"], list)

    def test_joiner_persists_to_state(self):
        """After joiner, entitlement should exist in state."""
        jml.simulate_joiner("U001")
        ent = get_entitlement("U001")
        assert ent is not None
        assert ent["status"] == "active"

    def test_joiner_unknown_user_fails(self):
        """Non-existent user ID should return error."""
        result = jml.simulate_joiner("XXXXXXX")
        assert result["success"] is False
        assert "not found" in result["error"]

    def test_joiner_permissions_match_role(self):
        """Provisioned permissions should match role definition."""
        result = jml.simulate_joiner("U001")
        assert result["success"] is True
        # analyst role should not have approve:payments
        assert "approve:payments" not in result["permissions"]
        assert "read:reports" in result["permissions"]


class TestMover:
    def test_mover_changes_role_and_dept(self):
        """Moving a user should update their department and role."""
        result = jml.simulate_mover("U001", "Procurement", "procurement")
        assert result["success"] is True
        assert result["new_department"] == "Procurement"
        assert result["new_role"] == "procurement"
        assert result["old_role"] == "analyst"

    def test_mover_updates_state(self):
        """After mover, state should reflect new role."""
        jml.simulate_mover("U001", "Procurement", "procurement")
        ent = get_entitlement("U001")
        assert ent["role"] == "procurement"
        assert ent["department"] == "Procurement"

    def test_mover_revokes_old_permissions(self):
        """Mover must revoke permissions not in new role."""
        result = jml.simulate_mover("U002", "Finance", "analyst")
        assert result["success"] is True
        # admin permissions not in analyst should be revoked
        assert "manage:systems" in result["revoked_permissions"] or len(result["revoked_permissions"]) > 0

    def test_mover_unknown_user_fails(self):
        """Moving a non-existent user should fail."""
        result = jml.simulate_mover("XXXXXXX", "IT", "admin")
        assert result["success"] is False

    def test_mover_invalid_role_fails(self):
        """Moving to an undefined role should fail."""
        result = jml.simulate_mover("U001", "IT", "nonexistent_role")
        assert result["success"] is False


class TestLeaver:
    def test_leaver_revokes_access(self):
        """Leaver should revoke all applications and permissions."""
        result = jml.simulate_leaver("U001")
        assert result["success"] is True
        assert result["event"] == "leaver"
        assert isinstance(result["revoked_applications"], list)

    def test_leaver_marks_inactive(self):
        """After leaver, user status in state should be inactive."""
        jml.simulate_leaver("U001")
        ent = get_entitlement("U001")
        assert ent["status"] == "inactive"
        assert ent["applications"] == []
        assert ent["permissions"] == []

    def test_leaver_preserves_audit_trail(self):
        """Leaver should keep the record with deprovisioned_at timestamp."""
        jml.simulate_leaver("U001")
        ent = get_entitlement("U001")
        assert ent is not None  # record preserved
        assert "deprovisioned_at" in ent

    def test_leaver_unknown_user_fails(self):
        """Trying to off-board a non-existent user should fail."""
        result = jml.simulate_leaver("XXXXXXX")
        assert result["success"] is False
