"""Tests for SoD (Segregation of Duties) detection."""

import pytest
from iam_governance.sod import check_sod_violations, run_sod_for_all


class TestSodViolations:
    def test_clean_user_no_violations(self):
        """User with non-conflicting permissions should have no violations."""
        result = check_sod_violations("TEST01", ["read:reports", "read:dashboards"])
        assert result["clean"] is True
        assert result["violations"] == []
        assert result["critical_count"] == 0

    def test_detect_critical_approve_and_create_po(self):
        """approve:payments + create:purchase_orders is a critical SoD violation."""
        perms = ["approve:payments", "create:purchase_orders", "read:reports"]
        result = check_sod_violations("TEST02", perms)
        assert result["clean"] is False
        assert result["critical_count"] >= 1
        conflict_ids = [v["conflict_id"] for v in result["violations"]]
        assert "SOD001" in conflict_ids

    def test_detect_create_and_approve_po(self):
        """create:purchase_orders + approve:purchase_orders is a critical SoD (SOD004)."""
        perms = ["create:purchase_orders", "approve:purchase_orders"]
        result = check_sod_violations("TEST03", perms)
        assert result["clean"] is False
        conflict_ids = [v["conflict_id"] for v in result["violations"]]
        assert "SOD004" in conflict_ids

    def test_admin_with_approve_payments_has_violations(self):
        """Admin permissions including manage:systems and approve:payments hit SOD005."""
        perms = ["manage:systems", "approve:payments", "read:reports"]
        result = check_sod_violations("U002", perms)
        assert result["clean"] is False
        conflict_ids = [v["conflict_id"] for v in result["violations"]]
        assert "SOD005" in conflict_ids

    def test_multiple_violations_detected(self):
        """A single user can have multiple violations at once."""
        perms = [
            "approve:payments",
            "create:purchase_orders",
            "approve:purchase_orders",
            "manage:systems",
            "write:users",
        ]
        result = check_sod_violations("TEST04", perms)
        assert len(result["violations"]) > 1

    def test_empty_permissions_clean(self):
        """User with no permissions should have no SoD violations."""
        result = check_sod_violations("TEST05", [])
        assert result["clean"] is True

    def test_run_sod_for_all_includes_only_active(self):
        """run_sod_for_all should skip inactive users."""
        entitlements = [
            {
                "user_id": "A1",
                "status": "active",
                "permissions": ["read:reports"],
                "name": "Active User",
            },
            {
                "user_id": "I1",
                "status": "inactive",
                "permissions": ["approve:payments", "create:purchase_orders"],
                "name": "Inactive User",
            },
        ]
        results = run_sod_for_all(entitlements)
        user_ids = [r["user_id"] for r in results]
        assert "A1" in user_ids
        assert "I1" not in user_ids

    def test_violation_has_required_fields(self):
        """Each violation entry must have required fields for reporting."""
        result = check_sod_violations("TEST06", ["approve:payments", "create:purchase_orders"])
        violation = result["violations"][0]
        assert "conflict_id" in violation
        assert "permission_a" in violation
        assert "permission_b" in violation
        assert "risk_level" in violation
        assert "rationale" in violation
