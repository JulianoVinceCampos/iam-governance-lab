"""Tests for RBAC and ABAC modules."""

import pytest
from iam_governance.rbac import get_permissions_for_role, get_role, resolve_applications_for_role
from iam_governance.abac import evaluate_abac, evaluate_user_app_access


class TestRBAC:
    def test_analyst_permissions(self):
        perms = get_permissions_for_role("analyst")
        assert "read:reports" in perms
        assert "approve:payments" not in perms

    def test_admin_permissions(self):
        perms = get_permissions_for_role("admin")
        assert "write:users" in perms
        assert "manage:systems" in perms

    def test_unknown_role_returns_empty(self):
        perms = get_permissions_for_role("nonexistent_role")
        assert perms == []

    def test_get_role_returns_dict(self):
        role = get_role("analyst")
        assert role is not None
        assert role["name"] == "analyst"
        assert "permissions" in role

    def test_get_role_unknown_returns_none(self):
        role = get_role("ghost_role")
        assert role is None

    def test_resolve_applications_for_role(self):
        apps = [
            {"id": "APP1", "required_roles": ["analyst", "admin"]},
            {"id": "APP2", "required_roles": ["manager"]},
            {"id": "APP3", "required_roles": ["admin"]},
        ]
        result = resolve_applications_for_role("analyst", apps)
        assert "APP1" in result
        assert "APP2" not in result

    def test_approver_has_approve_payments(self):
        perms = get_permissions_for_role("approver")
        assert "approve:payments" in perms
        assert "approve:purchase_orders" in perms


class TestABAC:
    def test_valid_user_allowed(self):
        user_attrs = {"location": "BR", "clearance": "standard", "contract_type": "full_time"}
        policy = {"allowed_locations": ["BR", "US"], "min_clearance": "standard", "allowed_contracts": ["full_time"]}
        result = evaluate_abac(user_attrs, policy)
        assert result["allowed"] is True
        assert result["violations"] == []

    def test_invalid_location_denied(self):
        user_attrs = {"location": "CN", "clearance": "standard", "contract_type": "full_time"}
        policy = {"allowed_locations": ["BR", "US"]}
        result = evaluate_abac(user_attrs, policy)
        assert result["allowed"] is False
        assert any("Location" in v for v in result["violations"])

    def test_insufficient_clearance_denied(self):
        user_attrs = {"location": "BR", "clearance": "standard", "contract_type": "full_time"}
        policy = {"min_clearance": "high"}
        result = evaluate_abac(user_attrs, policy)
        assert result["allowed"] is False
        assert any("Clearance" in v for v in result["violations"])

    def test_high_clearance_allows_standard_requirement(self):
        user_attrs = {"location": "BR", "clearance": "high", "contract_type": "full_time"}
        policy = {"min_clearance": "standard"}
        result = evaluate_abac(user_attrs, policy)
        assert result["allowed"] is True

    def test_contractor_denied_full_time_only_app(self):
        user_attrs = {"location": "BR", "clearance": "standard", "contract_type": "contractor"}
        policy = {"allowed_contracts": ["full_time"]}
        result = evaluate_abac(user_attrs, policy)
        assert result["allowed"] is False

    def test_multiple_violations_reported(self):
        user_attrs = {"location": "CN", "clearance": "standard", "contract_type": "contractor"}
        policy = {
            "allowed_locations": ["BR"],
            "min_clearance": "high",
            "allowed_contracts": ["full_time"],
        }
        result = evaluate_abac(user_attrs, policy)
        assert result["allowed"] is False
        assert len(result["violations"]) == 3

    def test_empty_policy_always_allows(self):
        user_attrs = {"location": "BR", "clearance": "standard", "contract_type": "full_time"}
        result = evaluate_abac(user_attrs, {})
        assert result["allowed"] is True

    def test_evaluate_user_app_access_returns_ids(self):
        user = {"id": "U001", "attributes": {"location": "BR", "clearance": "standard", "contract_type": "full_time"}}
        app = {"id": "APP001", "name": "ERP", "abac_policy": {"allowed_locations": ["BR"]}}
        result = evaluate_user_app_access(user, app)
        assert result["user_id"] == "U001"
        assert result["app_id"] == "APP001"
        assert result["allowed"] is True
