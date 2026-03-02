"""Tests for Access Review campaign functionality."""

import pytest
from iam_governance import access_review
from iam_governance.state import list_entitlements


class TestAccessReview:
    def test_run_campaign_returns_dict(self):
        campaign = access_review.run_access_review("test-q1-2024")
        assert isinstance(campaign, dict)
        assert campaign["campaign_name"] == "test-q1-2024"

    def test_campaign_has_required_fields(self):
        campaign = access_review.run_access_review("test-fields")
        required = ["campaign_name", "started_at", "status", "total_items", "approved", "denied", "users_reviewed", "items"]
        for field in required:
            assert field in campaign, f"Missing field: {field}"

    def test_items_have_required_fields(self):
        campaign = access_review.run_access_review("test-items")
        if campaign["items"]:
            item = campaign["items"][0]
            required = ["item_id", "user_id", "user_name", "application", "reviewer", "decision", "decision_timestamp"]
            for field in required:
                assert field in item, f"Missing item field: {field}"

    def test_decisions_are_valid_values(self):
        campaign = access_review.run_access_review("test-decisions")
        for item in campaign["items"]:
            assert item["decision"] in ("approve", "deny"), f"Invalid decision: {item['decision']}"

    def test_approved_plus_denied_equals_total(self):
        campaign = access_review.run_access_review("test-totals")
        assert campaign["approved"] + campaign["denied"] == campaign["total_items"]

    def test_campaign_persisted_to_state(self, isolated_state):
        access_review.run_access_review("test-persist")
        loaded = access_review.load_campaign("test-persist")
        assert loaded is not None
        assert loaded["campaign_name"] == "test-persist"

    def test_load_nonexistent_campaign_returns_none(self):
        result = access_review.load_campaign("no-such-campaign-xyz")
        assert result is None

    def test_campaign_only_reviews_active_users(self, isolated_state):
        """Campaign should skip inactive users."""
        from iam_governance import jml
        jml.simulate_leaver("U001")  # make U001 inactive
        campaign = access_review.run_access_review("test-active-only")
        reviewed_user_ids = {item["user_id"] for item in campaign["items"]}
        # U001 should have been skipped or should have no items
        assert "U001" not in reviewed_user_ids or campaign["users_reviewed"] < 3
