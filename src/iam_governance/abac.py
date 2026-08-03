"""ABAC - Attribute-Based Access Control.

Evaluates whether a user's attributes satisfy an application's ABAC policy.
Policy attributes checked:
  - allowed_locations: user location must be in the list
  - min_clearance: user clearance must meet minimum level
  - allowed_contracts: user contract_type must be in the list
"""

from typing import Any

CLEARANCE_LEVELS = {"standard": 1, "high": 2, "top_secret": 3}


def evaluate_abac(user_attributes: dict[str, Any], abac_policy: dict[str, Any]) -> dict[str, Any]:
    """
    Evaluate ABAC policy for a user.

    Returns a dict:
      { "allowed": bool, "violations": list[str] }
    """
    violations: list[str] = []

    # Check location
    allowed_locations = abac_policy.get("allowed_locations", [])
    if allowed_locations:
        user_location = user_attributes.get("location", "")
        if user_location not in allowed_locations:
            violations.append(
                f"Location '{user_location}' not in allowed locations {allowed_locations}"
            )

    # Check clearance level
    min_clearance = abac_policy.get("min_clearance", "standard")
    user_clearance = user_attributes.get("clearance", "standard")
    min_level = CLEARANCE_LEVELS.get(min_clearance, 1)
    user_level = CLEARANCE_LEVELS.get(user_clearance, 1)
    if user_level < min_level:
        violations.append(
            f"Clearance '{user_clearance}' is below required minimum '{min_clearance}'"
        )

    # Check contract type
    allowed_contracts = abac_policy.get("allowed_contracts", [])
    if allowed_contracts:
        user_contract = user_attributes.get("contract_type", "")
        if user_contract not in allowed_contracts:
            violations.append(
                f"Contract type '{user_contract}' not in allowed contracts {allowed_contracts}"
            )

    return {"allowed": len(violations) == 0, "violations": violations}


def evaluate_user_app_access(user: dict[str, Any], application: dict[str, Any]) -> dict[str, Any]:
    """Convenience wrapper to evaluate ABAC for a user against a specific application."""
    abac_policy = application.get("abac_policy", {})
    user_attrs = user.get("attributes", {})
    result = evaluate_abac(user_attrs, abac_policy)
    result["user_id"] = user.get("id") or user.get("user_id")
    result["app_id"] = application.get("id")
    result["app_name"] = application.get("name")
    return result
