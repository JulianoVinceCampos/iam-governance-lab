"""Report generation - CSV and Markdown evidence export."""

import csv
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_THIS_DIR = Path(__file__).parent
_PROJECT_ROOT = _THIS_DIR.parent.parent
REPORTS_DIR = _PROJECT_ROOT / "reports"


def _now_str() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H-%M-%SZ")


def _safe_name(name: str) -> str:
    return name.replace(" ", "_").lower()


def export_csv(campaign: dict[str, Any]) -> Path:
    """Export campaign review items as CSV evidence."""
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    campaign_name = _safe_name(campaign["campaign_name"])
    filepath = REPORTS_DIR / f"access_review_{campaign_name}_{_now_str()}.csv"

    fieldnames = [
        "item_id",
        "user_id",
        "user_name",
        "department",
        "user_role",
        "application",
        "reviewer",
        "decision",
        "decision_timestamp",
        "justification",
    ]

    with filepath.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(campaign["items"])

    return filepath


def export_markdown(campaign: dict[str, Any], sod_results: list[dict[str, Any]] | None = None) -> Path:
    """Export campaign as a Markdown report with executive summary and evidence table."""
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    campaign_name = _safe_name(campaign["campaign_name"])
    filepath = REPORTS_DIR / f"access_review_{campaign_name}_{_now_str()}.md"

    lines: list[str] = []

    # Title
    lines.append(f"# Access Review Evidence Report")
    lines.append(f"")
    lines.append(f"**Campaign:** {campaign['campaign_name']}")
    lines.append(f"**Generated At:** {_now_str().replace('-', ':', 2)}")
    lines.append(f"**Status:** {campaign['status'].upper()}")
    lines.append(f"")

    # Executive Summary
    lines.append(f"## Executive Summary")
    lines.append(f"")
    total = campaign["total_items"]
    approved = campaign["approved"]
    denied = campaign["denied"]
    users = campaign["users_reviewed"]
    approval_rate = (approved / total * 100) if total > 0 else 0

    lines.append(f"| Metric | Value |")
    lines.append(f"|--------|-------|")
    lines.append(f"| Users Reviewed | {users} |")
    lines.append(f"| Total Review Items | {total} |")
    lines.append(f"| Approved | {approved} ({approval_rate:.1f}%) |")
    lines.append(f"| Denied / Flagged | {denied} |")
    lines.append(f"| Campaign Started | {campaign['started_at']} |")
    lines.append(f"")

    # SoD summary if provided
    if sod_results:
        violators = [r for r in sod_results if not r["clean"]]
        lines.append(f"## Segregation of Duties (SoD) Summary")
        lines.append(f"")
        if violators:
            lines.append(f"> **WARNING:** {len(violators)} user(s) have SoD conflicts that require immediate remediation.")
            lines.append(f"")
            lines.append(f"| User ID | Name | Critical | High |")
            lines.append(f"|---------|------|----------|------|")
            for v in violators:
                lines.append(f"| {v['user_id']} | {v.get('name','')} | {v['critical_count']} | {v['high_count']} |")
        else:
            lines.append(f"> No SoD violations detected across all reviewed users.")
        lines.append(f"")

    # Denied items - requires attention
    denied_items = [i for i in campaign["items"] if i["decision"] == "deny"]
    if denied_items:
        lines.append(f"## Items Requiring Remediation ({len(denied_items)})")
        lines.append(f"")
        lines.append(f"The following access items were **DENIED** and must be revoked:")
        lines.append(f"")
        lines.append(f"| User | Department | Application | Reviewer | Justification |")
        lines.append(f"|------|-----------|-------------|----------|---------------|")
        for item in denied_items:
            lines.append(
                f"| {item['user_name']} ({item['user_id']}) "
                f"| {item['department']} "
                f"| {item['application']} "
                f"| {item['reviewer']} "
                f"| {item['justification']} |"
            )
        lines.append(f"")

    # Full evidence table
    lines.append(f"## Full Evidence - All Review Items")
    lines.append(f"")
    lines.append(f"| Item ID | User | Role | Department | Application | Decision | Reviewer | Timestamp |")
    lines.append(f"|---------|------|------|-----------|-------------|----------|----------|-----------|")

    for item in campaign["items"]:
        decision_badge = "APPROVED" if item["decision"] == "approve" else "**DENIED**"
        lines.append(
            f"| {item['item_id']} "
            f"| {item['user_name']} "
            f"| {item['user_role']} "
            f"| {item['department']} "
            f"| {item['application']} "
            f"| {decision_badge} "
            f"| {item['reviewer']} "
            f"| {item['decision_timestamp']} |"
        )

    lines.append(f"")
    lines.append(f"---")
    lines.append(f"*Report generated by IAM Governance Lab - for internal compliance use only.*")

    with filepath.open("w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    return filepath


def export_sod_report(sod_results: list[dict[str, Any]]) -> Path:
    """Export SoD check results as a CSV."""
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    filepath = REPORTS_DIR / f"sod_report_{_now_str()}.csv"

    rows = []
    for result in sod_results:
        if result["violations"]:
            for v in result["violations"]:
                rows.append({
                    "user_id": result["user_id"],
                    "name": result.get("name", ""),
                    "conflict_id": v["conflict_id"],
                    "permission_a": v["permission_a"],
                    "permission_b": v["permission_b"],
                    "risk_level": v["risk_level"],
                    "rationale": v["rationale"],
                })
        else:
            rows.append({
                "user_id": result["user_id"],
                "name": result.get("name", ""),
                "conflict_id": "NONE",
                "permission_a": "",
                "permission_b": "",
                "risk_level": "clean",
                "rationale": "No violations found.",
            })

    fieldnames = ["user_id", "name", "conflict_id", "permission_a", "permission_b", "risk_level", "rationale"]
    with filepath.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    return filepath
