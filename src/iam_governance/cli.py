"""CLI entry point - all commands defined here using Typer."""

from typing import Optional
import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

from iam_governance import jml, sod, access_review, reports
from iam_governance.state import get_entitlement, list_entitlements

app = typer.Typer(
    name="iam-governance",
    help="IAM Governance Lab - Mini IGA simulator for JML, SoD, RBAC, ABAC and Access Reviews.",
    no_args_is_help=True,
    rich_markup_mode="rich",
)

console = Console()


# ---------------------------------------------------------------------------
# JML Commands
# ---------------------------------------------------------------------------


@app.command("simulate-joiner")
def cmd_simulate_joiner(
    user_id: str = typer.Option(..., "--user-id", help="User ID from data/users.json"),
) -> None:
    """Provision access for a new hire (Joiner). Assigns role-based permissions and app access."""
    console.rule("[bold green]JML - Joiner Event[/bold green]")
    result = jml.simulate_joiner(user_id)

    if not result["success"]:
        console.print(f"[bold red]ERROR:[/bold red] {result['error']}")
        raise typer.Exit(1)

    console.print(f"[bold green]SUCCESS:[/bold green] User [cyan]{result['name']}[/cyan] ({user_id}) provisioned.")
    console.print(f"  Role       : [yellow]{result['role']}[/yellow]")
    console.print(f"  Applications provisioned: [green]{result['provisioned_applications']}[/green]")
    console.print(f"  Permissions: {result['permissions']}")

    if result["denied_applications"]:
        console.print(f"  [orange3]ABAC denied access to:[/orange3]")
        for denied in result["denied_applications"]:
            console.print(f"    - {denied['app_id']}: {denied['reasons']}")


@app.command("simulate-mover")
def cmd_simulate_mover(
    user_id: str = typer.Option(..., "--user-id", help="User ID to transfer"),
    new_dept: str = typer.Option(..., "--new-dept", help="New department name"),
    new_role: str = typer.Option(..., "--new-role", help="New role name (must exist in data/roles.json)"),
) -> None:
    """Transfer user to a new department/role (Mover). Re-provisions access via least-privilege."""
    console.rule("[bold yellow]JML - Mover Event[/bold yellow]")
    result = jml.simulate_mover(user_id, new_dept, new_role)

    if not result["success"]:
        console.print(f"[bold red]ERROR:[/bold red] {result['error']}")
        raise typer.Exit(1)

    console.print(f"[bold green]SUCCESS:[/bold green] {result['name']} moved from [yellow]{result['old_department']}[/yellow] to [cyan]{result['new_department']}[/cyan].")
    console.print(f"  Old role -> New role: [yellow]{result['old_role']}[/yellow] -> [green]{result['new_role']}[/green]")
    console.print(f"  Old apps: {result['old_applications']}")
    console.print(f"  New apps: {result['new_applications']}")
    if result["revoked_permissions"]:
        console.print(f"  [red]Revoked permissions:[/red] {result['revoked_permissions']}")
    if result["granted_permissions"]:
        console.print(f"  [green]Granted permissions:[/green] {result['granted_permissions']}")


@app.command("simulate-leaver")
def cmd_simulate_leaver(
    user_id: str = typer.Option(..., "--user-id", help="User ID of the departing employee"),
) -> None:
    """Revoke all access for a departing employee (Leaver). Preserves audit trail."""
    console.rule("[bold red]JML - Leaver Event[/bold red]")
    result = jml.simulate_leaver(user_id)

    if not result["success"]:
        console.print(f"[bold red]ERROR:[/bold red] {result['error']}")
        raise typer.Exit(1)

    console.print(f"[bold green]SUCCESS:[/bold green] {result['name']} ({user_id}) fully de-provisioned.")
    console.print(f"  Revoked applications : [red]{result['revoked_applications']}[/red]")
    console.print(f"  Revoked permissions  : [red]{result['revoked_permissions']}[/red]")
    console.print(f"  Timestamp            : {result['deprovisioned_at']}")


# ---------------------------------------------------------------------------
# SoD Command
# ---------------------------------------------------------------------------


@app.command("check-sod")
def cmd_check_sod(
    user_id: Optional[str] = typer.Option(None, "--user-id", help="User ID to check (omit to check ALL active users)"),
) -> None:
    """Check Segregation of Duties violations against the SoD conflict matrix."""
    console.rule("[bold magenta]SoD - Segregation of Duties Check[/bold magenta]")

    if user_id:
        record = get_entitlement(user_id)
        if record is None:
            console.print(f"[bold red]ERROR:[/bold red] No entitlement found for '{user_id}'.")
            raise typer.Exit(1)
        if record.get("status") != "active":
            console.print(f"[yellow]User '{user_id}' is inactive. Skipping SoD check.[/yellow]")
            return
        results = [sod.check_sod_violations(user_id, record.get("permissions", []))]
        results[0]["name"] = record.get("name", "")
    else:
        entitlements = list_entitlements()
        results = sod.run_sod_for_all(entitlements)

    # Build results table
    table = Table(title="SoD Violation Report", box=box.ROUNDED)
    table.add_column("User ID", style="cyan")
    table.add_column("Name")
    table.add_column("Status", justify="center")
    table.add_column("Critical", justify="center", style="red")
    table.add_column("High", justify="center", style="orange3")
    table.add_column("Conflicts")

    for result in results:
        status = "[green]CLEAN[/green]" if result["clean"] else "[bold red]VIOLATION[/bold red]"
        conflict_ids = ", ".join(v["conflict_id"] for v in result["violations"]) or "-"
        table.add_row(
            result["user_id"],
            result.get("name", ""),
            status,
            str(result["critical_count"]),
            str(result["high_count"]),
            conflict_ids,
        )

    console.print(table)

    # Print details for violations
    for result in results:
        if not result["clean"]:
            console.print(f"\n[bold red]Violation details for {result['user_id']} ({result.get('name','')}):[/bold red]")
            for v in result["violations"]:
                console.print(
                    Panel(
                        f"[bold]{v['conflict_id']}[/bold] - Risk: [red]{v['risk_level'].upper()}[/red]\n"
                        f"Permission A: [yellow]{v['permission_a']}[/yellow]\n"
                        f"Permission B: [yellow]{v['permission_b']}[/yellow]\n"
                        f"Rationale: {v['rationale']}",
                        title="Conflict",
                        border_style="red",
                    )
                )

    violations_found = sum(1 for r in results if not r["clean"])
    if violations_found == 0:
        console.print("\n[bold green]All checked users are SoD-compliant.[/bold green]")
    else:
        console.print(f"\n[bold red]{violations_found} user(s) have SoD violations requiring remediation.[/bold red]")


# ---------------------------------------------------------------------------
# Access Review Commands
# ---------------------------------------------------------------------------


@app.command("run-access-review")
def cmd_run_access_review(
    campaign_name: str = typer.Option(..., "--campaign-name", help="Unique name for this review campaign"),
) -> None:
    """Launch an access review campaign. Generates review items for all active users."""
    console.rule("[bold blue]Access Review Campaign[/bold blue]")

    campaign = access_review.run_access_review(campaign_name)

    table = Table(title=f"Campaign: {campaign_name}", box=box.ROUNDED)
    table.add_column("User", style="cyan")
    table.add_column("Dept")
    table.add_column("Role")
    table.add_column("Application")
    table.add_column("Reviewer")
    table.add_column("Decision", justify="center")
    table.add_column("Timestamp")

    for item in campaign["items"]:
        decision_style = "green" if item["decision"] == "approve" else "bold red"
        table.add_row(
            item["user_name"],
            item["department"],
            item["user_role"],
            item["application"],
            item["reviewer"],
            f"[{decision_style}]{item['decision'].upper()}[/{decision_style}]",
            item["decision_timestamp"],
        )

    console.print(table)
    console.print(f"\n[bold]Summary:[/bold]")
    console.print(f"  Users reviewed  : {campaign['users_reviewed']}")
    console.print(f"  Total items     : {campaign['total_items']}")
    console.print(f"  Approved        : [green]{campaign['approved']}[/green]")
    console.print(f"  Denied          : [red]{campaign['denied']}[/red]")
    console.print(f"\nCampaign saved to state/. Run [bold]export-evidence --campaign-name \"{campaign_name}\"[/bold] to generate reports.")


@app.command("export-evidence")
def cmd_export_evidence(
    campaign_name: str = typer.Option(..., "--campaign-name", help="Campaign name to export"),
    include_sod: bool = typer.Option(True, "--include-sod/--no-sod", help="Include SoD summary in Markdown report"),
) -> None:
    """Export access review evidence as CSV and Markdown reports."""
    console.rule("[bold blue]Evidence Export[/bold blue]")

    campaign = access_review.load_campaign(campaign_name)
    if campaign is None:
        console.print(f"[bold red]ERROR:[/bold red] Campaign '{campaign_name}' not found. Run run-access-review first.")
        raise typer.Exit(1)

    # SoD results for Markdown report
    sod_results = None
    if include_sod:
        entitlements = list_entitlements()
        sod_results = sod.run_sod_for_all(entitlements)

    csv_path = reports.export_csv(campaign)
    md_path = reports.export_markdown(campaign, sod_results)

    console.print(f"[bold green]Evidence exported successfully:[/bold green]")
    console.print(f"  CSV      : [cyan]{csv_path}[/cyan]")
    console.print(f"  Markdown : [cyan]{md_path}[/cyan]")
    console.print(f"\nApproved : [green]{campaign['approved']}[/green]  |  Denied: [red]{campaign['denied']}[/red]  |  Total: {campaign['total_items']}")
