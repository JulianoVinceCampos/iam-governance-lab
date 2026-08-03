# IAM Governance Lab

> **Mini IGA (Identity Governance and Administration) simulator** in Python with a full CLI.  
> Covers JML lifecycle, Access Reviews, SoD validation, RBAC and ABAC - all in a single local project.

```
 _ __ _ _ __   __ _  _____   __
| |/ _` | '_ \ / _` ||  _  \ / _|
| | (_| | | | | (_| || | | || |_
|_|\__,_|_| |_|\__, ||_| |_||___|
               |___/  Governance Lab
```

[![Tests](https://github.com/JulianoVinceCampos/iam-governance-lab/actions/workflows/test.yml/badge.svg)](https://github.com/JulianoVinceCampos/iam-governance-lab/actions/workflows/test.yml)
[![Lint](https://github.com/JulianoVinceCampos/iam-governance-lab/actions/workflows/lint.yml/badge.svg)](https://github.com/JulianoVinceCampos/iam-governance-lab/actions/workflows/lint.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/)

---

## Table of Contents

- [The Problem](#the-problem)
- [Why This Matters in Enterprises](#why-this-matters-in-enterprises)
- [Architecture](#architecture)
- [Quickstart](#quickstart)
- [CLI Commands](#cli-commands)
- [Data Model](#data-model)
- [Security and Audit](#security-and-audit)
- [Next Steps](#next-steps)
- [Contributing](#contributing)

---

## The Problem

In organizations with hundreds or thousands of employees, answering the following questions manually becomes infeasible:

- **Who has access to what?** ("Who can approve payments in the ERP right now?")
- **Is that access still appropriate?** ("Alice moved to Procurement 3 months ago - does she still have Finance approver rights?")
- **Are there dangerous permission combinations?** ("Does anyone both create AND approve purchase orders?")
- **Was access revoked when someone left?** ("Did we remove all access for the contractor who left last Friday?")

**IGA (Identity Governance and Administration)** is the discipline and tooling that answers these questions systematically. This lab simulates a mini-IGA engine so you can understand the concepts, test policies, and build toward a production solution.

---

## Why This Matters in Enterprises

| Domain | Real Risk Without IGA | How IGA Solves It |
|--------|----------------------|-------------------|
| **Financial Fraud** | An employee creates and self-approves purchase orders | SoD policy blocks conflicting permission combinations |
| **Regulatory Compliance** | SOX, ISO 27001, SOC 2 require evidence of access reviews | Quarterly campaigns with timestamped approve/deny decisions |
| **Data Breach** | A leaver's account remains active for weeks | Automated de-provisioning on HR event trigger |
| **Over-Provisioning** | Users accumulate permissions over time ("permission creep") | Mover event re-provisions from scratch (least privilege) |
| **Audit Findings** | No documentation of who approved what access, when | Evidence export to CSV and Markdown with full audit trail |

**Frameworks that require IGA controls:** SOX (Section 404), ISO/IEC 27001 (A.9), NIST 800-53 (AC-2), CIS Controls (v8 - Control 5 & 6), PCI DSS (Req. 7 & 8).

---

## Architecture

```
iam-governance-lab/
|
|-- data/                       # Static reference data (JSON)
|   |-- users.json              # User directory with attributes
|   |-- roles.json              # RBAC role-to-permission map
|   |-- applications.json       # App catalog with ABAC policies
|   |-- sod_matrix.json         # SoD conflict rules
|   |-- jml_events.json         # Sample HR events (reference only)
|
|-- state/                      # Runtime state (mutable)
|   |-- entitlements.json       # Current access snapshot (after JML events)
|   |-- campaign_<name>.json    # Access review campaign results
|
|-- reports/                    # Generated evidence (gitignored)
|   |-- access_review_*.csv
|   |-- access_review_*.md
|   |-- sod_report_*.csv
|
|-- src/iam_governance/         # Core library
|   |-- cli.py                  # Typer CLI commands
|   |-- jml.py                  # Joiner / Mover / Leaver logic
|   |-- sod.py                  # SoD violation checker
|   |-- access_review.py        # Campaign management
|   |-- rbac.py                 # Role-to-permission resolution
|   |-- abac.py                 # Attribute-based access evaluation
|   |-- reports.py              # CSV + Markdown evidence export
|   |-- state.py                # State file read/write
|
|-- tests/                      # pytest test suite
|-- pyproject.toml              # Dependencies and tool config
|-- Makefile                    # Developer shortcuts
```

### Data Flow

```
HR Event (CLI)
    |
    v
jml.py                rbac.py              abac.py
(lifecycle logic) --> (role->permissions) + (attribute policy)
    |
    v
state/entitlements.json   <-- single source of truth for current access
    |
    +---> sod.py            (check conflicts at any time)
    +---> access_review.py  (periodic certification campaigns)
              |
              v
          reports.py
        (CSV + Markdown)
```

---

## Quickstart

### Prerequisites

- Python 3.10 or higher
- `make` (optional but recommended)

### Installation

```bash
# Clone the repository
git clone https://github.com/JulianoVinceCampos/iam-governance-lab.git
cd iam-governance-lab

# Install with all dev dependencies
make setup

# Verify installation
python -m iam_governance --help
```

---

## CLI Commands

All commands use the `--option value` syntax. Run `--help` on any command for details.

### simulate-joiner

Provisions access for a new hire based on their role (RBAC) and attributes (ABAC).

```bash
python -m iam_governance simulate-joiner --user-id U001
```

**What happens:**
1. Looks up the user in `data/users.json`
2. Resolves permissions from their role via RBAC (`data/roles.json`)
3. Evaluates each application via ABAC policy (`data/applications.json`)
4. Saves the resulting entitlement to `state/entitlements.json`

---

### simulate-mover

Transfers a user to a new department and role, re-provisioning from scratch (least privilege).

```bash
python -m iam_governance simulate-mover \
  --user-id U001 \
  --new-dept Procurement \
  --new-role procurement
```

**What happens:**
1. Loads existing entitlement for the user
2. Revokes ALL current permissions and application access
3. Re-provisions based on new role (RBAC) and unchanged attributes (ABAC)
4. Reports what was revoked and what was granted

---

### simulate-leaver

Immediately revokes all access for a departing employee. Preserves the record with `status: inactive` for audit purposes.

```bash
python -m iam_governance simulate-leaver --user-id U003
```

---

### check-sod

Checks a user (or all active users) for Segregation of Duties violations based on `data/sod_matrix.json`.

```bash
# Check a single user
python -m iam_governance check-sod --user-id U002

# Check ALL active users
python -m iam_governance check-sod
```

**Sample output:**
```
SOD Violation Report
 User ID  Name           Status     Critical  High  Conflicts
 U002     Bruno Martins  VIOLATION  1         0     SOD005
```

---

### run-access-review

Launches an access review campaign for all active users. Simulates reviewer assignment and approve/deny decisions (85% approval rate to reflect realistic outcomes).

```bash
python -m iam_governance run-access-review --campaign-name "Q1-2024-Annual"
```

Campaign is saved to `state/campaign_q1-2024-annual.json` for export.

---

### export-evidence

Exports a completed campaign as audit-ready evidence (CSV + Markdown).

```bash
python -m iam_governance export-evidence --campaign-name "Q1-2024-Annual"

# Without SoD summary
python -m iam_governance export-evidence --campaign-name "Q1-2024-Annual" --no-sod
```

**Outputs:**
- `reports/access_review_q1-2024-annual_<timestamp>.csv` - Full evidence for SIEM/GRC import
- `reports/access_review_q1-2024-annual_<timestamp>.md` - Executive summary + evidence table

---

### Typical End-to-End Flow

```bash
# 1. New employee joins
python -m iam_governance simulate-joiner --user-id U001

# 2. Employee is promoted / transferred
python -m iam_governance simulate-mover --user-id U001 --new-dept Procurement --new-role procurement

# 3. Check for SoD conflicts across all users
python -m iam_governance check-sod

# 4. Run quarterly access review
python -m iam_governance run-access-review --campaign-name "Q2-2024"

# 5. Export evidence for auditors
python -m iam_governance export-evidence --campaign-name "Q2-2024"

# 6. Employee leaves
python -m iam_governance simulate-leaver --user-id U001
```

---

## Data Model

### users.json

```json
{
  "id": "U001",
  "name": "Alice Souza",
  "department": "Finance",
  "role": "analyst",
  "status": "active",
  "attributes": {
    "location": "BR",
    "clearance": "standard",
    "contract_type": "full_time"
  }
}
```

### roles.json

```json
{
  "id": "R001",
  "name": "analyst",
  "permissions": ["read:reports", "read:dashboards", "read:invoices"]
}
```

### sod_matrix.json

```json
{
  "id": "SOD001",
  "permission_a": "approve:payments",
  "permission_b": "create:purchase_orders",
  "risk_level": "critical",
  "rationale": "Enables fraudulent self-approval of transactions."
}
```

### applications.json (ABAC policy per app)

```json
{
  "id": "APP004",
  "name": "IT-Admin-Console",
  "required_roles": ["admin"],
  "abac_policy": {
    "allowed_locations": ["BR"],
    "min_clearance": "high",
    "allowed_contracts": ["full_time"]
  }
}
```

---

## Security and Audit

### What this lab demonstrates

- **Least Privilege Enforcement:** `simulate-mover` always re-provisions from zero, never accumulates permissions. This prevents "permission creep" - one of the most common IGA failures.

- **Immutable Audit Trail:** `simulate-leaver` marks users as `inactive` and preserves the record with a `deprovisioned_at` timestamp. Records are never hard-deleted.

- **Evidence-Based Reviews:** Every access review item is stamped with reviewer identity, decision, and ISO 8601 timestamp - ready for SOX or ISO 27001 audit requests.

- **Conflict Detection:** SoD checks run against a version-controlled conflict matrix. Adding a new rule (`data/sod_matrix.json`) automatically applies to all users on the next check.

- **Attribute-Based Controls:** ABAC policies per application enforce controls like "only Brazilian full-time employees can access the IT Admin Console" - without hard-coding these rules in role definitions.

### What to add for production

- Encrypt `state/entitlements.json` at rest
- Sign reports with a private key before delivery to auditors
- Store state in a database (PostgreSQL) with row-level audit logging
- Add MFA requirement tracking as an ABAC attribute
- Implement a "certifier" authentication flow (not auto-simulation)

---

## Next Steps

This lab is a foundation. Here is a maturity roadmap:

### Phase 1 - Integration

| Area | Tool/Standard | Notes |
|------|--------------|-------|
| Identity Provider | Okta, Entra ID, Ping | Replace `users.json` with SCIM API calls |
| ITSM | ServiceNow, Jira Service Mgmt | JML events triggered from ticket approval |
| HR System | Workday, SuccessFactors | Automated JML on hire/transfer/terminate |
| SIEM | Splunk, Microsoft Sentinel | Stream SoD violations as security events |

### Phase 2 - Real IGA Platform

When the complexity outgrows this simulator, consider:

- **Saviynt** - Cloud-native IGA with built-in SoD analytics
- **SailPoint IdentityNow** - Market leader for enterprise IGA
- **One Identity Manager** - Strong for hybrid on-prem/cloud
- **IBM Security Verify Governance** - Preferred for regulated industries

### Phase 3 - Advanced Governance

- **Risk scoring** per user (composite SoD risk + orphaned accounts + dormant access)
- **ML-based access recommendations** using peer group analysis
- **Continuous controls monitoring** (SoD checked in real-time, not just on demand)
- **PBAC (Policy-Based Access Control)** for fine-grained authorization
- **Zero Standing Privileges (ZSP)** - Just-In-Time access provisioning

---

## Development

```bash
make setup    # Install all dependencies
make test     # Run pytest suite
make lint     # Run ruff linter
make run      # Show CLI help
```

### Running tests with coverage

```bash
pytest tests/ --cov=src/iam_governance --cov-report=html
open htmlcov/index.html
```

---

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/add-risk-scoring`)
3. Commit your changes (`git commit -m 'Add: risk scoring module'`)
4. Push the branch (`git push origin feature/add-risk-scoring`)
5. Open a Pull Request

Please read [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) before contributing.

---

## License

MIT License - see [LICENSE](LICENSE) for details.

---

*Built to make IAM/IGA concepts tangible for engineers, security architects, and compliance teams.*
