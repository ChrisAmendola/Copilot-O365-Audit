# Copilot O365 Over-Permissioning Audit

Microsoft Copilot can only surface content a user can already access. This project helps you find **over-permissioned** Microsoft 365 content—SharePoint, OneDrive, Teams, Exchange, and related group/site ACLs—before or during Copilot rollouts.

## Primary script

**`copilot_audit.ps1`** is the tenant-wide entry point. It builds a principal→resource permission graph, emits actionable **findings**, and exports coverage metadata so operators know what was (and was not) scanned.

Use **`Copilot-OverPermissionAudit.ps1`** only for legacy **per-user deep dives** when you need the older single-user workflow. Tenant-wide over-permissioning audits should use `copilot_audit.ps1`.

## Quick start

```powershell
.\copilot_audit.ps1 -TenantName contoso.com
```

**Unattended (recommended for registered app):** with `-GraphAppId` + certificate (or `.graph-app.local.ps1` from `-RegisterGraphApp`), the audit uses **application permissions only** — no interactive Graph, Exchange, SPO, or PnP logins. SharePoint/OneDrive/Teams/Entra collectors run via Graph. Exchange mailbox findings run via EXO app-only when the app has a certificate, `Exchange.ManageAsApp`, and the **Exchange Administrator** role on the app’s service principal.

**Delegated (default without GraphAppId):** interactive Graph + optional Exchange/SPO sign-in, pinned to `-TenantName`.

## Key parameters

| Parameter | Purpose |
| --- | --- |
| `-TenantName` | Target tenant (SharePoint prefix, DNS domain, or tenant GUID). Pins Graph, Exchange, and SPO. |
| `-Users` / `-UserListPath` | Optional user scope for reporting and OneDrive sampling. Resources are still scanned tenant-wide. Also auto-enables the **user reach map** (SharedWithMe + membership edges). |
| `-CopilotLicensedOnly` | When no explicit user list is supplied, limits user reporting and OneDrive sampling to enabled users with a Copilot SKU. |
| `-IncludeUserReachMap` / `-SkipUserReachMap` | Force or disable the scoped-user Copilot reach map (auto-on when user scope is active). |
| `-UserReachMaxItems` | Cap SharedWithMe items per scoped user (default: 500). |
| `-UserReachMaxOwnerDrives` | Cap other users’ OneDrive drives reverse-scanned for direct grants to scoped users (default: 100). Graph `sharedWithMe` is deprecated and often empty. |
| `-UserReachReverseMaxDepth` | Max folder depth for reverse OneDrive grant scan (default: 3). |
| `-UserReachReverseMaxFolders` | Max folders inspected per owner drive in reverse grant scan (default: 60). |
| `-UserReachIncomingShareFindingThreshold` | Emit an IncomingShare finding when inbound share/grant count reaches this threshold (default: 25). |
| `-UserReachReverseSiteAcl` | Optional capped reverse ACL on prioritized risky sites for grants naming the scoped user. |
| `-GraphAppId` | Entra app (client) ID for **app-only** Graph (enables reverse OneDrive ACL across users). |
| `-GraphCertificateThumbprint` / `-GraphCertificatePath` | Certificate for app-only Graph (preferred over secret). Optional `-GraphCertificatePassword` for PFX. |
| `-GraphClientSecret` / `-GraphClientSecretEnvVar` | Client secret for app-only Graph (SecureString or env var name). Prefer env var for clean-child relaunch. |
| `-RegisterGraphApp` / `-RegisterGraphAppOnly` | Create Entra app + certificate (+ Graph app roles, `Exchange.ManageAsApp`, attempt admin consent / Exchange Administrator). Writes `.graph-app.local.ps1` + `.graph-app.local.pfx`. `Only` exits after registration. |
| `-GraphAppDisplayName` / `-GraphAppSecretValidMonths` | Name (default `Copilot-O365-OverPermission-Audit`) and certificate validity months (default 12) for registration. |
| `-BaselinePath` | CSV of expected access (`UserPrincipalName`, `ResourceType`, `ResourceId`, `ExpectedRole`). Matching findings are **Expected**; others are **Unexpected**. |
| `-ExchangeDeviceLogin` | Non-WAM Exchange sign-in for terminals where WAM fails (Cursor, VS Code). |
| `-DirectShareFanInThreshold` | Min distinct named user/group grants on a sampled drive item before a DirectShareFanIn finding (default: 15). |
| `-OutputPath` | Base folder for timestamped run output (default: `CopilotExposureOutput`). |

**Skip switches** (when a role or module is unavailable): `-SkipExchange`, `-SkipSharePointSites`, `-SkipOneDriveSample`, `-SkipSharePointContentSample`.

**Sampling caps** (Depth B — honest limits): `-BroadSharingMaxItems`, `-BroadSharingMaxDepth`, `-MaxSitesForContentSample`, `-MaxUsersForOneDriveSample`.

## Outputs

Each run creates a timestamped folder under `-OutputPath` (e.g. `CopilotExposureOutput\run-20260716-123116\`):

| File | Description |
| --- | --- |
| `findings.csv` | Primary audit deliverable — workload, resource, permission, severity, baseline status, remediation |
| `user-reach-by-principal.csv` | Scoped-user **incoming** Copilot reach (SharedWithMe + membership/delegation edges; sharer when known) |
| `coverage.json` | What was scanned, caps hit, skips/failures, and confidence limits |
| `executive-report.html` | Human-readable summary with findings and audit coverage |
| `nodes.csv`, `edges.csv` | Permission graph inventory |
| `users-by-blast-radius.csv`, `resources-by-blast-radius.csv` | Legacy fan-in ranking (findings are authoritative) |

## Example runs

```powershell
# Full tenant audit (Copilot-licensed users only)
.\copilot_audit.ps1 -TenantName contoso.com -CopilotLicensedOnly -ExchangeDeviceLogin

# Compare against expected access baseline
.\copilot_audit.ps1 -TenantName contoso.com -BaselinePath .\Copilot-OverPermission-baseline.example.csv

# Scoped user list with device-code Exchange auth (includes user reach map)
.\copilot_audit.ps1 -TenantName contoso.com -UserListPath .\users.txt -ExchangeDeviceLogin

# Scoped reach map + optional reverse ACL on prioritized risky sites
.\copilot_audit.ps1 -TenantName contoso.com -Users 'alice@contoso.com' -UserReachReverseSiteAcl -ExchangeDeviceLogin

# Admin inbound OneDrive reach via app-only Graph (certificate preferred)
.\copilot_audit.ps1 -TenantName contoso.com -Users 'alice@contoso.com' `
  -GraphAppId '00000000-0000-0000-0000-000000000000' `
  -GraphCertificateThumbprint 'ABC123...' `
  -ExchangeDeviceLogin

# Partial run when SharePoint Admin role is unavailable
.\copilot_audit.ps1 -TenantName contoso.com -SkipSharePointSites -SkipSharePointContentSample
```

## App-only Graph + Exchange setup

### Option A — script creates the app + certificate

```powershell
# Creates Entra app + cert, Graph app roles, Exchange.ManageAsApp, attempts admin consent /
# Exchange Administrator on the app SP, writes .graph-app.local.ps1 + .graph-app.local.pfx, then exits
.\copilot_audit.ps1 -TenantName contoso.com -RegisterGraphAppOnly
```

Sign in as Application Administrator / Global Administrator when prompted. Helper + PFX are gitignored.

```powershell
# Dot-source helper, then unattended audit (Graph + EXO app-only; no user logins)
. .\.graph-app.local.ps1
.\copilot_audit.ps1 -TenantName contoso.com -Users 'alice@contoso.com'
```

Reads `COPILOT_GRAPH_APP_ID` / `COPILOT_GRAPH_CERT_THUMBPRINT` (and optional PFX path/password). Or use `-RegisterGraphApp` (without `Only`) to create and continue in one run.

### Option B — manual Entra app

1. In Entra ID, register an application (or reuse one).
2. Add **Application** permissions on Microsoft Graph: `Files.Read.All`, `Sites.Read.All`, `User.Read.All`, `Directory.Read.All`, `Group.Read.All`, `Team.ReadBasic.All`, `TeamMember.Read.All`, `RoleManagement.Read.Directory`.
3. Add **Application** permission on Office 365 Exchange Online: `Exchange.ManageAsApp`.
4. Grant **admin consent**. Assign **Exchange Administrator** to the app’s service principal for mailbox scans.
5. Upload a certificate (required for EXO app-only; preferred for Graph too).
6. Run with `-GraphAppId` + `-GraphCertificateThumbprint` (or PFX path).
7. Confirm `coverage.json` shows `"GraphAuthMode": "AppOnly"` and reverse scan opens owner drives (`UserReachOwnerDrivesScanned` > 0).

## Verification checklist

After a run against a real tenant, operators can confirm behavior with these checks:

1. **SharePoint Everyone** — A site granting Everyone should produce a Critical/High SharePoint finding with a remediation recommendation.
2. **Exchange Full Access** — A mailbox with ≥5 FullAccess delegates should produce an Exchange finding; SendAs-only mailboxes should not rank equally.
3. **OneDrive org-wide link** — An org-wide sharing link in the OneDrive sample should appear as a finding with path evidence.
4. **Copilot-licensed scope** — With `-CopilotLicensedOnly`, the user table is a subset of Copilot-licensed users; org-wide Everyone resources still appear tenant-wide.
5. **Baseline Expected vs Unexpected** — A baseline row marked Expected should yield `BaselineStatus=Expected` and lower severity than an equivalent Unexpected finding.
6. **Missing SPO module** — When the SharePoint Online module is unavailable, the coverage section should show Graph inventory limitations—not a silent “all clear.”
7. **Tenant pinning** — Mixed-tenant sessions must not return; Graph, Exchange, and SPO stay pinned to `-TenantName`.
8. **Output completeness** — The run folder contains `findings.csv`, `coverage.json`, graph CSVs (`nodes.csv`, `edges.csv`, blast-radius CSVs), and `executive-report.html`.
9. **User reach / inbound OneDrive shares (delegated)** — Sign in as B; expect `AccessVia=AccessibleShare` via `/me` search/recent.
10. **User reach / inbound OneDrive shares (app-only)** — With `-GraphAppId` + cert/secret, an admin run with `-Users B` should open other users’ OneDrives and emit `AccessVia=DirectGrant` when A shared a folder with B. `coverage.json` must show `GraphAuthMode=AppOnly`.

## Design docs

- [Over-permissioning revision design](docs/superpowers/specs/2026-07-16-copilot-overpermission-revision-design.md)
- [Implementation plan](docs/superpowers/plans/2026-07-16-copilot-overpermission-revision.md)
- [User reach map design](docs/superpowers/specs/2026-07-16-user-reach-map-design.md)
- [User reach map plan](docs/superpowers/plans/2026-07-16-user-reach-map.md)
- [Graph app-only auth design](docs/superpowers/specs/2026-07-16-graph-app-only-auth-design.md)
- Baseline format: `Copilot-OverPermission-baseline.example.csv`
