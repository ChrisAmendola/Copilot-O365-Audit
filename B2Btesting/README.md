# Cross-tenant Global Reader example (AA → BB)

This folder demonstrates how **home tenant AA** can call Microsoft Graph in **resource tenant BB** with broad **read-only** directory access.

It uses:

- A **multi-tenant** Entra app registration (created in AA)
- **Admin consent** in BB (creates BB’s Enterprise app / service principal)
- **Graph application permissions** on that SP in BB
- Entra directory role **Global Reader** on that SP in BB
- **Certificate** client credentials (no client secret)

> Naming note: people often say “B2B app” for this pattern. It is **not** the same as inviting a guest user (B2B collaboration). Guests are optional and unused here. Access is **application identity** into BB.

> Role note: use **Global Reader**, not Global Administrator. Global Admin is full write; Global Reader is the broad read-only directory role.

## Mental model

```text
Tenant AA (home / operator)                 Tenant BB (resource)
─────────────────────────────────           ─────────────────────────────────
App registration (multi-tenant)      ──►    Service principal (same appId)
Certificate private key                     Admin consent (Graph app roles)
                                            Global Reader on that SP

Connect-MgGraph -TenantId BB ...     ──►    Token issued for BB
```

Permissions that matter for BB are stored **in BB** (consent grants + role assignment). AA only holds the app definition and the private key.

## Prerequisites

| Actor | Needs |
| --- | --- |
| AA operator (Home / Test) | PowerShell 5.1+, `Microsoft.Graph.Authentication`, rights to create apps (`Application.ReadWrite.All`, etc.) |
| BB Global Admin | Can open admin consent URL; run Resource mode (`RoleManagement.ReadWrite.Directory`) |
| Operator host | Certificate in `CurrentUser\My` (or PFX from helper) |

Install Graph auth once:

```powershell
Install-Module Microsoft.Graph.Authentication -Scope CurrentUser -Force
```

## Files

| File | Purpose |
| --- | --- |
| `b2b-global-reader-example.ps1` | Home / Resource / Test automation for AA→BB Global Reader access |
| `Audit-MultiTenantApps.ps1` | Inventory multi-tenant app registrations + inbound external enterprise apps |
| `.b2b-global-reader.local.ps1` | Generated helper (AppId + cert env) — **do not commit** |
| `.b2b-global-reader.local.pfx` | Generated PFX — **do not commit** |
| `README.md` | This document |

## End-to-end steps

Replace GUIDs with your AA and BB tenant IDs.

### 1. Home mode (tenant AA)

Sign in as Application Administrator or Global Administrator in **AA**:

```powershell
cd '.\B2Btesting'
.\b2b-global-reader-example.ps1 -Mode Home -TenantId 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
```

Creates:

- Multi-tenant app (`signInAudience = AzureADMultipleOrgs`)
- Certificate in `CurrentUser\My` + `.b2b-global-reader.local.pfx`
- Helper `.b2b-global-reader.local.ps1`
- Prints BB admin-consent URL

### 2. Admin consent (tenant BB)

A **BB** Global Admin opens (replace BB tenant id and client id):

```text
https://login.microsoftonline.com/{BB-TENANT-ID}/adminconsent?client_id={APP-ID}
```

This creates the Enterprise application (service principal) in BB.

### 3. Resource mode (tenant BB)

Still as a BB privileged admin:

```powershell
.\b2b-global-reader-example.ps1 -Mode Resource `
  -TenantId 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb' `
  -AppId '<client-id-from-home>'
```

This:

- Confirms the SP exists in BB
- Assigns the Graph **application** roles listed below (if missing)
- Assigns **Global Reader** to that SP

### 4. Test mode (from AA operator host)

```powershell
. .\.b2b-global-reader.local.ps1
.\b2b-global-reader-example.ps1 -Mode Test `
  -TenantId 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa' `
  -ResourceTenantId 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb'
```

Connects **app-only into BB** and reads `/organization` plus `/directoryRoles`.

Equivalent manual connect:

```powershell
Connect-MgGraph -TenantId '<BB-TENANT-ID>' `
  -ClientId '<APP-ID>' `
  -CertificateThumbprint '<THUMBPRINT>'
```

## Graph application permissions requested

These are declared on the app and assigned in BB during Resource mode:

- `Directory.Read.All`
- `User.Read.All`
- `Group.Read.All`
- `Organization.Read.All`
- `RoleManagement.Read.Directory`
- `AuditLog.Read.All`
- `Policy.Read.All`

**Global Reader** unlocks broad Entra read experiences; Graph still requires matching **application** permissions for the APIs you call. Role alone is not enough for app-only Graph.

## How permissions are maintained in BB

| Artifact in BB | Purpose |
| --- | --- |
| Enterprise app / service principal (`appId` = client ID) | Local instance of AA’s app |
| `appRoleAssignment` on Microsoft Graph SP | Application permissions |
| `unifiedRoleAssignment` → Global Reader | Directory role for the app SP |
| Conditional Access / Enterprise app policies (optional) | Extra AA/BB controls |

Revoking access in BB: remove role assignment, revoke app role assignments, and/or delete the Enterprise app. That does not delete the app registration in AA.

## Security

- Anyone with the **private key** can act as this app in every resource tenant where it is consented and role-assigned. Treat the PFX like a break-glass credential.
- Prefer certificate over client secret (this example uses cert only).
- Prefer **Global Reader** over Global Administrator.
- Do not commit `.b2b-global-reader.local.*` files.
- For MSP / partner customer access at scale, consider **GDAP** instead of putting Global Reader on a long-lived app SP.

## Troubleshooting

| Symptom | Likely cause |
| --- | --- |
| Resource mode: SP not found | Admin consent in BB not completed |
| Test: `AADSTS700016` / app not found in BB | Wrong BB tenant id or consent not done |
| Test: 403 on Graph | Missing app role assignment or consent in BB |
| Test: cert not found | Dot-source helper or import PFX into `CurrentUser\My` |
| Role assignment fails | Caller lacks `RoleManagement.ReadWrite.Directory` / Privileged Role Admin |

## Multi-tenant / B2B application inventory audit

[`Audit-MultiTenantApps.ps1`](Audit-MultiTenantApps.ps1) lists application IDs in a tenant that participate in cross-tenant patterns and flags security concerns.

### What it inventories

| Direction | Source | Meaning |
| --- | --- | --- |
| **Outbound** | App registrations with `signInAudience` = `AzureADMultipleOrgs` or `AzureADandPersonalMicrosoftAccount` | Apps **this tenant publishes** that other tenants can admin-consent |
| **Inbound** | Service principals whose `appOwnerOrganizationId` ≠ this tenant | Apps from **other tenants** (third-party multi-tenant) consented into this tenant |

Microsoft first-party inbound apps are **excluded by default** (noisy). Pass `-IncludeMicrosoftFirstParty` to include them.

### Where it looks for service-principal access

The audit correlates several Entra/Graph surfaces per inbound service principal (Azure RBAC/ARM is **not** covered — enumerate that separately with `Get-AzRoleAssignment`):

| Access source | Graph surface |
| --- | --- |
| Application permissions | `servicePrincipals/{id}/appRoleAssignments` |
| Delegated permissions (admin vs user consent) | `oauth2PermissionGrants` |
| Active directory roles | `memberOf/microsoft.graph.directoryRole`, `roleManagement/directory/roleAssignments` |
| **PIM-eligible directory roles** | `roleManagement/directory/roleEligibilityScheduleInstances` |
| **Security-group memberships** (incl. role-assignable) | `memberOf/microsoft.graph.group` |
| **Owned objects** (apps/groups it can modify) | `servicePrincipals/{id}/ownedObjects` |
| Owners / assigned users & groups | `owners`, `appRoleAssignedTo` |
| Credentials | `keyCredentials` / `passwordCredentials` |
| **Federated identity credentials** (outbound apps) | `applications/{id}/federatedIdentityCredentials` |
| **Sign-in evidence** (actual use, all four categories: interactive user, non-interactive user, service principal, managed identity) | `auditLogs/signIns?$filter=appId eq … and signInEventTypes/any(t: t eq '<type>')` (Entra ID P1) |
| **Exchange app RBAC + access policies** (`-IncludeExchange`) | `Get-ServicePrincipal`, `Get-ManagementRoleAssignment`, `Get-ApplicationAccessPolicy` |

### Security fields / risk flags

Reports include (among others):

- AppId, display name, home tenant id, verified publisher
- **Outbound:** requested permissions from `requiredResourceAccess` (application + delegated), federated identity credentials, with high-risk highlights
- **Inbound service principals:** granted **application permissions**, **delegated scopes** split by **admin consent** (`AllPrincipals`) vs **user consent** (`Principal`), active + **PIM-eligible directory roles**, **group memberships**, **owned objects**, owners/admins, assigned users/groups, Exchange app access, and sign-in evidence
- Certificate vs client-secret counts; expired / expiring-in-30-days credentials
- Redirect / reply URI issues (`http://`, wildcards, localhost)
- Severity (`High` / `Medium` / `Low`) and human-readable `SecurityNotes`
- Graph calls are wrapped with retry/backoff for throttling (HTTP 429) and transient 5xx

### Run

Delegated (needs `Application.Read.All` and related read scopes).

**Cursor / VS Code:** `Connect-MgGraph -UseDeviceCode` often prints the code via `Console.WriteLine`, which the IDE terminal swallows. This script uses a custom device-code callback (`Write-Host`) so the code should appear in-terminal. If it still does not, run the **entire** audit in an external window (Graph sessions are per-process — connecting elsewhere does not help Cursor):

```powershell
# Windows Terminal / external pwsh:
cd 'D:\Powershell stuff\Copilot O365 Audit\B2Btesting'
.\Audit-MultiTenantApps.ps1 -TenantId contoso.com -DeviceCode -SkipExternalRelaunch
```

In Cursor (preferred attempt):

```powershell
.\Audit-MultiTenantApps.ps1 -TenantId contoso.com -DeviceCode
```

App-only (e.g. after Global Reader example helper, against BB):

```powershell
. .\.b2b-global-reader.local.ps1
.\Audit-MultiTenantApps.ps1 -TenantId '<BB-TENANT-ID>' -AppOnly
```

Include Exchange app RBAC and a wider sign-in window:

```powershell
.\Audit-MultiTenantApps.ps1 -TenantId contoso.com -IncludeExchange -SignInLookbackDays 90
```

Graph scopes used (delegated): `Application.Read.All`, `Directory.Read.All`, `DelegatedPermissionGrant.Read.All`, `RoleManagement.Read.Directory`, `AuditLog.Read.All`. Use `-SkipSignInActivity` if you lack Entra ID P1, and `-IncludeExchange` (needs the `ExchangeOnlineManagement` module) for Exchange application RBAC / access policies.

### Outputs

Timestamped folder under `MultiTenantAppAuditOutput\run-yyyyMMdd-HHmmss\`:

| File | Contents |
| --- | --- |
| `multitenant-apps-all.csv` | Combined inventory |
| `multitenant-apps-outbound.csv` | Multi-tenant app registrations owned here |
| `multitenant-apps-inbound.csv` | External enterprise apps |
| `multitenant-apps-report.html` | Dashboard + searchable/sortable inbound & outbound tables with collapsible permission lists |
| `summary.json` | Counts (severity totals, options used) |

## Relation to `copilot_audit.ps1`

The main audit script registers a **single-tenant** (or app-only) audit app for Copilot over-permissioning. This folder is separate: cross-tenant Global Reader access demos and multi-tenant app inventory. Do not reuse production audit credentials for experiments; keep this folder’s cert/helper local to B2B testing.
