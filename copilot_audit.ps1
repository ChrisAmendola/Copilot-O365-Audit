#Requires -Version 5.1
<#
.SYNOPSIS
    Tenant-wide Copilot over-permissioning audit (depth B) — surfaces overshared content
    that Copilot could retrieve via permissions and broad sharing.

.DESCRIPTION
    Audits unintended Copilot content exposure by building a principal→resource permission
    graph from Entra privileged roles, M365 Groups/Teams, Exchange Full Access / Send As,
    SharePoint site-level Everyone/external capability, and a capped Graph sample of OneDrive
    / team site libraries for org/anonymous/Everyone sharing.

    Depth B (honest limits): sampling caps, no full ACL enumeration, and sensitivity hints
    are heuristic — not guaranteed MIP label coverage. Findings emphasize over-permissioning
    and Copilot impact rather than reach/fan-in ranking alone.

    Exports findings.csv alongside nodes.csv, edges.csv, users-by-blast-radius.csv, and
    resources-by-blast-radius.csv under a timestamped output folder. Resource scores reflect
    inbound permission fan-in (legacy ranking; findings are the primary audit deliverable).

.PARAMETER TenantName
    Target tenant: SharePoint prefix (contoso), DNS domain (contoso.com /
    contoso.onmicrosoft.com), or tenant GUID. Pins Graph, Exchange, and SPO to that tenant.

.PARAMETER OutputPath
    Base directory for run output folders.

.PARAMETER BroadSharingMaxItems
    Max drive items inspected per drive during content sample.

.PARAMETER BroadSharingMaxDepth
    Max folder depth for content sample.

.PARAMETER MaxSitesForContentSample
    Max team/group SharePoint sites to sample via Graph.

.PARAMETER DirectShareFanInThreshold
    Minimum number of distinct named user or group grants on a sampled drive item before a
    DirectShareFanIn finding is emitted.

.PARAMETER MaxUsersForOneDriveSample
    Max users whose OneDrive is sampled (0 = all enabled users with a drive).

.PARAMETER SkipSharePointContentSample
    Skip Graph library sampling (site-level SPO scan still runs unless -SkipSharePointSites).

.PARAMETER SkipSharePointSites
    Skip Connect-SPOService / Get-SPOSite Everyone scan.

.PARAMETER SkipExchange
    Skip mailbox permission scan.

.PARAMETER SkipOneDriveSample
    Skip personal OneDrive sampling.

.PARAMETER ExchangeDeviceLogin
    Prefer Exchange device-code sign-in (then DisableWAM / interactive fallbacks).
    Recommended in Cursor / VS Code terminals where browser/WAM prompts hang.
.PARAMETER ExchangeUserPrincipalName
    Optional UPN hint passed to Connect-ExchangeOnline (-UserPrincipalName).

.PARAMETER Users
    Optional comma/semicolon-separated UPNs, mails, or object IDs to scope user reporting
    and OneDrive/enrichment. Resources are still scanned tenant-wide. Combines with -UserListPath.

.PARAMETER UserListPath
    Optional .txt/.csv of users to scope (one identity per line, or UPN/Mail/ObjectId/Id column).
    Combines with -Users. Resources remain tenant-wide.

.PARAMETER CopilotLicensedOnly
    When no explicit -Users or -UserListPath is supplied, scopes user reporting and OneDrive
    sampling to enabled users with a Copilot SKU. Explicit user scope always takes precedence.

.PARAMETER BaselinePath
    Optional CSV of expected user-to-resource access using UserPrincipalName, ResourceType,
    ResourceId, and ExpectedRole columns. Matching membership findings are Expected; other
    membership findings are Unexpected.

.PARAMETER SensitiveNamePatterns
    Optional regular-expression patterns used to identify sensitive resource names. Matching
    unexpected memberships are elevated one severity level.

.PARAMETER IncludeUserReachMap
    Force the scoped-user Copilot reach map (SharedWithMe + membership edges). Auto-on when
    -Users / -UserListPath / -CopilotLicensedOnly has resolved targets unless -SkipUserReachMap.

.PARAMETER SkipUserReachMap
    Disable the user reach map even when a user scope is active.

.PARAMETER UserReachMaxItems
    Max SharedWithMe / shared drive items to collect per scoped user (default: 500).

.PARAMETER UserReachIncomingShareFindingThreshold
    Emit an IncomingShare finding when a scoped user’s SharedWithMe item count reaches this
    threshold (default: 25).

.PARAMETER UserReachReverseSiteAcl
    Optionally scan up to 20 prioritized risky sites for ACL grants naming the scoped user.

.PARAMETER UserReachMaxOwnerDrives
    When building the user reach map, max other users' OneDrive drives to reverse-scan for
    direct grants to scoped users (default: 100). Needed because Graph sharedWithMe is
    deprecated/degraded and often returns empty for admin/delegated audits.

.PARAMETER UserReachReverseMaxDepth
    Max folder depth for reverse OneDrive grant scan (default: 3). Separate from content-sample depth.

.PARAMETER UserReachReverseMaxFolders
    Max folders inspected per owner drive during reverse OneDrive grant scan (default: 60).

.PARAMETER GraphAppId
    Optional Entra application (client) ID for app-only Microsoft Graph. Requires a
    certificate or client secret. Prefer certificate when both are supplied.

.PARAMETER GraphCertificateThumbprint
    Certificate thumbprint in the current user/local machine cert store for app-only Graph.

.PARAMETER GraphCertificatePath
    Path to a .pfx/.cer certificate file for app-only Graph (use with optional password).

.PARAMETER GraphCertificatePassword
    Password for -GraphCertificatePath (SecureString).

.PARAMETER GraphClientSecret
    Client secret for app-only Graph (SecureString). Prefer -GraphClientSecretEnvVar for
    clean-child relaunch.

.PARAMETER GraphClientSecretEnvVar
    Name of an environment variable that holds the client secret (plain text in the env var).

.PARAMETER RegisterGraphApp
    Create an Entra application + certificate credential with application permissions for
    app-only Graph (Files.Read.All, Sites.Read.All, etc.) and Exchange.ManageAsApp, attempt
    admin consent (+ Exchange Administrator role on the app SP), write .graph-app.local.ps1 /
    .graph-app.local.pfx, then continue the audit using those credentials.

.PARAMETER RegisterGraphAppOnly
    With -RegisterGraphApp, exit after creating the app/certificate (do not run the audit).

.PARAMETER GraphAppDisplayName
    Display name for -RegisterGraphApp (default: Copilot-O365-OverPermission-Audit).

.PARAMETER GraphAppSecretValidMonths
    Certificate validity in months for -RegisterGraphApp (default: 12; name kept for compatibility).

.EXAMPLE
    .\copilot_audit.ps1 -TenantName contoso.com

    Full tenant over-permissioning audit with default sampling.

.EXAMPLE
    .\copilot_audit.ps1 -TenantName contoso.com -RegisterGraphAppOnly

    Create the Entra app + certificate for app-only Graph/EXO, write .graph-app.local.ps1, then exit.

.EXAMPLE
    .\copilot_audit.ps1 -TenantName contoso.com -CopilotLicensedOnly -ExchangeDeviceLogin

    Copilot-licensed user scope with device-code Exchange sign-in (recommended in Cursor / VS Code terminals).

.EXAMPLE
    .\copilot_audit.ps1 -TenantName contoso.com -BaselinePath .\Copilot-OverPermission-baseline.example.csv

    Compare membership findings against an expected-access baseline CSV.

.EXAMPLE
    .\copilot_audit.ps1 -TenantName contoso.com -Users 'alice@contoso.com,bob@contoso.com' -ExchangeDeviceLogin

    Scoped user reporting and OneDrive sampling; resources remain tenant-wide. Also builds the
    user reach map (SharedWithMe + membership edges) for those users.

.EXAMPLE
    .\copilot_audit.ps1 -TenantName contoso.com -UserListPath .\users.txt -CopilotLicensedOnly

    User list from file combined with Copilot-licensed scope for OneDrive sampling.

.EXAMPLE
    .\copilot_audit.ps1 -TenantName contoso.com -Users 'alice@contoso.com' -UserReachReverseSiteAcl

    Scoped reach map plus capped reverse ACL checks on prioritized risky sites.

.NOTES
    Spec: docs/superpowers/specs/2026-07-14-copilot-exposure-graph-design.md
    Requirements: docs/superpowers/specs/2026-07-14-copilot-exposure-graph-requirements.md

    Auth model: delegated interactive sign-in (Microsoft Graph, Exchange Online, optional SPO),
    pinned to -TenantName (mismatched existing sessions are disconnected and re-authenticated).
    Optional app-only Graph via -GraphAppId (+ cert/secret) or -RegisterGraphApp.

    Tenant pinning design: docs/superpowers/specs/2026-07-16-tenant-specific-audit-design.md
    Resource blast-radius design: docs/superpowers/specs/2026-07-16-resource-permission-blast-radius-design.md
    User list scope design: docs/superpowers/specs/2026-07-16-user-list-scope-design.md
    Over-permissioning revision (Phase 0): docs/superpowers/specs/2026-07-16-copilot-overpermission-revision-design.md
    User reach map design: docs/superpowers/specs/2026-07-16-user-reach-map-design.md
    Graph app-only auth design: docs/superpowers/specs/2026-07-16-graph-app-only-auth-design.md

    Recommended Entra roles for a complete run:
      - Global Reader (directory inventory baseline)
      - Exchange Administrator or Exchange Recipient Administrator (mailbox permissions)
      - SharePoint Administrator (SPO site Everyone scan; improves OneDrive content sampling)
    Global Administrator satisfies all of the above but is more privilege than required.

    Microsoft Graph auth:
      Delegated (default): Read scopes User.Read.All, Directory.Read.All, Group.Read.All,
      RoleManagement.Read.Directory, Sites.Read.All, Files.Read.All, Team.ReadBasic.All,
      TeamMember.Read.All on the Microsoft Graph PowerShell app (admin consent typical).
      App-only (optional): -GraphAppId plus certificate and/or client secret. Application
      permissions Files.Read.All + Sites.Read.All (+ directory/group/team reads) with admin
      consent enable reverse OneDrive ACL scans of other users' drives.
    Private/shared channel membership is collected only when Channel.ReadBasic.All has also
    been consented (delegated). Without it, the Teams collector records team membership and
    skips channels without failing the audit.

    Feature mapping:
      Privileged roles / Groups / Teams  -> Graph scopes + directory read
      Exchange Full Access / Send As     -> Exchange Online + mailbox permission read
      SPO Everyone / SharingCapability   -> SharePoint Administrator + SPO module
      OneDrive / library content sample  -> Sites.Read.All + Files.Read.All (SharePoint Admin recommended)
      Graph site inventory fallback      -> Sites.Read.All (when SPO module unavailable)

    Partial-run switches when a role is missing:
      -SkipExchange, -SkipSharePointSites, -SkipOneDriveSample, -SkipSharePointContentSample
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$TenantName,

    [string]$OutputPath = (Join-Path $PSScriptRoot 'CopilotExposureOutput'),

    [int]$BroadSharingMaxItems = 200,
    [int]$BroadSharingMaxDepth = 4,
    [int]$MaxSitesForContentSample = 50,
    [int]$DirectShareFanInThreshold = 15,
    [int]$MaxUsersForOneDriveSample = 0,

    [switch]$SkipSharePointContentSample,
    [switch]$SkipSharePointSites,
    [switch]$SkipExchange,
    [switch]$SkipOneDriveSample,
    [switch]$ExchangeDeviceLogin,
    [string]$ExchangeUserPrincipalName,

    [string]$Users,
    [string]$UserListPath,

    [switch]$CopilotLicensedOnly,
    [string]$BaselinePath,
    [string[]]$SensitiveNamePatterns = @(
        'Finance', 'HR', 'Legal', 'Executive', 'Payroll', 'Confidential', 'Board', 'M&A'
    ),

    [switch]$IncludeUserReachMap,
    [switch]$SkipUserReachMap,
    [int]$UserReachMaxItems = 500,
    [int]$UserReachIncomingShareFindingThreshold = 25,
    [switch]$UserReachReverseSiteAcl,
    [int]$UserReachMaxOwnerDrives = 100,
    [int]$UserReachReverseMaxDepth = 3,
    [int]$UserReachReverseMaxFolders = 60,

    [string]$GraphAppId,
    [string]$GraphCertificateThumbprint,
    [string]$GraphCertificatePath,
    [securestring]$GraphCertificatePassword,
    [securestring]$GraphClientSecret,
    [string]$GraphClientSecretEnvVar,

    [switch]$RegisterGraphApp,
    [switch]$RegisterGraphAppOnly,
    [string]$GraphAppDisplayName = 'Copilot-O365-OverPermission-Audit',
    [int]$GraphAppSecretValidMonths = 12,

    [switch]$CleanChildProcess,
    [switch]$NoCleanRelaunch
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'

#region Constants
$Script:PrivilegedEntraRoles = @(
    'Global Administrator',
    'Privileged Role Administrator',
    'Exchange Administrator',
    'SharePoint Administrator',
    'Teams Administrator',
    'Application Administrator',
    'Cloud Application Administrator',
    'User Administrator',
    'Compliance Administrator',
    'Security Administrator'
)

$Script:BroadGroupNamePatterns = @(
    'Everyone',
    'Everyone except external users',
    'All Users',
    'All Company',
    'All Staff',
    'Company',
    'Authenticated Users',
    'Org-Wide',
    'Organization'
)
$Script:BroadGroupPatternRegex = ($Script:BroadGroupNamePatterns | ForEach-Object { [regex]::Escape($_) }) -join '|'
$Script:SensitiveNamePatternRegex = if ($SensitiveNamePatterns.Count -gt 0) {
    '(?i)(?:' + ($SensitiveNamePatterns -join '|') + ')'
}
else {
    '(?!)'
}

$Script:BroadShareLoginPatterns = @(
    'spo-grid-all-users',
    'everyone except external users',
    '^c:0\(\.f\|membership\|',
    'everyone'
)

$Script:MailboxDelegateWeight = 20
$Script:MailboxScoreCap = 100
$Script:PrivilegedRoleWeight = 80
$Script:SiteMemberWeight = 2
$Script:SiteMemberEdgeCap = 500
# Emit a fan-in finding when a site has this many distinct SiteMember sources.
$Script:SiteMemberFanInFindingThreshold = 25
$Script:SiteRoleWeights = @{
    Owner   = 25
    Member  = 8
    Visitor = 3
}
$Script:SiteRoleOwnerFanInFindingThreshold = 3
$Script:SiteGroupExpansionMemberCap = 200
$Script:SiteExternalSharingWeight = 20
$Script:ResourceScoreCaps = @{
    Mailbox        = 100
    Site           = 120
    Group          = 100
    DriveItem      = 80
    Role           = 100
    BroadPrincipal = 40
}
$Script:SpoAvailable = $false
$Script:PnpAvailable = $false
$Script:PnpConnection = $null
$Script:DefaultPnPClientId = '14d82eec-204b-4c2f-b7e8-296a70dab67e'
$Script:ExchangeAvailable = $false
$Script:RunCoverage = [PSCustomObject][ordered]@{
    GraphOk                 = $false
    ExchangeOk              = $false
    SpoOk                   = $false
    PnpOk                   = $false
    SharePointRoleMode      = 'NotStarted'
    SharePointInventoryMode = 'NotStarted'
    SitesSampled            = 0
    SitesTotal              = 0
    ContentSitesPrioritized = 0
    ContentItemsScanned     = 0
    ContentItemsCapped      = 0
    ContentItemsSkippedDepth = 0
    ContentItemsSkippedCap  = 0
    ContentDriveFailures    = 0
    ContentPermissionFailures = 0
    DirectShareFindings     = 0
    OneDriveUsersSampled    = 0
    SiteMemberEdgeCapHits   = 0
    TeamsOk                 = $false
    TeamsCount              = 0
    TeamsChannelsOk         = $false
    TeamsChannelsSkipped    = $false
    UserScopeActive         = $false
    CopilotLicensedOnly     = [bool]$CopilotLicensedOnly
    BaselineLoaded          = $false
    SensitivePatternsCount  = $SensitiveNamePatterns.Count
    FindingsCount           = 0
    UserReachMap            = 'NotStarted'
    UserReachSharedWithMeOk = $false
    UserReachItemCount      = 0
    UserReachGraphEdgeCount = 0
    UserReachReverseAclSites = 0
    UserReachOwnerDrivesScanned = 0
    UserReachDirectGrantCount = 0
    UserReachFoldersScanned = 0
    UserReachLimitation     = ''
    GraphAuthMode           = 'NotStarted'
    GraphAppId              = ''
    UnattendedAppOnly       = $false
    ExchangeSkippedReason   = ''
    SpoSkippedReason        = ''
}
$Script:AuditTenant = $null
$Script:AuditProgressId = 1
$Script:AuditProgressActivity = ''
$Script:AuditProgressStopwatch = $null
$Script:TargetUserScopeEnabled = $false
$Script:TargetUserInputCount = 0
$Script:TargetUserIndex = @{}
$Script:TargetUsers = [System.Collections.Generic.List[object]]::new()
$Script:AccessBaseline = @()
$Script:Nodes = [System.Collections.Generic.List[object]]::new()
$Script:Edges = [System.Collections.Generic.List[object]]::new()
$Script:Findings = [System.Collections.Generic.List[object]]::new()
$Script:FindingIndex = @{}
$Script:FindingColumns = @(
    'Workload', 'ResourceType', 'ResourceId', 'ResourceName', 'PrincipalId', 'PrincipalUpn',
    'Permission', 'PermissionStrength', 'FanIn', 'SensitivityHint', 'BaselineStatus',
    'Severity', 'CopilotImpact', 'Recommendation', 'Evidence'
)
$Script:UserReachSharedRows = [System.Collections.Generic.List[object]]::new()
$Script:UserReachColumns = @(
    'PrincipalId', 'PrincipalUpn', 'PrincipalDisplayName', 'Workload', 'ResourceType',
    'ResourceId', 'ResourceName', 'AccessVia', 'PermissionStrength', 'SharerId', 'SharerUpn',
    'SharerDisplayName', 'Evidence', 'SensitivityHint', 'BaselineStatus'
)
$Script:GraphAuthMode = 'NotStarted'
$Script:ExitAfterGraphRegistration = $false
$Script:GraphAppRequiredPermissionValues = @(
    'Files.Read.All',
    'Sites.Read.All',
    'User.Read.All',
    'Directory.Read.All',
    'Group.Read.All',
    'Team.ReadBasic.All',
    'TeamMember.Read.All',
    'RoleManagement.Read.Directory'
)
$Script:NodeIndex = @{}
$Script:GraphSubModules = @(
    'Microsoft.Graph.Authentication',
    'Microsoft.Graph.Users',
    'Microsoft.Graph.Groups',
    'Microsoft.Graph.Identity.DirectoryManagement',
    'Microsoft.Graph.Sites',
    'Microsoft.Graph.Teams'
)
if ($RegisterGraphAppOnly) { $RegisterGraphApp = $true }
# Convenience: load AppId from env when using .graph-app.local.ps1 helpers.
if ([string]::IsNullOrWhiteSpace($GraphAppId)) {
    $envAppId = [Environment]::GetEnvironmentVariable('COPILOT_GRAPH_APP_ID')
    if (-not [string]::IsNullOrWhiteSpace($envAppId)) {
        $GraphAppId = $envAppId.Trim()
    }
}
if ([string]::IsNullOrWhiteSpace($GraphCertificateThumbprint)) {
    $envThumb = [Environment]::GetEnvironmentVariable('COPILOT_GRAPH_CERT_THUMBPRINT')
    if (-not [string]::IsNullOrWhiteSpace($envThumb)) {
        $GraphCertificateThumbprint = $envThumb.Trim()
    }
}
if ([string]::IsNullOrWhiteSpace($GraphCertificatePath)) {
    $envCertPath = [Environment]::GetEnvironmentVariable('COPILOT_GRAPH_CERT_PATH')
    if (-not [string]::IsNullOrWhiteSpace($envCertPath)) {
        $GraphCertificatePath = $envCertPath.Trim()
    }
}
if ((-not $GraphCertificatePassword -or $GraphCertificatePassword.Length -eq 0) -and
    -not [string]::IsNullOrWhiteSpace([Environment]::GetEnvironmentVariable('COPILOT_GRAPH_CERT_PASSWORD'))) {
    $GraphCertificatePassword = ConvertTo-SecureString -String ([Environment]::GetEnvironmentVariable('COPILOT_GRAPH_CERT_PASSWORD')) -AsPlainText -Force
}
if ([string]::IsNullOrWhiteSpace($GraphClientSecretEnvVar) -and
    -not [string]::IsNullOrWhiteSpace([Environment]::GetEnvironmentVariable('COPILOT_GRAPH_SECRET'))) {
    $GraphClientSecretEnvVar = 'COPILOT_GRAPH_SECRET'
}
#endregion

#region Logging / helpers
function Write-AuditLog {
    param(
        [string]$Message,
        [ValidateSet('Info', 'Warn', 'Error')]
        [string]$Level = 'Info'
    )
    $color = switch ($Level) {
        'Warn'  { 'Yellow' }
        'Error' { 'Red' }
        default { 'Cyan' }
    }
    Write-Host $Message -ForegroundColor $color
}

function Format-AuditElapsed {
    param([TimeSpan]$Elapsed)

    if ($Elapsed.TotalHours -ge 1) {
        return ('{0}h {1:D2}m {2:D2}s' -f [int]$Elapsed.TotalHours, $Elapsed.Minutes, $Elapsed.Seconds)
    }
    if ($Elapsed.TotalMinutes -ge 1) {
        return ('{0}m {1:D2}s' -f [int]$Elapsed.TotalMinutes, $Elapsed.Seconds)
    }
    return ('{0}s' -f [int][Math]::Max(0, [Math]::Floor($Elapsed.TotalSeconds)))
}

function Write-AuditProgress {
    param(
        [Parameter(Mandatory)]
        [string]$Activity,

        [string]$Status = '',
        [int]$Current = 0,
        [int]$Total = 0,
        # Accepted for call-site compatibility; not shown (counts + elapsed only).
        $CurrentOperation = ''
    )

    if ($Activity -ne $Script:AuditProgressActivity -or $null -eq $Script:AuditProgressStopwatch) {
        $Script:AuditProgressActivity = $Activity
        $Script:AuditProgressStopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    }

    $elapsedText = Format-AuditElapsed -Elapsed $Script:AuditProgressStopwatch.Elapsed
    $percent = 0
    if ($Total -gt 0) {
        $percent = [int][Math]::Min(100, [Math]::Floor(($Current * 100.0) / $Total))
        $Status = "$Current / $Total | elapsed $elapsedText"
    }
    elseif (-not $Status) {
        $Status = "elapsed $elapsedText"
    }
    elseif ($Status -notmatch '(?i)elapsed') {
        $Status = "$Status | elapsed $elapsedText"
    }

    Write-Progress -Id $Script:AuditProgressId -Activity $Activity -Status $Status -PercentComplete $percent
}

function Complete-AuditProgress {
    param([string]$Activity = 'Done')

    $elapsedText = ''
    if ($null -ne $Script:AuditProgressStopwatch) {
        $elapsedText = Format-AuditElapsed -Elapsed $Script:AuditProgressStopwatch.Elapsed
        $Script:AuditProgressStopwatch.Stop()
    }
    Write-Progress -Id $Script:AuditProgressId -Activity $Activity -Completed
    if ($elapsedText -and $Activity -and $Activity -ne 'Done') {
        Write-AuditLog "  $Activity complete ($elapsedText)."
    }
    $Script:AuditProgressActivity = ''
    $Script:AuditProgressStopwatch = $null
}

function Get-AlignedGraphModuleVersion {
    $authVersions = @(
        Get-Module -ListAvailable -Name 'Microsoft.Graph.Authentication' |
            ForEach-Object { [version]$_.Version } |
            Sort-Object -Descending
    )

    foreach ($version in $authVersions) {
        $allPresent = $true
        foreach ($subModule in $Script:GraphSubModules) {
            $match = Get-Module -ListAvailable -Name $subModule |
                Where-Object { [version]$_.Version -eq $version }
            if (-not $match) {
                $allPresent = $false
                break
            }
        }
        if ($allPresent) {
            return $version
        }
    }

    return $null
}

function Import-AlignedGraphModules {
    $version = Get-AlignedGraphModuleVersion
    if (-not $version) {
        throw 'No aligned Microsoft.Graph submodule set found. Run: Install-Module Microsoft.Graph -Scope CurrentUser -Force -AllowClobber'
    }

    $authVersions = @(Get-Module -ListAvailable -Name 'Microsoft.Graph.Authentication' | Select-Object -ExpandProperty Version -Unique)
    if (@($authVersions).Count -gt 1) {
        Write-AuditLog "Multiple Microsoft.Graph.Authentication versions installed: $($authVersions -join ', ')" Warn
        Write-AuditLog "Using aligned version $version for this run." Info
    }

    Get-Module -Name 'Microsoft.Graph*' -ErrorAction SilentlyContinue |
        Remove-Module -Force -ErrorAction SilentlyContinue

    foreach ($subModule in $Script:GraphSubModules) {
        Import-Module -Name $subModule -RequiredVersion $version -Force -ErrorAction Stop
    }
}

function Start-ExposureGraphCleanProcess {
    param([string]$ScriptPath)

    Write-AuditLog 'Relaunching in an isolated -NoProfile PowerShell session (avoids Graph/EXO assembly conflicts)...' Info

    $shell = $null
    $pwshCmd = Get-Command pwsh -ErrorAction SilentlyContinue
    if ($pwshCmd) {
        $shell = $pwshCmd.Source
    }
    elseif ($PSVersionTable.PSEdition -eq 'Core') {
        $shell = (Get-Process -Id $PID).Path
    }
    else {
        $shell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    }

    Write-AuditLog "  Child host: $shell" Info

    $childArgs = [System.Collections.Generic.List[string]]::new()
    $childArgs.AddRange([string[]]@(
            '-NoProfile',
            '-NoLogo',
            '-ExecutionPolicy', 'Bypass',
            '-File', $ScriptPath,
            '-CleanChildProcess',
            '-TenantName', $TenantName,
            '-OutputPath', $OutputPath,
            '-BroadSharingMaxItems', "$BroadSharingMaxItems",
            '-BroadSharingMaxDepth', "$BroadSharingMaxDepth",
            '-MaxSitesForContentSample', "$MaxSitesForContentSample",
            '-DirectShareFanInThreshold', "$DirectShareFanInThreshold",
            '-MaxUsersForOneDriveSample', "$MaxUsersForOneDriveSample",
            '-UserReachMaxItems', "$UserReachMaxItems",
            '-UserReachIncomingShareFindingThreshold', "$UserReachIncomingShareFindingThreshold",
            '-UserReachMaxOwnerDrives', "$UserReachMaxOwnerDrives",
            '-UserReachReverseMaxDepth', "$UserReachReverseMaxDepth",
            '-UserReachReverseMaxFolders', "$UserReachReverseMaxFolders"
        ))

    if ($SkipSharePointContentSample) { $childArgs.Add('-SkipSharePointContentSample') }
    if ($SkipSharePointSites) { $childArgs.Add('-SkipSharePointSites') }
    if ($SkipExchange) { $childArgs.Add('-SkipExchange') }
    if ($SkipOneDriveSample) { $childArgs.Add('-SkipOneDriveSample') }
    if ($IncludeUserReachMap) { $childArgs.Add('-IncludeUserReachMap') }
    if ($SkipUserReachMap) { $childArgs.Add('-SkipUserReachMap') }
    if ($UserReachReverseSiteAcl) { $childArgs.Add('-UserReachReverseSiteAcl') }
    if ($ExchangeDeviceLogin) { $childArgs.Add('-ExchangeDeviceLogin') }
    if ($ExchangeUserPrincipalName) {
        $childArgs.Add('-ExchangeUserPrincipalName')
        $childArgs.Add($ExchangeUserPrincipalName)
    }
    if ($Users) {
        $childArgs.Add('-Users')
        $childArgs.Add($Users)
    }
    if ($UserListPath) {
        $resolvedListPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($UserListPath)
        $childArgs.Add('-UserListPath')
        $childArgs.Add($resolvedListPath)
    }
    if ($CopilotLicensedOnly) { $childArgs.Add('-CopilotLicensedOnly') }
    if ($BaselinePath) {
        $resolvedBaselinePath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($BaselinePath)
        $childArgs.Add('-BaselinePath')
        $childArgs.Add($resolvedBaselinePath)
    }
    # -File cannot take array values as separate argv tokens (later tokens become
    # positional and fail, e.g. "Payroll"). Only forward an explicit override, as
    # one comma-joined argument; otherwise the child uses its param defaults.
    if ($PSBoundParameters.ContainsKey('SensitiveNamePatterns') -and $SensitiveNamePatterns.Count -gt 0) {
        $childArgs.Add('-SensitiveNamePatterns')
        $childArgs.Add(($SensitiveNamePatterns -join ','))
    }

    # App-only Graph: forward non-secret params; secrets via env var only (never argv).
    if ($GraphAppId) {
        $childArgs.Add('-GraphAppId')
        $childArgs.Add($GraphAppId)
    }
    if ($GraphCertificateThumbprint) {
        $childArgs.Add('-GraphCertificateThumbprint')
        $childArgs.Add($GraphCertificateThumbprint)
    }
    if ($GraphCertificatePath) {
        $resolvedCertPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($GraphCertificatePath)
        $childArgs.Add('-GraphCertificatePath')
        $childArgs.Add($resolvedCertPath)
    }
    if ($RegisterGraphApp) { $childArgs.Add('-RegisterGraphApp') }
    if ($RegisterGraphAppOnly) { $childArgs.Add('-RegisterGraphAppOnly') }
    if ($PSBoundParameters.ContainsKey('GraphAppDisplayName') -and $GraphAppDisplayName) {
        $childArgs.Add('-GraphAppDisplayName')
        $childArgs.Add($GraphAppDisplayName)
    }
    if ($PSBoundParameters.ContainsKey('GraphAppSecretValidMonths')) {
        $childArgs.Add('-GraphAppSecretValidMonths')
        $childArgs.Add("$GraphAppSecretValidMonths")
    }
    if ($GraphClientSecretEnvVar) {
        $childArgs.Add('-GraphClientSecretEnvVar')
        $childArgs.Add($GraphClientSecretEnvVar)
    }
    elseif ($GraphClientSecret -and $GraphClientSecret.Length -gt 0) {
        $bridgeEnv = 'COPILOT_AUDIT_GRAPH_CLIENT_SECRET'
        $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($GraphClientSecret)
        try {
            [Environment]::SetEnvironmentVariable($bridgeEnv, [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr))
        }
        finally {
            [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
        }
        $childArgs.Add('-GraphClientSecretEnvVar')
        $childArgs.Add($bridgeEnv)
        Write-AuditLog "  Bridging Graph client secret to child via env var $bridgeEnv (not logged)." Info
    }
    if ($GraphCertificatePassword -and $GraphCertificatePassword.Length -gt 0) {
        $bridgeCertEnv = 'COPILOT_AUDIT_GRAPH_CERT_PASSWORD'
        $bstrCert = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($GraphCertificatePassword)
        try {
            [Environment]::SetEnvironmentVariable($bridgeCertEnv, [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstrCert))
        }
        finally {
            [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstrCert)
        }
        # Child reads this env if GraphCertificatePath is set and no password param was passed.
        $Script:GraphCertificatePasswordEnvBridge = $bridgeCertEnv
        [Environment]::SetEnvironmentVariable('COPILOT_AUDIT_GRAPH_CERT_PASSWORD_ENV', $bridgeCertEnv)
        Write-AuditLog '  Bridging Graph certificate password to child via env (not logged).' Info
    }

    try {
        & $shell @childArgs
        exit $LASTEXITCODE
    }
    finally {
        foreach ($name in @('COPILOT_AUDIT_GRAPH_CLIENT_SECRET', 'COPILOT_AUDIT_GRAPH_CERT_PASSWORD', 'COPILOT_AUDIT_GRAPH_CERT_PASSWORD_ENV')) {
            if ([Environment]::GetEnvironmentVariable($name)) {
                [Environment]::SetEnvironmentVariable($name, $null)
            }
        }
    }
}

function Resolve-SharePointTenantName {
    param([string]$Name)

    $normalized = $Name.Trim().TrimEnd('.')
    if ($normalized -match '^([^.]+)\.onmicrosoft\.com$') { return $Matches[1] }
    if ($normalized -match '^([^.]+)\.sharepoint\.com$') { return $Matches[1] }
    if ($normalized -match '^([^.]+)\.[^.]+\.[^.]+$' -or $normalized -match '^([^.]+)\.[^.]+$') {
        if ($normalized -notmatch '\.sharepoint\.' -and $normalized.Contains('.')) {
            return ($normalized -split '\.')[0]
        }
    }
    return $normalized
}

function Get-SeverityFromScore {
    param([double]$Score)
    if ($Score -ge 80) { return 'Critical' }
    if ($Score -ge 50) { return 'High' }
    if ($Score -ge 20) { return 'Medium' }
    return 'Low'
}

function Get-GraphObjectProperty {
    param($Object, [string]$PropertyName)
    if ($null -eq $Object) { return $null }

    # Invoke-MgGraphRequest often returns Hashtable/Dictionary; PSObject.Properties
    # does not reliably expose those keys on all hosts.
    if ($Object -is [System.Collections.IDictionary]) {
        foreach ($key in @($Object.Keys)) {
            if ([string]$key -ieq $PropertyName) { return $Object[$key] }
        }
        return $null
    }

    $property = $Object.PSObject.Properties | Where-Object { $_.Name -ieq $PropertyName } | Select-Object -First 1
    if ($property) { return $property.Value }
    return $null
}

function Get-NormalizedGraphSiteId {
    param($SiteOrId)

    if ($null -eq $SiteOrId) { return '' }

    $raw = $SiteOrId
    if ($SiteOrId -isnot [string] -and $SiteOrId -isnot [ValueType]) {
        $raw = Get-GraphObjectProperty -Object $SiteOrId -PropertyName 'id'
        if ($null -eq $raw -and $SiteOrId.PSObject.Properties['Id']) {
            $raw = $SiteOrId.Id
        }
    }

    foreach ($candidate in @($raw)) {
        if ($null -eq $candidate) { continue }
        $text = ([string]$candidate).Trim()
        if ([string]::IsNullOrWhiteSpace($text)) { continue }
        # Reject concatenated multi-site blobs (SDK/search quirk).
        if ($text -match '\r|\n') { continue }
        # Graph composite site id: hostname,siteCollectionId,webId
        if ($text -match '^[A-Za-z0-9][A-Za-z0-9.-]*,[0-9a-fA-F-]{36},[0-9a-fA-F-]{36}$') {
            return $text
        }
        # Plain GUID is not accepted by Get-MgSiteDrive in many tenants — skip.
    }
    return ''
}

function Get-GraphGroupDefaultDriveId {
    param([Parameter(Mandatory)][string]$GroupId)

    $groupKey = [uri]::EscapeDataString($GroupId)
    try {
        $drive = Invoke-MgGraphRequest -Method GET `
            -Uri "https://graph.microsoft.com/v1.0/groups/$groupKey/drive" -ErrorAction Stop
        return [string](Get-GraphObjectProperty -Object $drive -PropertyName 'id')
    }
    catch {
        return ''
    }
}

function Get-GraphSiteDriveIds {
    param(
        [string]$SiteId = '',
        [string]$WebUrl = ''
    )

    $uris = [System.Collections.Generic.List[string]]::new()
    if ($SiteId) {
        $encoded = [uri]::EscapeDataString($SiteId)
        [void]$uris.Add("https://graph.microsoft.com/v1.0/sites/$encoded/drives")
    }
    if ($WebUrl -match '^https?://') {
        try {
            $uri = [uri]$WebUrl
            $hostName = $uri.Host
            $path = $uri.AbsolutePath.Trim('/')
            if ($path) {
                [void]$uris.Add("https://graph.microsoft.com/v1.0/sites/${hostName}:/${path}:/drives")
            }
            else {
                [void]$uris.Add("https://graph.microsoft.com/v1.0/sites/${hostName}:/drives")
            }
        }
        catch { }
    }

    $driveIds = [System.Collections.Generic.List[string]]::new()
    foreach ($requestUri in $uris) {
        try {
            $response = Invoke-MgGraphRequest -Method GET -Uri $requestUri -ErrorAction Stop
            foreach ($drive in @((Get-GraphObjectProperty -Object $response -PropertyName 'value'))) {
                $id = [string](Get-GraphObjectProperty -Object $drive -PropertyName 'id')
                if ($id) { $driveIds.Add($id) }
            }
            if ($driveIds.Count -gt 0) { break }
        }
        catch { }
    }
    return @($driveIds)
}

function Get-GraphUserDrive {
    param(
        [Parameter(Mandatory)]$User,
        [switch]$PreferMe
    )

    $errors = [System.Collections.Generic.List[string]]::new()
    $uris = [System.Collections.Generic.List[string]]::new()
    if ($PreferMe -or (Test-SignedInUserMatchesPrincipal -Principal $User)) {
        [void]$uris.Add('https://graph.microsoft.com/v1.0/me/drive')
    }
    if ($User.Id) {
        [void]$uris.Add("https://graph.microsoft.com/v1.0/users/$([uri]::EscapeDataString([string]$User.Id))/drive")
    }
    if ($User.UserPrincipalName) {
        [void]$uris.Add("https://graph.microsoft.com/v1.0/users/$([uri]::EscapeDataString([string]$User.UserPrincipalName))/drive")
    }

    foreach ($uri in $uris) {
        try {
            $drive = Invoke-MgGraphRequest -Method GET -Uri $uri -ErrorAction Stop
            $driveId = [string](Get-GraphObjectProperty -Object $drive -PropertyName 'id')
            if ($driveId) {
                return [PSCustomObject]@{
                    Drive   = $drive
                    DriveId = $driveId
                    Uri     = $uri
                }
            }
            [void]$errors.Add("$uri returned no drive id")
        }
        catch {
            [void]$errors.Add("${uri}: $($_.Exception.Message)")
        }
    }

    return [PSCustomObject]@{
        Drive   = $null
        DriveId = ''
        Uri     = ''
        Errors  = @($errors)
    }
}

function Test-IsBroadGroupName {
    param([string]$Name)
    if ([string]::IsNullOrWhiteSpace($Name)) { return $false }
    return $Name -match $Script:BroadGroupPatternRegex
}

function Test-IsBroadShareLoginName {
    param([string]$LoginName)
    if ([string]::IsNullOrWhiteSpace($LoginName)) { return $false }
    foreach ($pattern in $Script:BroadShareLoginPatterns) {
        if ($LoginName -match $pattern) { return $true }
    }
    return $false
}

function Test-IsSystemSharePointLogin {
    param(
        [string]$LoginName,
        [switch]$AllowEntraGroupClaims
    )
    if ([string]::IsNullOrWhiteSpace($LoginName)) { return $true }

    $login = $LoginName.Trim()
    if ($login -match '(?i)^NT AUTHORITY\\') { return $true }
    if ($login -match '(?i)^SHAREPOINT\\') { return $true }
    if ($login -match '(?i)^APP@') { return $true }
    if ($login -match '(?i)\.svc(\b|@|/)') { return $true }
    if (-not $AllowEntraGroupClaims -and $login -match '(?i)c:0o\.c\|federateddirectoryclaimprovider\|') { return $true }
    if ($login -match '(?i)spo-grid-all-users') { return $true }
    if ($login -match '(?i)^c:0\(\.s\|true/') { return $true }
    return $false
}

function Resolve-SharePointPrincipal {
    param(
        [string]$LoginName,
        [string]$DisplayName = ''
    )

    $login = $LoginName.Trim()
    $candidate = $login
    if ($login -match '\|([^|]+)$') {
        $candidate = $Matches[1].Trim()
    }

    $resolved = $null
    $principalType = 'User'
    try {
        if (Test-LooksLikeGuid -Value $candidate) {
            $resolved = Get-MgUser -UserId $candidate -Property 'id,displayName,userPrincipalName,mail' -ErrorAction SilentlyContinue
            if (-not $resolved) {
                $resolved = Get-MgGroup -GroupId $candidate -Property 'id,displayName,mail' -ErrorAction SilentlyContinue
                if ($resolved) { $principalType = 'Group' }
            }
        }
        elseif ($candidate -match '@') {
            $resolved = Get-MgUser -UserId $candidate -Property 'id,displayName,userPrincipalName,mail' -ErrorAction SilentlyContinue
        }
    }
    catch {
        $resolved = $null
    }

    if ($resolved -and $resolved.Id) {
        return [PSCustomObject]@{
            Id          = [string]$resolved.Id
            Type        = $principalType
            DisplayName = $(if ($resolved.DisplayName) { [string]$resolved.DisplayName } else { $DisplayName })
            Upn         = [string](Get-GraphObjectProperty -Object $resolved -PropertyName 'userPrincipalName')
            RawLogin    = $login
        }
    }

    return [PSCustomObject]@{
        Id          = $login
        Type        = 'User'
        DisplayName = $(if ($DisplayName) { $DisplayName } else { $login })
        Upn         = $(if ($candidate -match '@' -and $candidate -notmatch '#ext#') { $candidate } else { '' })
        RawLogin    = $login
    }
}

function Add-SharePointGroupRoleMembers {
    param(
        [Parameter(Mandatory)][string]$GroupId,
        [Parameter(Mandatory)][string]$SiteUrl,
        [Parameter(Mandatory)][string]$Role,
        [Parameter(Mandatory)][hashtable]$RolePrincipalIds
    )

    $expanded = 0
    try {
        $members = @(Get-MgGroupMember -GroupId $GroupId -Top $Script:SiteGroupExpansionMemberCap -ErrorAction Stop)
        foreach ($member in $members) {
            if (-not $member.Id) { continue }
            $odataType = [string](Get-GraphObjectProperty -Object $member.AdditionalProperties -PropertyName '@odata.type')
            if ($odataType -match '(?i)group$') { continue }

            $memberId = [string]$member.Id
            $memberDisplayName = [string](Get-GraphObjectProperty -Object $member -PropertyName 'displayName')
            $memberUpn = [string](Get-GraphObjectProperty -Object $member -PropertyName 'userPrincipalName')
            if (-not $memberDisplayName -and $member.AdditionalProperties) {
                $memberDisplayName = [string](Get-GraphObjectProperty -Object $member.AdditionalProperties -PropertyName 'displayName')
            }
            if (-not $memberUpn -and $member.AdditionalProperties) {
                $memberUpn = [string](Get-GraphObjectProperty -Object $member.AdditionalProperties -PropertyName 'userPrincipalName')
            }

            Add-ExposureNode -Id $memberId -Type User -DisplayName $memberDisplayName -UserPrincipalName $memberUpn
            Add-ExposureEdge -SourceId $memberId -TargetId $SiteUrl -EdgeType SiteRole `
                -Detail "$Role via Entra group $GroupId" -Weight $Script:SiteRoleWeights[$Role]
            $RolePrincipalIds[$memberId] = $true
            $expanded++
        }
    }
    catch {
        Write-AuditLog "  Could not expand Entra group $GroupId for SharePoint role fan-in: $($_.Exception.Message)" Warn
    }
    return $expanded
}

function Initialize-OptionalPnPConnection {
    param([Parameter(Mandatory)]$TenantTarget)

    $Script:PnpAvailable = $false
    $Script:PnpConnection = $null
    $Script:RunCoverage.PnpOk = $false
    $Script:RunCoverage.SharePointRoleMode = 'SPOFlatMembership'

    if ($SkipSharePointSites) {
        $Script:RunCoverage.SharePointRoleMode = 'Skipped'
        return
    }
    if ($Script:GraphAuthMode -eq 'AppOnly') {
        $Script:RunCoverage.SharePointRoleMode = 'GraphFallbackNoRoles'
        Write-AuditLog 'Skipping interactive PnP sign-in (unattended app-only Graph run).' Info
        return
    }
    if (-not (Get-Module -ListAvailable -Name 'PnP.PowerShell')) {
        Write-AuditLog 'PnP.PowerShell is unavailable; using SPO flat site membership only.' Warn
        return
    }

    try {
        Import-Module PnP.PowerShell -ErrorAction Stop
        $adminUrl = "https://$($TenantTarget.SharePointPrefix)-admin.sharepoint.com"
        Write-AuditLog "Connecting to SharePoint admin through optional PnP: $adminUrl"
        $Script:PnpConnection = Connect-PnPOnline -Url $adminUrl -ClientId $Script:DefaultPnPClientId `
            -Interactive -ReturnConnection -ErrorAction Stop
        $Script:PnpAvailable = $null -ne $Script:PnpConnection
        $Script:RunCoverage.PnpOk = $Script:PnpAvailable
        if ($Script:PnpAvailable) {
            $Script:RunCoverage.SharePointRoleMode = 'PnPAssociatedGroups'
            Write-AuditLog '  PnP role collection enabled (Owners/Members/Visitors).'
        }
    }
    catch {
        $Script:PnpAvailable = $false
        $Script:PnpConnection = $null
        Write-AuditLog "PnP role collection unavailable; continuing with SPO flat membership: $($_.Exception.Message)" Warn
    }
}

function Get-ResourceBlastRadiusCap {
    param([string]$Type)
    if ($Script:ResourceScoreCaps.ContainsKey($Type)) {
        return [double]$Script:ResourceScoreCaps[$Type]
    }
    return 100.0
}

function Add-TargetUserIndexKey {
    param([string]$Key, $User)
    if ([string]::IsNullOrWhiteSpace($Key)) { return }
    $Script:TargetUserIndex[$Key.Trim().ToLowerInvariant()] = $User
}

function Get-RawUserScopeIdentities {
    $idents = [System.Collections.Generic.List[string]]::new()

    if (-not [string]::IsNullOrWhiteSpace($Users)) {
        foreach ($part in @($Users -split '[,;]+')) {
            $trimmed = $part.Trim()
            if ($trimmed) { $idents.Add($trimmed) }
        }
    }

    if (-not [string]::IsNullOrWhiteSpace($UserListPath)) {
        $resolvedPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($UserListPath)
        if (-not (Test-Path -LiteralPath $resolvedPath)) {
            throw "UserListPath not found: $resolvedPath"
        }

        $extension = [System.IO.Path]::GetExtension($resolvedPath).ToLowerInvariant()
        if ($extension -eq '.csv') {
            $rows = @(Import-Csv -LiteralPath $resolvedPath)
            foreach ($row in $rows) {
                $value = $null
                foreach ($propName in @('UserPrincipalName', 'Mail', 'ObjectId', 'Id', 'UPN', 'Email')) {
                    $prop = $row.PSObject.Properties | Where-Object { $_.Name -ieq $propName } | Select-Object -First 1
                    if ($prop -and -not [string]::IsNullOrWhiteSpace([string]$prop.Value)) {
                        $value = [string]$prop.Value
                        break
                    }
                }
                if (-not $value) {
                    $first = $row.PSObject.Properties | Select-Object -First 1
                    if ($first -and -not [string]::IsNullOrWhiteSpace([string]$first.Value)) {
                        $value = [string]$first.Value
                    }
                }
                if ($value) { $idents.Add($value.Trim()) }
            }
        }
        else {
            foreach ($line in @(Get-Content -LiteralPath $resolvedPath -ErrorAction Stop)) {
                $trimmed = $line.Trim()
                if (-not $trimmed -or $trimmed.StartsWith('#')) { continue }
                $idents.Add($trimmed)
            }
        }
    }

    if ($idents.Count -eq 0) { return @() }

    $seen = @{}
    $unique = [System.Collections.Generic.List[string]]::new()
    foreach ($identity in $idents) {
        $key = $identity.ToLowerInvariant()
        if ($seen.ContainsKey($key)) { continue }
        $seen[$key] = $true
        $unique.Add($identity)
    }
    return @($unique)
}

function Get-CopilotLicensedUsers {
    $skus = @(Get-MgSubscribedSku -All -ErrorAction Stop)
    $copilotSkuIds = @(
        $skus |
            Where-Object { $_.SkuPartNumber -match '(?i)COPILOT' } |
            Select-Object -ExpandProperty SkuId
    )

    $users = @(
        Get-MgUser -All -Property 'id,displayName,userPrincipalName,mail,assignedLicenses,accountEnabled' -ErrorAction Stop |
            Where-Object { $_.AccountEnabled }
    )
    if ($copilotSkuIds.Count -eq 0) {
        Write-AuditLog 'No Copilot SKUs detected via SkuPartNumber *COPILOT*; falling back to all enabled users.' Warn
        return $users
    }

    return @(
        $users | Where-Object {
            $_.AssignedLicenses.SkuId | Where-Object { $_ -in $copilotSkuIds }
        }
    )
}

function Add-ResolvedTargetUser {
    param(
        [Parameter(Mandatory)]$User,
        [string]$Identity = ''
    )

    if (-not $User.Id) { return $false }
    $userId = [string]$User.Id
    if ($Script:TargetUserIndex.ContainsKey($userId.ToLowerInvariant())) {
        return $false
    }

    $Script:TargetUsers.Add($User)
    Add-TargetUserIndexKey -Key $userId -User $User
    Add-TargetUserIndexKey -Key $User.UserPrincipalName -User $User
    Add-TargetUserIndexKey -Key $User.Mail -User $User
    Add-TargetUserIndexKey -Key $Identity -User $User
    Add-ExposureNode -Id $userId -Type User -DisplayName $User.DisplayName `
        -UserPrincipalName $User.UserPrincipalName -Mail $User.Mail
    return $true
}

function Initialize-TargetUserScope {
    $Script:TargetUserScopeEnabled = $false
    $Script:RunCoverage.UserScopeActive = $false
    $Script:TargetUserInputCount = 0
    $Script:TargetUserIndex = @{}
    $Script:TargetUsers = [System.Collections.Generic.List[object]]::new()

    $rawIdentities = @(Get-RawUserScopeIdentities)
    if ($rawIdentities.Count -eq 0) {
        if ($CopilotLicensedOnly) {
            Write-AuditLog 'Resolving enabled Copilot-licensed users for user reporting and OneDrive sampling...'
            $licensedUsers = @(Get-CopilotLicensedUsers)
            foreach ($user in $licensedUsers) {
                [void](Add-ResolvedTargetUser -User $user)
            }
            if ($Script:TargetUsers.Count -eq 0) {
                throw 'No enabled Copilot-licensed users were resolved in this tenant.'
            }
            $Script:TargetUserInputCount = $Script:TargetUsers.Count
            $Script:TargetUserScopeEnabled = $true
            $Script:RunCoverage.UserScopeActive = $true
            Write-AuditLog "User scope: $($Script:TargetUsers.Count) Copilot-licensed enabled users (resources remain tenant-wide)."
            return
        }
        Write-AuditLog 'User scope: none (tenant-wide user reporting / OneDrive sample).'
        return
    }

    $Script:TargetUserInputCount = $rawIdentities.Count
    Write-AuditLog "Resolving user scope list ($($rawIdentities.Count) input identities)..."

    $activity = 'Resolving scoped users'
    $i = 0
    try {
        foreach ($identity in $rawIdentities) {
            $i++
            Write-AuditProgress -Activity $activity -Current $i -Total $rawIdentities.Count -CurrentOperation $identity
            try {
                $user = Get-MgUser -UserId $identity -Property 'id,displayName,userPrincipalName,mail,accountEnabled' -ErrorAction Stop
            }
            catch {
                Write-AuditLog "  Could not resolve user '$identity': $($_.Exception.Message)" Warn
                continue
            }

            if (-not $user -or -not $user.Id) {
                Write-AuditLog "  Could not resolve user '$identity'." Warn
                continue
            }

            [void](Add-ResolvedTargetUser -User $user -Identity $identity)
        }
    }
    finally {
        Complete-AuditProgress -Activity $activity
    }

    if ($Script:TargetUsers.Count -eq 0) {
        throw "User scope list had $($rawIdentities.Count) identities but none resolved in this tenant."
    }

    $Script:TargetUserScopeEnabled = $true
    $Script:RunCoverage.UserScopeActive = $true
    Write-AuditLog "User scope: $($Script:TargetUsers.Count) resolved / $($rawIdentities.Count) input (resources remain tenant-wide)."
}

function Test-ShouldCollectUserReachMap {
    if ($SkipUserReachMap) { return $false }
    if ($IncludeUserReachMap) { return $true }
    return [bool]$Script:TargetUserScopeEnabled
}

function Test-IsInTargetUserScope {
    param(
        [string]$UserId = '',
        [string]$ObjectId = '',
        [string]$UserPrincipalName = '',
        [string]$Mail = ''
    )

    if (-not $Script:TargetUserScopeEnabled) { return $true }

    foreach ($candidate in @($UserId, $ObjectId, $UserPrincipalName, $Mail)) {
        if ([string]::IsNullOrWhiteSpace($candidate)) { continue }
        if ($Script:TargetUserIndex.ContainsKey($candidate.Trim().ToLowerInvariant())) {
            return $true
        }
    }
    return $false
}

function Test-LooksLikeGuid {
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $false }
    $parsed = [guid]::Empty
    return [guid]::TryParse($Value, [ref]$parsed)
}

function Get-OpenIdTenantId {
    param(
        [Parameter(Mandatory)]
        [string]$TenantHint
    )

    $uri = "https://login.microsoftonline.com/$TenantHint/v2.0/.well-known/openid-configuration"
    try {
        $doc = Invoke-RestMethod -Method Get -Uri $uri -ErrorAction Stop
    }
    catch {
        throw "Tenant discovery failed for '$TenantHint': $($_.Exception.Message)"
    }

    # issuer looks like .../{tenantId}/v2.0 ; token_endpoint embeds /{tenantId}/oauth2/...
    foreach ($candidate in @([string]$doc.issuer, [string]$doc.token_endpoint)) {
        if ($candidate -match '/([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})(/|$)') {
            return $Matches[1]
        }
    }

    throw "Could not resolve tenant id from OpenID discovery for '$TenantHint'."
}

function Resolve-AuditTenantTarget {
    param(
        [Parameter(Mandatory)]
        [string]$Name
    )

    $trimmed = $Name.Trim().TrimEnd('.')
    if ([string]::IsNullOrWhiteSpace($trimmed)) {
        throw 'TenantName is required.'
    }

    $prefix = Resolve-SharePointTenantName -Name $trimmed
    $organizationDomain = $null
    $discoveryHint = $null

    if (Test-LooksLikeGuid -Value $trimmed) {
        $discoveryHint = $trimmed
    }
    elseif ($trimmed.Contains('.')) {
        $organizationDomain = $trimmed
        $discoveryHint = $trimmed
    }
    else {
        $organizationDomain = "$prefix.onmicrosoft.com"
        $discoveryHint = $organizationDomain
    }

    $tenantId = Get-OpenIdTenantId -TenantHint $discoveryHint

    return [PSCustomObject]@{
        InputName          = $trimmed
        TenantId           = $tenantId
        OrganizationDomain = $organizationDomain
        SharePointPrefix   = $prefix
    }
}

function Get-ExchangeConnectedTenantInfo {
    try {
        if (-not (Get-Command Get-ConnectionInformation -ErrorAction SilentlyContinue)) {
            return $null
        }

        $connection = @(Get-ConnectionInformation -ErrorAction Stop | Where-Object {
                $_.State -eq 'Connected' -and
                (
                    -not $_.PSObject.Properties['IsValid'] -or
                    $_.IsValid -eq $true
                )
            }) | Select-Object -First 1

        if (-not $connection) { return $null }

        $tenantId = [string](Get-GraphObjectProperty -Object $connection -PropertyName 'TenantId')
        if (-not $tenantId) {
            $tenantId = [string](Get-GraphObjectProperty -Object $connection -PropertyName 'TenantID')
        }
        $organization = [string](Get-GraphObjectProperty -Object $connection -PropertyName 'Organization')

        return [PSCustomObject]@{
            TenantId     = $tenantId
            Organization = $organization
        }
    }
    catch {
        return $null
    }
}

function Test-ExchangeTenantMatchesTarget {
    param(
        [Parameter(Mandatory)]$TenantTarget
    )

    $info = Get-ExchangeConnectedTenantInfo
    if (-not $info) { return $false }

    if ($info.TenantId -and (Test-LooksLikeGuid -Value $info.TenantId)) {
        if ([string]::Equals($info.TenantId, $TenantTarget.TenantId, [System.StringComparison]::OrdinalIgnoreCase)) {
            return $true
        }
    }

    if ($TenantTarget.OrganizationDomain -and $info.Organization) {
        if ([string]::Equals($info.Organization, $TenantTarget.OrganizationDomain, [System.StringComparison]::OrdinalIgnoreCase)) {
            return $true
        }
        # EXO often reports the initial *.onmicrosoft.com domain
        if ($info.Organization -match [regex]::Escape($TenantTarget.SharePointPrefix) -and $info.Organization -match '\.onmicrosoft\.com$') {
            return $true
        }
    }

    return $false
}

function Assert-GraphTenantMatchesTarget {
    param(
        [Parameter(Mandatory)]$TenantTarget
    )

    $ctx = Get-MgContext
    if (-not $ctx) {
        throw 'Microsoft Graph is not connected.'
    }
    if (-not [string]::Equals([string]$ctx.TenantId, $TenantTarget.TenantId, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Microsoft Graph is connected to tenant '$($ctx.TenantId)' but this audit targets '$($TenantTarget.TenantId)' ($($TenantTarget.InputName))."
    }
}

function Assert-ExchangeTenantMatchesTarget {
    param(
        [Parameter(Mandatory)]$TenantTarget
    )

    if (-not (Test-ExchangeTenantMatchesTarget -TenantTarget $TenantTarget)) {
        $info = Get-ExchangeConnectedTenantInfo
        $actual = if ($info) { "TenantId=$($info.TenantId); Organization=$($info.Organization)" } else { 'no Connected session' }
        throw "Exchange Online session does not match target tenant '$($TenantTarget.TenantId)' ($($TenantTarget.InputName)). Connected: $actual"
    }
}

function Resolve-OrganizationDomainFromGraph {
    param(
        [Parameter(Mandatory)]$TenantTarget,
        [switch]$PreferInitialOnMicrosoft
    )

    # Keep vanity domain when already set unless caller needs EXO app-only's *.onmicrosoft.com.
    if ($TenantTarget.OrganizationDomain -and -not $PreferInitialOnMicrosoft) {
        return [string]$TenantTarget.OrganizationDomain
    }
    if ($PreferInitialOnMicrosoft -and $TenantTarget.OrganizationDomain -match '(?i)\.onmicrosoft\.com$') {
        return [string]$TenantTarget.OrganizationDomain
    }

    $org = @(Get-MgOrganization -ErrorAction Stop | Select-Object -First 1)
    if (-not $org) {
        throw 'Could not read organization profile from Microsoft Graph to resolve Exchange -Organization domain.'
    }

    $domains = @($org.VerifiedDomains)
    $initial = $domains | Where-Object { $_.IsInitial -eq $true } | Select-Object -First 1
    if (-not $initial) {
        $initial = $domains | Where-Object { $_.Name -match '\.onmicrosoft\.com$' } | Select-Object -First 1
    }
    if (-not $initial -and -not $PreferInitialOnMicrosoft) {
        $initial = $domains | Select-Object -First 1
    }
    if (-not $initial -or -not $initial.Name) {
        if ($TenantTarget.OrganizationDomain) {
            return [string]$TenantTarget.OrganizationDomain
        }
        throw 'No verified domain found on the Graph organization for Exchange -Organization.'
    }

    return [string]$initial.Name
}

function Get-IdentityParts {
    param(
        [string]$Id,
        [string]$DisplayName = '',
        [string]$UserPrincipalName = '',
        [string]$Mail = ''
    )

    $upn = $UserPrincipalName
    $mailAddr = $Mail
    $name = $DisplayName

    # If DisplayName looks like an email/UPN and UPN missing, promote it
    if (-not $upn -and $name -match '@') {
        $upn = $name
    }
    if (-not $mailAddr -and $upn -match '@') {
        $mailAddr = $upn
    }

    $objectId = if (Test-LooksLikeGuid -Value $Id) { $Id } else { '' }
    $label = if ($name) { $name } elseif ($upn) { $upn } elseif ($mailAddr) { $mailAddr } else { $Id }

    return [PSCustomObject]@{
        ObjectId          = $objectId
        DisplayName       = $label
        UserPrincipalName = $upn
        Mail              = $mailAddr
    }
}

function Add-ExposureNode {
    param(
        [Parameter(Mandatory)][string]$Id,
        [Parameter(Mandatory)][ValidateSet('User', 'Group', 'Site', 'Mailbox', 'DriveItem', 'Role', 'BroadPrincipal')]
        [string]$Type,
        [string]$DisplayName = '',
        [string]$UserPrincipalName = '',
        [string]$Mail = '',
        [double]$Score = 0,
        [string]$RiskFlags = '',
        [string]$Extra = ''
    )

    $parts = Get-IdentityParts -Id $Id -DisplayName $DisplayName -UserPrincipalName $UserPrincipalName -Mail $Mail

    if ($Script:NodeIndex.ContainsKey($Id)) {
        $existing = $Script:NodeIndex[$Id]
        if ($Score -gt [double]$existing.Score) { $existing.Score = $Score }
        if ($RiskFlags) {
            $merged = @(($existing.RiskFlags -split ',') + ($RiskFlags -split ',') | Where-Object { $_ } | Select-Object -Unique)
            $existing.RiskFlags = $merged -join ','
        }
        if ($parts.DisplayName -and (
                [string]::IsNullOrWhiteSpace($existing.DisplayName) -or
                ((Test-LooksLikeGuid -Value $existing.DisplayName) -and -not (Test-LooksLikeGuid -Value $parts.DisplayName))
            )) {
            $existing.DisplayName = $parts.DisplayName
        }
        if ($parts.UserPrincipalName -and [string]::IsNullOrWhiteSpace($existing.UserPrincipalName)) {
            $existing.UserPrincipalName = $parts.UserPrincipalName
        }
        if ($parts.Mail -and [string]::IsNullOrWhiteSpace($existing.Mail)) {
            $existing.Mail = $parts.Mail
        }
        if ($parts.ObjectId -and [string]::IsNullOrWhiteSpace($existing.ObjectId)) {
            $existing.ObjectId = $parts.ObjectId
        }
        if ($Extra) {
            $extraParts = @(($existing.Extra -split ';') + ($Extra -split ';') |
                Where-Object { $_ } | Select-Object -Unique)
            $existing.Extra = $extraParts -join ';'
        }
        $existing.Severity = Get-SeverityFromScore -Score ([double]$existing.Score)
        # Do not emit the node to the pipeline (avoids Format-List console spam).
        return
    }

    $node = [PSCustomObject]@{
        Id                = $Id
        ObjectId          = $parts.ObjectId
        Type              = $Type
        DisplayName       = $parts.DisplayName
        UserPrincipalName = $parts.UserPrincipalName
        Mail              = $parts.Mail
        Score             = $Score
        Severity          = (Get-SeverityFromScore -Score $Score)
        RiskFlags         = $RiskFlags
        Extra             = $Extra
    }
    $Script:Nodes.Add($node)
    $Script:NodeIndex[$Id] = $node
    # Do not emit the node to the pipeline (avoids Format-List console spam).
}

function Get-NodeLabel {
    param([string]$NodeId)

    if (-not $Script:NodeIndex.ContainsKey($NodeId)) {
        return [PSCustomObject]@{
            ObjectId          = $(if (Test-LooksLikeGuid -Value $NodeId) { $NodeId } else { '' })
            DisplayName       = $NodeId
            UserPrincipalName = ''
            Mail              = ''
        }
    }

    $n = $Script:NodeIndex[$NodeId]
    return [PSCustomObject]@{
        ObjectId          = $(if ($n.ObjectId) { $n.ObjectId } elseif (Test-LooksLikeGuid -Value $n.Id) { $n.Id } else { '' })
        DisplayName       = $n.DisplayName
        UserPrincipalName = $n.UserPrincipalName
        Mail              = $n.Mail
    }
}

function Add-ExposureEdge {
    param(
        [Parameter(Mandatory)][string]$SourceId,
        [Parameter(Mandatory)][string]$TargetId,
        [Parameter(Mandatory)][string]$EdgeType,
        [string]$Detail = '',
        [double]$Weight = 0
    )

    $source = Get-NodeLabel -NodeId $SourceId
    $target = Get-NodeLabel -NodeId $TargetId

    $Script:Edges.Add([PSCustomObject]@{
        SourceId                = $SourceId
        SourceObjectId          = $source.ObjectId
        SourceDisplayName       = $source.DisplayName
        SourceUserPrincipalName = $source.UserPrincipalName
        SourceMail              = $source.Mail
        TargetId                = $TargetId
        TargetObjectId          = $target.ObjectId
        TargetDisplayName       = $target.DisplayName
        TargetUserPrincipalName = $target.UserPrincipalName
        TargetMail              = $target.Mail
        EdgeType                = $EdgeType
        Detail                  = $Detail
        Weight                  = $Weight
    })
}

function Update-EdgeIdentityLabels {
    $activity = 'Labeling graph edges'
    $total = $Script:Edges.Count
    $i = 0
    try {
        foreach ($edge in $Script:Edges) {
            $i++
            if ($total -gt 0 -and (($i % 25 -eq 0) -or $i -eq $total)) {
                Write-AuditProgress -Activity $activity -Current $i -Total $total
            }
            $source = Get-NodeLabel -NodeId $edge.SourceId
            $target = Get-NodeLabel -NodeId $edge.TargetId
            $edge.SourceObjectId = $source.ObjectId
            $edge.SourceDisplayName = $source.DisplayName
            $edge.SourceUserPrincipalName = $source.UserPrincipalName
            $edge.SourceMail = $source.Mail
            $edge.TargetObjectId = $target.ObjectId
            $edge.TargetDisplayName = $target.DisplayName
            $edge.TargetUserPrincipalName = $target.UserPrincipalName
            $edge.TargetMail = $target.Mail
        }
    }
    finally {
        Complete-AuditProgress -Activity $activity
    }
}

function Complete-UserIdentityLabels {
    Write-AuditLog "`nEnriching user identities (UPN / mail / display name)..."
    $candidates = @($Script:Nodes | Where-Object {
            $_.Type -eq 'User' -and
            (
                [string]::IsNullOrWhiteSpace($_.UserPrincipalName) -or
                [string]::IsNullOrWhiteSpace($_.Mail) -or
                (Test-LooksLikeGuid -Value $_.DisplayName)
            ) -and
            (
                (Test-LooksLikeGuid -Value $_.Id) -or $_.Id -match '@'
            ) -and
            (
                Test-IsInTargetUserScope -UserId $_.Id -ObjectId $_.ObjectId -UserPrincipalName $_.UserPrincipalName -Mail $_.Mail
            )
        })

    if ($Script:TargetUserScopeEnabled) {
        Write-AuditLog "  User scope active: enriching only listed users ($($candidates.Count) candidates)."
    }

    $enriched = 0
    $i = 0
    $activity = 'Enriching user identities'
    try {
        foreach ($node in $candidates) {
            $i++
            Write-AuditProgress -Activity $activity -Current $i -Total $candidates.Count -CurrentOperation ([string]$node.Id)

            try {
                $user = Get-MgUser -UserId $node.Id -Property 'id,displayName,userPrincipalName,mail' -ErrorAction Stop
                if ($user.DisplayName) { $node.DisplayName = $user.DisplayName }
                if ($user.UserPrincipalName) { $node.UserPrincipalName = $user.UserPrincipalName }
                if ($user.Mail) { $node.Mail = $user.Mail }
                elseif ($user.UserPrincipalName) { $node.Mail = $user.UserPrincipalName }
                if ($user.Id) { $node.ObjectId = $user.Id }
                $enriched++
            }
            catch {
                # leave as-is (could be a non-user principal string)
            }
        }
    }
    finally {
        Complete-AuditProgress -Activity $activity
    }

    Write-AuditLog "  Enriched $enriched of $($candidates.Count) candidate user node(s)."
}

function Test-PowerShellGetAvailable {
    try {
        Import-Module PackageManagement -ErrorAction SilentlyContinue
        Import-Module PowerShellGet -ErrorAction SilentlyContinue
        $null = Get-PackageProvider -Name NuGet -ErrorAction Stop
        $null = Get-Command Install-Module -ErrorAction Stop
        return $true
    }
    catch {
        return $false
    }
}

function Initialize-PowerShellGet {
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    }
    catch { }

    foreach ($name in @('PackageManagement', 'PowerShellGet')) {
        try {
            Import-Module $name -ErrorAction SilentlyContinue
        }
        catch { }
    }

    try {
        $nuget = Get-PackageProvider -Name NuGet -ErrorAction SilentlyContinue
        if (-not $nuget -or [version]$nuget.Version -lt [version]'2.8.5.201') {
            Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -Scope CurrentUser -ErrorAction Stop | Out-Null
        }
    }
    catch {
        return $false
    }

    try {
        $repo = Get-PSRepository -Name PSGallery -ErrorAction SilentlyContinue
        if ($repo -and $repo.InstallationPolicy -ne 'Trusted') {
            Set-PSRepository -Name PSGallery -InstallationPolicy Trusted -ErrorAction SilentlyContinue
        }
    }
    catch { }

    return (Test-PowerShellGetAvailable)
}

function Ensure-ModulePresent {
    param(
        [Parameter(Mandatory)][string]$Name,
        [string]$MinimumVersion,
        [switch]$AllowInstallFailure
    )

    $module = Get-Module -ListAvailable -Name $Name | Sort-Object Version -Descending | Select-Object -First 1
    if ($module) {
        return $true
    }

    if (-not (Test-PowerShellGetAvailable)) {
        $message = "Module '$Name' is not installed, and PowerShellGet is unavailable in this -NoProfile session."
        if ($AllowInstallFailure) {
            Write-AuditLog $message Warn
            Write-AuditLog "Install once outside this script: Install-Module $Name -Scope CurrentUser -Force" Info
            return $false
        }
        if (-not (Initialize-PowerShellGet)) {
            throw $message
        }
    }
    elseif (-not (Initialize-PowerShellGet)) {
        if ($AllowInstallFailure) {
            Write-AuditLog "Cannot prepare PowerShellGet to install '$Name'." Warn
            return $false
        }
        throw "Cannot prepare PowerShellGet to install '$Name'."
    }

    Write-AuditLog "Module '$Name' not found; attempting install..." Warn
    try {
        $params = @{ Name = $Name; Scope = 'CurrentUser'; Force = $true; AllowClobber = $true; ErrorAction = 'Stop' }
        if ($MinimumVersion) { $params['MinimumVersion'] = $MinimumVersion }
        Install-Module @params
        $module = Get-Module -ListAvailable -Name $Name | Sort-Object Version -Descending | Select-Object -First 1
        return [bool]$module
    }
    catch {
        if ($AllowInstallFailure) {
            Write-AuditLog "Install of '$Name' failed: $($_.Exception.Message)" Warn
            Write-AuditLog "Install once in a normal PowerShell window: Install-Module $Name -Scope CurrentUser -Force" Info
            return $false
        }
        throw
    }
}
#endregion

#region Connections
function Test-ExchangeOnlineConnected {
    try {
        if (-not (Get-Command Get-ConnectionInformation -ErrorAction SilentlyContinue)) {
            return $false
        }

        $connections = @(Get-ConnectionInformation -ErrorAction Stop | Where-Object {
            $_.State -eq 'Connected' -and
            (
                -not $_.PSObject.Properties['IsValid'] -or
                $_.IsValid -eq $true
            )
        })

        return ($connections.Count -gt 0)
    }
    catch {
        return $false
    }
}

function Get-ExoConnectParameterNames {
    try {
        return @((Get-Command Connect-ExchangeOnline -ErrorAction Stop).Parameters.Keys)
    }
    catch {
        return @()
    }
}

function Get-ExchangeUserPrincipalNameHint {
    if (-not [string]::IsNullOrWhiteSpace($ExchangeUserPrincipalName)) {
        return $ExchangeUserPrincipalName.Trim()
    }

    # Single scoped UPN is a useful Connect-ExchangeOnline hint in device/browser flows.
    if (-not [string]::IsNullOrWhiteSpace($Users)) {
        $first = @($Users -split '[,;]+' | ForEach-Object { $_.Trim() } | Where-Object { $_ }) | Select-Object -First 1
        if ($first -and $first -match '@' -and $first -notmatch '\s') {
            return $first
        }
    }

    return $null
}

function New-ExoConnectSplat {
    param(
        [ValidateSet('DisableWAM', 'Device', 'Interactive')]
        [string]$Mode
    )

    $names = Get-ExoConnectParameterNames
    $splat = @{
        ShowBanner  = $false
        ErrorAction = 'Stop'
    }

    $upnHint = Get-ExchangeUserPrincipalNameHint
    if ($upnHint -and ($names -contains 'UserPrincipalName')) {
        $splat['UserPrincipalName'] = $upnHint
    }

    if ($Script:AuditTenant -and $Script:AuditTenant.OrganizationDomain -and ($names -contains 'Organization')) {
        $splat['Organization'] = $Script:AuditTenant.OrganizationDomain
    }

    # Avoid PowerShell's 4096-function limit when Graph/SPO modules are also loaded.
    if ($names -contains 'CommandName') {
        $splat['CommandName'] = @(
            'Get-EXOMailbox',
            'Get-EXOMailboxPermission',
            'Get-MailboxPermission',
            'Get-RecipientPermission',
            'Get-EXORecipientPermission',
            'Get-ConnectionInformation',
            'Disconnect-ExchangeOnline'
        )
    }
    if ($names -contains 'SkipLoadingFormatData') {
        $splat['SkipLoadingFormatData'] = $true
    }
    if ($names -contains 'SkipLoadingCmdletHelp') {
        $splat['SkipLoadingCmdletHelp'] = $true
    }

    switch ($Mode) {
        'DisableWAM' {
            if ($names -notcontains 'DisableWAM') { return $null }
            $splat['DisableWAM'] = $true
        }
        'Device' {
            if ($names -contains 'Device') {
                $splat['Device'] = $true
            }
            elseif ($names -contains 'DeviceCode') {
                $splat['DeviceCode'] = $true
            }
            elseif ($names -contains 'UseDeviceAuthentication') {
                $splat['UseDeviceAuthentication'] = $true
            }
            else {
                return $null
            }
        }
        'Interactive' {
            # default interactive / WAM
        }
    }

    return $splat
}

function Import-GraphCertificateToCurrentUserStore {
    param([Parameter(Mandatory)][string]$CertPath)

    $resolved = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($CertPath)
    if (-not (Test-Path -LiteralPath $resolved)) {
        throw "Certificate file not found: $resolved"
    }

    $certPassword = Get-GraphCertificatePasswordSecureString
    $plain = $null
    if ($certPassword) {
        $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($certPassword)
        try { $plain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) }
        finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
    }

    $flags = [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable -bor
        [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::PersistKeySet
    if ($plain) {
        $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($resolved, $plain, $flags)
    }
    else {
        $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($resolved, '', $flags)
    }

    $store = [System.Security.Cryptography.X509Certificates.X509Store]::new('My', 'CurrentUser')
    $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
    try { $store.Add($cert) } finally { $store.Close() }
    return $cert
}

function Connect-ExchangeOnlineAppOnly {
    param([Parameter(Mandatory)]$TenantTarget)

    if ([string]::IsNullOrWhiteSpace($GraphAppId)) { return $false }
    if ([string]::IsNullOrWhiteSpace($GraphCertificateThumbprint) -and [string]::IsNullOrWhiteSpace($GraphCertificatePath)) {
        return $false
    }

    # EXO app-only requires the tenant's initial *.onmicrosoft.com domain (vanity domains often fail).
    $exoOrg = $null
    try {
        $exoOrg = Resolve-OrganizationDomainFromGraph -TenantTarget $TenantTarget -PreferInitialOnMicrosoft
    }
    catch {
        $exoOrg = $TenantTarget.OrganizationDomain
    }
    if ([string]::IsNullOrWhiteSpace($exoOrg)) { return $false }
    if ($exoOrg -ine [string]$TenantTarget.OrganizationDomain) {
        Write-AuditLog "  EXO app-only Organization domain: $exoOrg (from Graph initial domain; TenantName was $($TenantTarget.OrganizationDomain))"
    }

    $thumbprint = $GraphCertificateThumbprint
    if ([string]::IsNullOrWhiteSpace($thumbprint) -and $GraphCertificatePath) {
        $imported = Import-GraphCertificateToCurrentUserStore -CertPath $GraphCertificatePath
        $thumbprint = [string]$imported.Thumbprint
    }
    elseif ($GraphCertificatePath -and $thumbprint) {
        # Ensure PFX is in this process's cert store (clean child relaunch / missing private key).
        try {
            $null = Get-Item -Path "Cert:\CurrentUser\My\$thumbprint" -ErrorAction Stop
        }
        catch {
            Write-AuditLog '  Certificate thumbprint not found in CurrentUser\My; importing PFX for EXO...' Warn
            $imported = Import-GraphCertificateToCurrentUserStore -CertPath $GraphCertificatePath
            $thumbprint = [string]$imported.Thumbprint
        }
    }

    $paramNames = @(Get-ExoConnectParameterNames)
    $params = @{
        AppId        = $GraphAppId
        Organization = $exoOrg
        ShowBanner   = $false
        ErrorAction  = 'Stop'
    }
    if ($paramNames -contains 'CertificateThumbprint') {
        $params['CertificateThumbprint'] = $thumbprint
    }
    elseif ($paramNames -contains 'CertificateThumbPrint') {
        $params['CertificateThumbPrint'] = $thumbprint
    }
    else {
        Write-AuditLog '  Connect-ExchangeOnline has no CertificateThumbprint parameter on this module build.' Warn
        return $false
    }

    Write-AuditLog "  Attempting Exchange Online app-only (AppId=$GraphAppId; Organization=$exoOrg; thumbprint=$thumbprint)..."
    Connect-ExchangeOnline @params
    Start-Sleep -Seconds 2
    if (-not (Test-ExchangeOnlineConnected)) {
        Write-AuditLog '  Connect-ExchangeOnline completed but no Connected EXO session was detected.' Warn
        return $false
    }
    Assert-ExchangeTenantMatchesTarget -TenantTarget $TenantTarget
    $Script:ExchangeAvailable = $true
    Write-AuditLog "  Exchange Online connected (AppOnly) to tenant $($TenantTarget.TenantId) via $exoOrg."
    return $true
}

function Connect-ExchangeOnlineResilient {
    param(
        [Parameter(Mandatory)]$TenantTarget
    )

    if ($SkipExchange) {
        Write-AuditLog 'Skipping Exchange Online (-SkipExchange).' Warn
        $Script:ExchangeAvailable = $false
        $Script:RunCoverage.ExchangeSkippedReason = 'SkipExchange'
        return
    }

    Write-AuditLog "Connecting to Exchange Online (Organization=$($TenantTarget.OrganizationDomain))..."
    $Script:ExchangeAvailable = $false

    if (Test-ExchangeOnlineConnected) {
        if (Test-ExchangeTenantMatchesTarget -TenantTarget $TenantTarget) {
            Write-AuditLog '  Existing Exchange Online session matches target tenant.'
            $Script:ExchangeAvailable = $true
            return
        }

        Write-AuditLog '  Existing Exchange Online session is for a different tenant; disconnecting...' Warn
        try { Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue } catch { }
    }

    # App-only Graph runs: never open interactive EXO logins. Certificate enables EXO app-only.
    if ($Script:GraphAuthMode -eq 'AppOnly') {
        try {
            if (Connect-ExchangeOnlineAppOnly -TenantTarget $TenantTarget) {
                return
            }
            Write-AuditLog '  Exchange Online app-only did not establish a session.' Warn
        }
        catch {
            Write-AuditLog "  Exchange Online app-only failed: $($_.Exception.Message)" Warn
            try { Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue } catch { }
        }

        Write-AuditLog 'Skipping Exchange Online interactive login (unattended app-only Graph run).' Warn
        Write-AuditLog '  Ensure certificate + Exchange.ManageAsApp + Exchange Administrator on the app SP; Organization must be the tenant *.onmicrosoft.com domain.' Info
        $Script:ExchangeAvailable = $false
        $Script:RunCoverage.ExchangeSkippedReason = 'AppOnlyUnattended'
        return
    }

    $modeOrder = [System.Collections.Generic.List[string]]::new()
    if ($ExchangeDeviceLogin) {
        # Cursor/VS Code: device code first — DisableWAM/browser often hangs after Graph auth.
        $modeOrder.Add('Device')
        $modeOrder.Add('DisableWAM')
        $modeOrder.Add('Interactive')
    }
    else {
        $modeOrder.Add('DisableWAM')
        $modeOrder.Add('Interactive')
        $modeOrder.Add('Device')
    }

    $upnHint = Get-ExchangeUserPrincipalNameHint
    if ($upnHint) {
        Write-AuditLog "  Exchange UPN hint: $upnHint"
    }

    $lastError = $null
    $attempted = 0
    foreach ($mode in $modeOrder) {
        $params = New-ExoConnectSplat -Mode $mode
        if (-not $params) {
            if ($mode -eq 'Device') {
                Write-AuditLog '  Device-code login is not supported by this ExchangeOnlineManagement build; trying other methods...' Warn
            }
            continue
        }

        $attempted++
        try {
            Write-AuditLog "  Attempting Exchange Online sign-in ($mode)..."
            if ($mode -eq 'Device') {
                Write-AuditLog '  Watch for a device code / URL below (separate from the Graph browser sign-in).' Info
            }
            elseif ($mode -eq 'DisableWAM') {
                Write-AuditLog '  A browser window may open. If this sits idle for >2 minutes, press Ctrl+C and re-run with -ExchangeDeviceLogin (device code) or -SkipExchange.' Warn
            }

            Connect-ExchangeOnline @params
            Start-Sleep -Seconds 1
            if (Test-ExchangeOnlineConnected) {
                Assert-ExchangeTenantMatchesTarget -TenantTarget $TenantTarget
                $Script:ExchangeAvailable = $true
                Write-AuditLog "  Exchange Online connected ($mode) to tenant $($TenantTarget.TenantId)."
                return
            }

            $lastError = "Connect-ExchangeOnline ($mode) returned but no Connected session was found."
            Write-AuditLog "  $lastError" Warn
            try { Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue } catch { }
        }
        catch {
            $lastError = $_.Exception.Message
            Write-AuditLog "  Exchange connect ($mode) failed: $lastError" Warn
            try { Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue } catch { }
        }
    }

    if ($attempted -eq 0) {
        Write-AuditLog 'No compatible Connect-ExchangeOnline auth parameters found on this module.' Warn
    }

    Write-AuditLog 'Exchange Online unavailable; mailbox delegation scan will be skipped.' Warn
    Write-AuditLog 'Tips: start a clean shell: powershell.exe -NoProfile, then re-run; use -ExchangeDeviceLogin; or -SkipExchange.' Info
    Write-AuditLog "Optional: -ExchangeUserPrincipalName user@$($TenantTarget.OrganizationDomain)" Info
    if ($lastError -match '4096|function capacity') {
        Write-AuditLog '  This session has too many loaded functions (common with Graph + conda/profile). A -NoProfile window usually fixes it.' Warn
    }
    if ($lastError) {
        Write-AuditLog "  Last error: $lastError" Warn
    }
    $Script:ExchangeAvailable = $false
}

function Get-ResourceAppRoleMap {
    param(
        [Parameter(Mandatory)][string]$ResourceAppId,
        [Parameter(Mandatory)][string]$ResourceLabel
    )

    $uri = "https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=appId eq '$ResourceAppId'&`$select=id,appId,appRoles"
    $response = Invoke-MgGraphRequest -Method GET -Uri $uri -ErrorAction Stop
    $sp = @((Get-GraphObjectProperty -Object $response -PropertyName 'value')) | Select-Object -First 1
    if (-not $sp) {
        throw "Could not resolve the $ResourceLabel service principal (appId $ResourceAppId)."
    }

    $roles = @{}
    foreach ($role in @((Get-GraphObjectProperty -Object $sp -PropertyName 'appRoles'))) {
        $value = [string](Get-GraphObjectProperty -Object $role -PropertyName 'value')
        $id = [string](Get-GraphObjectProperty -Object $role -PropertyName 'id')
        $enabled = Get-GraphObjectProperty -Object $role -PropertyName 'isEnabled'
        if ($value -and $id -and ($enabled -ne $false)) {
            $roles[$value] = $id
        }
    }

    return [PSCustomObject]@{
        ServicePrincipalId = [string](Get-GraphObjectProperty -Object $sp -PropertyName 'id')
        AppId              = $ResourceAppId
        RolesByValue       = $roles
    }
}

function Get-MicrosoftGraphAppRoleMap {
    return (Get-ResourceAppRoleMap -ResourceAppId '00000003-0000-0000-c000-000000000000' -ResourceLabel 'Microsoft Graph')
}

function Get-ExchangeOnlineAppRoleMap {
    # Office 365 Exchange Online
    return (Get-ResourceAppRoleMap -ResourceAppId '00000002-0000-0ff1-ce00-000000000000' -ResourceLabel 'Office 365 Exchange Online')
}

function New-CopilotAuditAppCertificate {
    param(
        [Parameter(Mandatory)][string]$DisplayName,
        [Parameter(Mandatory)][int]$ValidMonths,
        [Parameter(Mandatory)][string]$PfxPath
    )

    $notAfter = (Get-Date).AddMonths($ValidMonths)
    $cert = New-SelfSignedCertificate `
        -Subject "CN=$DisplayName" `
        -CertStoreLocation 'Cert:\CurrentUser\My' `
        -KeyExportPolicy Exportable `
        -KeySpec Signature `
        -KeyLength 2048 `
        -KeyAlgorithm RSA `
        -HashAlgorithm SHA256 `
        -NotAfter $notAfter `
        -ErrorAction Stop

    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $bytes = New-Object byte[] 32
    $rng.GetBytes($bytes)
    $pwdPlain = [Convert]::ToBase64String($bytes)
    $pwdSecure = ConvertTo-SecureString -String $pwdPlain -AsPlainText -Force
    $null = Export-PfxCertificate -Cert $cert -FilePath $PfxPath -Password $pwdSecure -ErrorAction Stop

    return [PSCustomObject]@{
        Certificate   = $cert
        Thumbprint    = [string]$cert.Thumbprint
        PfxPath       = $PfxPath
        PasswordPlain = $pwdPlain
        PasswordSecure = $pwdSecure
        KeyBase64     = [Convert]::ToBase64String($cert.RawData)
    }
}

function Grant-AppRoleAssignments {
    param(
        [Parameter(Mandatory)][string]$PrincipalSpId,
        [Parameter(Mandatory)]$ResourceMap,
        [Parameter(Mandatory)][string[]]$PermissionValues
    )

    $failures = [System.Collections.Generic.List[string]]::new()
    foreach ($permValue in $PermissionValues) {
        if (-not $ResourceMap.RolesByValue.ContainsKey($permValue)) {
            [void]$failures.Add("$permValue (app role not found on resource)")
            Write-AuditLog "  Admin consent skipped; role missing on resource: $permValue" Warn
            continue
        }
        $roleId = $ResourceMap.RolesByValue[$permValue]
        $assignBody = @{
            principalId = $PrincipalSpId
            resourceId  = $ResourceMap.ServicePrincipalId
            appRoleId   = $roleId
        }
        try {
            Invoke-MgGraphRequest -Method POST `
                -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$($ResourceMap.ServicePrincipalId)/appRoleAssignedTo" `
                -Body $assignBody -ContentType 'application/json' -ErrorAction Stop | Out-Null
            Write-AuditLog "  Admin consent granted: $permValue"
        }
        catch {
            [void]$failures.Add("$permValue ($($_.Exception.Message))")
            Write-AuditLog "  Admin consent failed for ${permValue}: $($_.Exception.Message)" Warn
        }
    }
    return @($failures)
}

function Grant-ExchangeAdministratorRole {
    param([Parameter(Mandatory)][string]$PrincipalSpId)

    try {
        $uri = "https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions?`$filter=displayName eq 'Exchange Administrator'&`$select=id,displayName"
        $response = Invoke-MgGraphRequest -Method GET -Uri $uri -ErrorAction Stop
        $roleDef = @((Get-GraphObjectProperty -Object $response -PropertyName 'value')) | Select-Object -First 1
        $roleDefId = [string](Get-GraphObjectProperty -Object $roleDef -PropertyName 'id')
        if (-not $roleDefId) {
            Write-AuditLog '  Could not resolve Exchange Administrator role definition; assign it manually to the app service principal.' Warn
            return $false
        }

        $body = @{
            '@odata.type'      = '#microsoft.graph.unifiedRoleAssignment'
            principalId        = $PrincipalSpId
            roleDefinitionId   = $roleDefId
            directoryScopeId   = '/'
        }
        Invoke-MgGraphRequest -Method POST `
            -Uri 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments' `
            -Body $body -ContentType 'application/json' -ErrorAction Stop | Out-Null
        Write-AuditLog '  Assigned Entra role: Exchange Administrator (required for EXO app-only mailbox reads).'
        return $true
    }
    catch {
        Write-AuditLog "  Exchange Administrator role assignment failed: $($_.Exception.Message)" Warn
        Write-AuditLog '  Assign Exchange Administrator to the app service principal in Entra if mailbox scans should run unattended.' Warn
        return $false
    }
}

function Register-CopilotAuditGraphApp {
    param(
        [Parameter(Mandatory)]$TenantTarget,
        [string]$DisplayName = 'Copilot-O365-OverPermission-Audit',
        [int]$SecretValidMonths = 12
    )

    if ($SecretValidMonths -lt 1 -or $SecretValidMonths -gt 24) {
        throw 'GraphAppSecretValidMonths must be between 1 and 24 (certificate validity months).'
    }

    Write-AuditLog "`nRegistering Entra application for app-only Graph + Exchange..."
    Write-AuditLog "  DisplayName: $DisplayName"

    $graphSp = Get-MicrosoftGraphAppRoleMap
    $exoSp = Get-ExchangeOnlineAppRoleMap
    $graphAccess = [System.Collections.Generic.List[object]]::new()
    $missing = [System.Collections.Generic.List[string]]::new()
    foreach ($permValue in $Script:GraphAppRequiredPermissionValues) {
        if (-not $graphSp.RolesByValue.ContainsKey($permValue)) {
            [void]$missing.Add($permValue)
            continue
        }
        $graphAccess.Add(@{
                id   = $graphSp.RolesByValue[$permValue]
                type = 'Role'
            })
    }
    if ($missing.Count -gt 0) {
        throw "Microsoft Graph service principal is missing app roles: $($missing -join ', ')"
    }
    if (-not $exoSp.RolesByValue.ContainsKey('Exchange.ManageAsApp')) {
        throw 'Office 365 Exchange Online service principal is missing app role Exchange.ManageAsApp.'
    }

    $pfxPath = Join-Path $PSScriptRoot '.graph-app.local.pfx'
    $certInfo = New-CopilotAuditAppCertificate -DisplayName $DisplayName -ValidMonths $SecretValidMonths -PfxPath $pfxPath
    Write-AuditLog "  Created certificate thumbprint=$($certInfo.Thumbprint) (valid $SecretValidMonths month(s)); PFX=$pfxPath"

    $appBody = @{
        displayName            = $DisplayName
        signInAudience         = 'AzureADMyOrg'
        keyCredentials         = @(
            @{
                type        = 'AsymmetricX509Cert'
                usage       = 'Verify'
                key         = $certInfo.KeyBase64
                displayName = "CN=$DisplayName"
            }
        )
        requiredResourceAccess = @(
            @{
                resourceAppId  = $graphSp.AppId
                resourceAccess = @($graphAccess)
            }
            @{
                resourceAppId  = $exoSp.AppId
                resourceAccess = @(
                    @{
                        id   = $exoSp.RolesByValue['Exchange.ManageAsApp']
                        type = 'Role'
                    }
                )
            }
        )
    }

    $app = Invoke-MgGraphRequest -Method POST -Uri 'https://graph.microsoft.com/v1.0/applications' `
        -Body $appBody -ContentType 'application/json' -ErrorAction Stop
    $objectId = [string](Get-GraphObjectProperty -Object $app -PropertyName 'id')
    $clientId = [string](Get-GraphObjectProperty -Object $app -PropertyName 'appId')
    if (-not $objectId -or -not $clientId) {
        throw 'Application create returned no id/appId.'
    }
    Write-AuditLog "  Created application ObjectId=$objectId AppId=$clientId"

    $sp = Invoke-MgGraphRequest -Method POST -Uri 'https://graph.microsoft.com/v1.0/servicePrincipals' `
        -Body @{ appId = $clientId } -ContentType 'application/json' -ErrorAction Stop
    $spId = [string](Get-GraphObjectProperty -Object $sp -PropertyName 'id')
    if (-not $spId) {
        throw 'Service principal create returned no id.'
    }
    Write-AuditLog "  Created service principal Id=$spId"

    $consentFailures = [System.Collections.Generic.List[string]]::new()
    foreach ($fail in @(Grant-AppRoleAssignments -PrincipalSpId $spId -ResourceMap $graphSp -PermissionValues @($Script:GraphAppRequiredPermissionValues))) {
        [void]$consentFailures.Add($fail)
    }
    foreach ($fail in @(Grant-AppRoleAssignments -PrincipalSpId $spId -ResourceMap $exoSp -PermissionValues @('Exchange.ManageAsApp'))) {
        [void]$consentFailures.Add($fail)
    }
    $null = Grant-ExchangeAdministratorRole -PrincipalSpId $spId

    [Environment]::SetEnvironmentVariable('COPILOT_GRAPH_APP_ID', $clientId)
    [Environment]::SetEnvironmentVariable('COPILOT_GRAPH_CERT_THUMBPRINT', $certInfo.Thumbprint)
    [Environment]::SetEnvironmentVariable('COPILOT_GRAPH_CERT_PATH', $pfxPath)
    [Environment]::SetEnvironmentVariable('COPILOT_GRAPH_CERT_PASSWORD', $certInfo.PasswordPlain)

    $script:GraphAppId = $clientId
    Set-Variable -Name GraphAppId -Value $clientId -Scope Script -Force
    Set-Variable -Name GraphCertificateThumbprint -Value $certInfo.Thumbprint -Scope Script -Force
    Set-Variable -Name GraphCertificatePath -Value $pfxPath -Scope Script -Force
    Set-Variable -Name GraphCertificatePassword -Value $certInfo.PasswordSecure -Scope Script -Force
    # Prefer cert over any leftover secret env from older registrations.
    Set-Variable -Name GraphClientSecretEnvVar -Value '' -Scope Script -Force
    Set-Variable -Name GraphClientSecret -Value $null -Scope Script -Force

    $helperPath = Join-Path $PSScriptRoot '.graph-app.local.ps1'
    $pwdEscaped = $certInfo.PasswordPlain -replace "'", "''"
    $pfxEscaped = $pfxPath -replace "'", "''"
    $helper = @"
# Generated by copilot_audit.ps1 -RegisterGraphApp — DO NOT COMMIT
# Tenant: $($TenantTarget.TenantId)
# App display name: $DisplayName
# Certificate auth (Graph + Exchange.ManageAsApp). Cert also in CurrentUser\My.
`$env:COPILOT_GRAPH_APP_ID = '$clientId'
`$env:COPILOT_GRAPH_CERT_THUMBPRINT = '$($certInfo.Thumbprint)'
`$env:COPILOT_GRAPH_CERT_PATH = '$pfxEscaped'
`$env:COPILOT_GRAPH_CERT_PASSWORD = '$pwdEscaped'
# Unattended audit (Graph + EXO app-only; no interactive logins):
# . .\.graph-app.local.ps1
# .\copilot_audit.ps1 -TenantName '$TenantName' -Users 'user@$($TenantTarget.OrganizationDomain)'
"@
    [System.IO.File]::WriteAllText($helperPath, $helper, [System.Text.UTF8Encoding]::new($false))

    Write-Host ''
    Write-Host '========== Graph app registration complete ==========' -ForegroundColor Green
    Write-Host "AppId (Client ID): $clientId" -ForegroundColor Green
    Write-Host "Certificate thumbprint: $($certInfo.Thumbprint)" -ForegroundColor Green
    Write-Host "PFX path:          $pfxPath" -ForegroundColor Cyan
    Write-Host "Helper script:     $helperPath" -ForegroundColor Cyan
    Write-Host 'Permissions: Graph app roles + Exchange.ManageAsApp (+ Exchange Administrator on SP when allowed).' -ForegroundColor Cyan
    Write-Host '(PFX password is in .graph-app.local.ps1 / COPILOT_GRAPH_CERT_PASSWORD — do not commit.)' -ForegroundColor Yellow
    if ($consentFailures.Count -gt 0) {
        $consentUrl = "https://login.microsoftonline.com/$($TenantTarget.TenantId)/adminconsent?client_id=$clientId"
        Write-Host 'Admin consent was incomplete. Open this URL as a Global Admin / Privileged Role Admin:' -ForegroundColor Yellow
        Write-Host "  $consentUrl" -ForegroundColor Yellow
    }
    Write-Host '====================================================' -ForegroundColor Green
    Write-Host ''

    return [PSCustomObject]@{
        AppId              = $clientId
        ObjectId           = $objectId
        ServicePrincipalId = $spId
        CertificateThumbprint = $certInfo.Thumbprint
        PfxPath            = $pfxPath
        HelperPath         = $helperPath
        ConsentFailures    = @($consentFailures)
    }
}

function Connect-DelegatedGraphForAppRegistration {
    param([Parameter(Mandatory)]$TenantTarget)

    $registerScopes = @(
        'Application.ReadWrite.All',
        'AppRoleAssignment.ReadWrite.All',
        'Directory.Read.All',
        'RoleManagement.ReadWrite.Directory'
    )

    $ctx = Get-MgContext
    if ($ctx -and -not [string]::Equals([string]$ctx.TenantId, $TenantTarget.TenantId, [System.StringComparison]::OrdinalIgnoreCase)) {
        try { Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null } catch { }
        $ctx = $null
    }

    $existingAuthType = if ($ctx) { [string](Get-GraphObjectProperty -Object $ctx -PropertyName 'AuthType') } else { '' }
    if ($ctx -and $existingAuthType -eq 'AppOnly') {
        try { Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null } catch { }
        $ctx = $null
    }

    if (-not $ctx) {
        Write-AuditLog "Connecting to Microsoft Graph (delegated) for app registration (TenantId=$($TenantTarget.TenantId))..."
        Connect-MgGraph -TenantId $TenantTarget.TenantId -Scopes $registerScopes -NoWelcome
    }
    else {
        Write-AuditLog '  Using existing delegated Graph session for app registration (ensure Application.ReadWrite.All was consented).'
    }
}

function Test-GraphAppOnlyConfigured {
    if ([string]::IsNullOrWhiteSpace($GraphAppId)) { return $false }
    if (-not [string]::IsNullOrWhiteSpace($GraphCertificateThumbprint)) { return $true }
    if (-not [string]::IsNullOrWhiteSpace($GraphCertificatePath)) { return $true }
    if ($GraphClientSecret -and $GraphClientSecret.Length -gt 0) { return $true }
    if (-not [string]::IsNullOrWhiteSpace($GraphClientSecretEnvVar) -and
        -not [string]::IsNullOrWhiteSpace([Environment]::GetEnvironmentVariable($GraphClientSecretEnvVar))) {
        return $true
    }
    return $false
}

function Get-GraphClientSecretSecureString {
    if ($GraphClientSecret -and $GraphClientSecret.Length -gt 0) {
        return $GraphClientSecret
    }
    $envName = $GraphClientSecretEnvVar
    if ([string]::IsNullOrWhiteSpace($envName)) { return $null }
    $plain = [Environment]::GetEnvironmentVariable($envName)
    if ([string]::IsNullOrWhiteSpace($plain)) { return $null }
    return (ConvertTo-SecureString -String $plain -AsPlainText -Force)
}

function Get-GraphCertificatePasswordSecureString {
    if ($GraphCertificatePassword -and $GraphCertificatePassword.Length -gt 0) {
        return $GraphCertificatePassword
    }
    foreach ($envName in @(
            [Environment]::GetEnvironmentVariable('COPILOT_AUDIT_GRAPH_CERT_PASSWORD_ENV'),
            'COPILOT_GRAPH_CERT_PASSWORD',
            'COPILOT_AUDIT_GRAPH_CERT_PASSWORD'
        )) {
        if ([string]::IsNullOrWhiteSpace($envName)) { continue }
        $plain = [Environment]::GetEnvironmentVariable($envName)
        if (-not [string]::IsNullOrWhiteSpace($plain)) {
            return (ConvertTo-SecureString -String $plain -AsPlainText -Force)
        }
    }
    return $null
}

function Connect-AuditMicrosoftGraph {
    param(
        [Parameter(Mandatory)]$TenantTarget
    )

    $Script:GraphAuthMode = 'NotStarted'
    $Script:RunCoverage.GraphAuthMode = 'NotStarted'
    $Script:RunCoverage.GraphAppId = ''

    $ctx = Get-MgContext
    if ($ctx -and -not [string]::Equals([string]$ctx.TenantId, $TenantTarget.TenantId, [System.StringComparison]::OrdinalIgnoreCase)) {
        Write-AuditLog "Existing Graph session is tenant '$($ctx.TenantId)'; target is '$($TenantTarget.TenantId)'. Disconnecting..." Warn
        try { Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null } catch { }
        $ctx = $null
    }

    $wantAppOnly = -not [string]::IsNullOrWhiteSpace($GraphAppId)
    if ($wantAppOnly -and -not (Test-GraphAppOnlyConfigured)) {
        throw 'GraphAppId was supplied but no certificate or client secret was provided. Use -GraphCertificateThumbprint / -GraphCertificatePath or -GraphClientSecret / -GraphClientSecretEnvVar.'
    }

    if ($wantAppOnly) {
        # Prefer certificate when both cert and secret are available.
        $hasCert = (-not [string]::IsNullOrWhiteSpace($GraphCertificateThumbprint)) -or (-not [string]::IsNullOrWhiteSpace($GraphCertificatePath))
        $secretSecure = Get-GraphClientSecretSecureString

        $existingAuthType = if ($ctx) { [string](Get-GraphObjectProperty -Object $ctx -PropertyName 'AuthType') } else { '' }
        if ($ctx -and $existingAuthType -ne 'AppOnly') {
            # Existing delegated session — replace with app-only for this audit.
            try { Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null } catch { }
            $ctx = $null
        }

        if (-not $ctx) {
            Write-AuditLog "Connecting to Microsoft Graph app-only (TenantId=$($TenantTarget.TenantId); AppId=$GraphAppId)..."
            if ($hasCert) {
                if ($GraphCertificateThumbprint) {
                    Connect-MgGraph -TenantId $TenantTarget.TenantId -ClientId $GraphAppId `
                        -CertificateThumbprint $GraphCertificateThumbprint -NoWelcome -ErrorAction Stop
                    Write-AuditLog '  Graph auth: AppOnly (certificate thumbprint).'
                }
                else {
                    $certPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($GraphCertificatePath)
                    if (-not (Test-Path -LiteralPath $certPath)) {
                        throw "Graph certificate file not found: $certPath"
                    }
                    $certPassword = Get-GraphCertificatePasswordSecureString
                    if ($certPassword) {
                        $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($certPassword)
                        try {
                            $plainCertPassword = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
                            $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new(
                                $certPath,
                                $plainCertPassword,
                                [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable
                            )
                        }
                        finally {
                            [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
                        }
                    }
                    else {
                        $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($certPath)
                    }
                    Connect-MgGraph -TenantId $TenantTarget.TenantId -ClientId $GraphAppId `
                        -Certificate $cert -NoWelcome -ErrorAction Stop
                    Write-AuditLog '  Graph auth: AppOnly (certificate file).'
                }
            }
            elseif ($secretSecure) {
                $clientSecretCredential = [pscredential]::new($GraphAppId, $secretSecure)
                Connect-MgGraph -TenantId $TenantTarget.TenantId -ClientSecretCredential $clientSecretCredential `
                    -NoWelcome -ErrorAction Stop
                Write-AuditLog '  Graph auth: AppOnly (client secret).'
            }
            else {
                throw 'App-only Graph credentials resolved empty after validation.'
            }
        }
        else {
            Write-AuditLog "  Existing Microsoft Graph app-only session matches target tenant $($TenantTarget.TenantId)."
        }

        $Script:GraphAuthMode = 'AppOnly'
        $Script:RunCoverage.GraphAuthMode = 'AppOnly'
        $Script:RunCoverage.GraphAppId = $GraphAppId
        return
    }

    $graphScopes = @(
        'User.Read.All',
        'Directory.Read.All',
        'Group.Read.All',
        'RoleManagement.Read.Directory',
        'Sites.Read.All',
        'Files.Read.All',
        'Team.ReadBasic.All',
        'TeamMember.Read.All'
    )

    $existingAuthType = if ($ctx) { [string](Get-GraphObjectProperty -Object $ctx -PropertyName 'AuthType') } else { '' }
    if ($ctx -and $existingAuthType -eq 'AppOnly') {
        Write-AuditLog 'Existing Graph session is app-only but this run has no GraphAppId; disconnecting for delegated auth...' Warn
        try { Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null } catch { }
        $ctx = $null
    }

    if (-not $ctx) {
        Write-AuditLog "Connecting to Microsoft Graph delegated (TenantId=$($TenantTarget.TenantId))..."
        Connect-MgGraph -TenantId $TenantTarget.TenantId -Scopes $graphScopes -NoWelcome
    }
    else {
        Write-AuditLog "  Existing Microsoft Graph session matches target tenant $($TenantTarget.TenantId)."
    }

    $Script:GraphAuthMode = 'Delegated'
    $Script:RunCoverage.GraphAuthMode = 'Delegated'
}

function Connect-ExposureServices {
    param(
        [Parameter(Mandatory)]$TenantTarget
    )

    $Script:AuditTenant = $TenantTarget
    $sharePointTenantPrefix = $TenantTarget.SharePointPrefix

    $null = Ensure-ModulePresent -Name 'ExchangeOnlineManagement'

    # Graph must load before ExchangeOnlineManagement assemblies occupy the AppDomain.
    # Clean -NoProfile child process is used to avoid version conflicts / 4096-function exhaustion.
    if (-not (Get-Module -ListAvailable -Name 'Microsoft.Graph.Authentication')) {
        Write-AuditLog 'Installing Microsoft.Graph bundle (aligned submodules)...' Warn
        Install-Module -Name 'Microsoft.Graph' -Scope CurrentUser -Force -AllowClobber -Repository PSGallery
    }

    Write-AuditLog 'Importing aligned Microsoft Graph modules...'
    Import-AlignedGraphModules

    if ($RegisterGraphApp) {
        if (-not [string]::IsNullOrWhiteSpace($GraphAppId) -and (Test-GraphAppOnlyConfigured)) {
            Write-AuditLog 'RegisterGraphApp skipped: GraphAppId and credentials are already configured.' Warn
        }
        else {
            Connect-DelegatedGraphForAppRegistration -TenantTarget $TenantTarget
            Assert-GraphTenantMatchesTarget -TenantTarget $TenantTarget
            $null = Register-CopilotAuditGraphApp -TenantTarget $TenantTarget `
                -DisplayName $GraphAppDisplayName -SecretValidMonths $GraphAppSecretValidMonths
            try { Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null } catch { }
            if ($RegisterGraphAppOnly) {
                $Script:ExitAfterGraphRegistration = $true
                Write-AuditLog 'RegisterGraphAppOnly: exiting without running the audit.'
                return
            }
            Write-AuditLog 'Continuing audit with newly registered app-only Graph credentials...'
        }
    }

    Connect-AuditMicrosoftGraph -TenantTarget $TenantTarget

    Assert-GraphTenantMatchesTarget -TenantTarget $TenantTarget
    $Script:RunCoverage.GraphOk = $true
    $Script:RunCoverage.UnattendedAppOnly = ($Script:GraphAuthMode -eq 'AppOnly')
    if ($Script:RunCoverage.UnattendedAppOnly) {
        Write-AuditLog 'Unattended app-only mode: Graph uses application permissions; interactive EXO/SPO/PnP logins are not used.'
    }

    if (-not $TenantTarget.OrganizationDomain) {
        $resolvedDomain = Resolve-OrganizationDomainFromGraph -TenantTarget $TenantTarget
        $TenantTarget.OrganizationDomain = $resolvedDomain
        $Script:AuditTenant = $TenantTarget
        Write-AuditLog "Resolved Exchange organization domain from Graph: $resolvedDomain"
    }

    if ($SkipExchange -or $Script:GraphAuthMode -eq 'AppOnly') {
        # Still attempt EXO app-only (cert) inside Connect-ExchangeOnlineResilient; never interactive.
        $null = Ensure-ModulePresent -Name 'ExchangeOnlineManagement' -AllowInstallFailure
        try { Import-Module ExchangeOnlineManagement -ErrorAction Stop } catch { }
    }
    else {
        Import-Module ExchangeOnlineManagement -ErrorAction Stop
    }
    Connect-ExchangeOnlineResilient -TenantTarget $TenantTarget

    if ($Script:ExchangeAvailable) {
        Assert-ExchangeTenantMatchesTarget -TenantTarget $TenantTarget
    }
    $Script:RunCoverage.ExchangeOk = $Script:ExchangeAvailable

    $Script:SpoAvailable = $false
    if ($Script:GraphAuthMode -eq 'AppOnly') {
        Write-AuditLog 'Skipping interactive SharePoint Online Management Shell (unattended app-only). Using Graph Sites.Read.All inventory / content APIs.'
        $Script:RunCoverage.SpoSkippedReason = 'AppOnlyUnattended'
        $Script:RunCoverage.SharePointRoleMode = 'GraphFallbackNoRoles'
    }
    elseif (-not $SkipSharePointSites) {
        try {
            if (-not (Ensure-ModulePresent -Name 'Microsoft.Online.SharePoint.PowerShell' -AllowInstallFailure)) {
                throw 'Microsoft.Online.SharePoint.PowerShell is not installed and could not be installed in this session.'
            }

            # Assembly conflicts with PnP / stale Client.Tenant DLLs are common — never abort the whole audit.
            Import-Module Microsoft.Online.SharePoint.PowerShell -ErrorAction Stop
            $adminUrl = "https://$sharePointTenantPrefix-admin.sharepoint.com"
            Write-AuditLog "Connecting to SharePoint admin: $adminUrl"
            Connect-SPOService -Url $adminUrl -ErrorAction Stop

            $expectedHost = "$sharePointTenantPrefix-admin.sharepoint.com"
            $spoOk = $true
            try {
                if (Get-Command Get-SPOTenant -ErrorAction SilentlyContinue) {
                    $spoTenant = Get-SPOTenant -ErrorAction Stop
                    $spoRoot = [string](Get-GraphObjectProperty -Object $spoTenant -PropertyName 'RootSiteUrl')
                    if (-not $spoRoot) {
                        $spoRoot = [string](Get-GraphObjectProperty -Object $spoTenant -PropertyName 'SharePointSiteUrl')
                    }
                    if ($spoRoot -and ($spoRoot -notmatch [regex]::Escape($sharePointTenantPrefix))) {
                        $spoOk = $false
                        Write-AuditLog "SharePoint tenant root '$spoRoot' does not match prefix '$sharePointTenantPrefix'." Warn
                    }
                }
            }
            catch {
                # Host URL pin is enough when Get-SPOTenant is unavailable/denied.
            }

            if ($spoOk) {
                $Script:SpoAvailable = $true
                Write-AuditLog "  SharePoint Online connected ($expectedHost)."
            }
            else {
                try { Disconnect-SPOService -ErrorAction SilentlyContinue } catch { }
                $Script:SpoAvailable = $false
                Write-AuditLog 'SharePoint session discarded due to tenant mismatch; continuing without SPO site scan.' Warn
            }
        }
        catch {
            $Script:SpoAvailable = $false
            Write-AuditLog "SharePoint Online Management Shell unavailable: $($_.Exception.Message)" Warn
            Write-AuditLog 'Continuing with Graph-only site inventory (Everyone principal scan via Get-SPOUser will be skipped).' Warn
            Write-AuditLog 'To enable SPO: in a normal (profile) PowerShell window run Install-Module Microsoft.Online.SharePoint.PowerShell -Scope CurrentUser -Force, then re-run this script.' Info
        }
    }
    elseif ($SkipSharePointSites) {
        $Script:RunCoverage.SpoSkippedReason = 'SkipSharePointSites'
    }

    $Script:RunCoverage.SpoOk = $Script:SpoAvailable
    if ($Script:SpoAvailable) {
        Initialize-OptionalPnPConnection -TenantTarget $TenantTarget
    }
    elseif ($SkipSharePointSites) {
        $Script:RunCoverage.SharePointRoleMode = 'Skipped'
    }
    elseif ($Script:GraphAuthMode -eq 'AppOnly') {
        $Script:RunCoverage.SharePointRoleMode = 'GraphFallbackNoRoles'
    }
    else {
        $Script:RunCoverage.SharePointRoleMode = 'GraphFallbackNoRoles'
    }
    Write-AuditLog "Tenant pin confirmed: Graph=$($TenantTarget.TenantId) ($($Script:GraphAuthMode)); Exchange=$(if ($Script:ExchangeAvailable) { 'matched' } else { 'skipped/unavailable' }); SPO=$(if ($Script:SpoAvailable) { 'matched' } else { 'skipped/unavailable' })"
}
#endregion

#region Broad share grant parsing
function Get-GraphPermissionBroadSharingGrants {
    param($Permission)

    $grants = [System.Collections.Generic.List[object]]::new()
    if ($null -eq $Permission) { return $grants }

    $link = Get-GraphObjectProperty -Object $Permission -PropertyName 'link'
    $linkScope = Get-GraphObjectProperty -Object $link -PropertyName 'scope'
    if ($linkScope -and ($linkScope -in @('organization', 'anonymous'))) {
        $weight = if ($linkScope -eq 'anonymous') { 40 } else { 25 }
        $grants.Add([PSCustomObject]@{
            GrantType = 'SharingLink'
            Grantee   = $linkScope
            Detail    = "Sharing link scope: $linkScope"
            Weight    = $weight
            PrincipalId = "broad:link:$linkScope"
            PrincipalType = 'BroadPrincipal'
        })
    }

    $identitySets = [System.Collections.Generic.List[object]]::new()
    foreach ($propName in @('grantedToIdentitiesV2', 'grantedToIdentities', 'grantedToV2', 'grantedTo')) {
        $collection = Get-GraphObjectProperty -Object $Permission -PropertyName $propName
        if ($collection) {
            foreach ($entry in @($collection)) { $identitySets.Add($entry) }
        }
    }

    foreach ($identitySet in $identitySets) {
        foreach ($entityType in @('siteGroup', 'group', 'user')) {
            $entity = Get-GraphObjectProperty -Object $identitySet -PropertyName $entityType
            if (-not $entity) { continue }

            $displayName = [string](Get-GraphObjectProperty -Object $entity -PropertyName 'displayName')
            $loginName = [string](Get-GraphObjectProperty -Object $entity -PropertyName 'loginName')
            $entityId = [string](Get-GraphObjectProperty -Object $entity -PropertyName 'id')

            if ((Test-IsBroadGroupName -Name $displayName) -or (Test-IsBroadShareLoginName -LoginName $loginName)) {
                $label = if ($displayName) { $displayName } elseif ($loginName) { $loginName } else { 'broad-principal' }
                $principalId = if ($entityId) { $entityId } else { "broad:$label" }
                $grants.Add([PSCustomObject]@{
                    GrantType = 'BroadPrincipal'
                    Grantee   = $label
                    Detail    = "Broad grant: $label"
                    Weight    = 40
                    PrincipalId = $principalId
                    PrincipalType = if ($entityType -eq 'user') { 'User' } elseif ($entityType -eq 'group') { 'Group' } else { 'BroadPrincipal' }
                })
            }
            else {
                $label = if ($displayName) { $displayName } elseif ($loginName) { $loginName } else { '' }
                $email = [string](Get-GraphObjectProperty -Object $entity -PropertyName 'email')
                if (-not $email) { $email = [string](Get-GraphObjectProperty -Object $entity -PropertyName 'userPrincipalName') }
                $principalId = if ($entityId) { $entityId } elseif ($email) { $email } elseif ($label) { "direct:${entityType}:$label" } else { '' }
                if (-not $principalId) { continue }
                $grants.Add([PSCustomObject]@{
                    GrantType     = 'DirectSharePrincipal'
                    Grantee       = $label
                    Email         = $email
                    Detail        = "Named $entityType grant: $(if ($email) { $email } else { $label })"
                    Weight        = 0
                    PrincipalId   = $principalId
                    PrincipalType = if ($entityType -eq 'user') { 'User' } else { 'Group' }
                })
            }
        }
    }

    return $grants
}
#endregion

#region Collectors
function Collect-PrivilegedRoles {
    Write-AuditLog "`nScanning Entra privileged roles..."
    try {
        $roles = @(Get-MgDirectoryRole -All -ErrorAction Stop)
    }
    catch {
        Write-AuditLog "Privileged roles scan failed: $($_.Exception.Message)" Warn
        return
    }

    $targetRoles = @($roles | Where-Object { $Script:PrivilegedEntraRoles -contains $_.DisplayName })
    $activity = 'Scanning Entra privileged roles'
    $i = 0
    try {
        foreach ($role in $targetRoles) {
            $i++
            Write-AuditProgress -Activity $activity -Current $i -Total $targetRoles.Count -CurrentOperation ([string]$role.DisplayName)

            $roleId = "role:$($role.Id)"
            Add-ExposureNode -Id $roleId -Type Role -DisplayName $role.DisplayName -Score $Script:PrivilegedRoleWeight -RiskFlags 'PrivilegedRole'

            try {
                $members = @(Get-MgDirectoryRoleMember -DirectoryRoleId $role.Id -All -ErrorAction Stop)
            }
            catch {
                Write-AuditLog "  Could not list members for $($role.DisplayName): $($_.Exception.Message)" Warn
                continue
            }

            foreach ($member in $members) {
                $memberId = $member.Id
                if (-not $memberId) { continue }
                $display = [string](Get-GraphObjectProperty -Object $member -PropertyName 'displayName')
                $upn = [string](Get-GraphObjectProperty -Object $member -PropertyName 'userPrincipalName')
                if (-not $display -and $member.AdditionalProperties) {
                    $display = [string](Get-GraphObjectProperty -Object $member.AdditionalProperties -PropertyName 'displayName')
                }
                if (-not $upn -and $member.AdditionalProperties) {
                    $upn = [string](Get-GraphObjectProperty -Object $member.AdditionalProperties -PropertyName 'userPrincipalName')
                }

                Add-ExposureNode -Id $memberId -Type User -DisplayName $display -UserPrincipalName $upn
                Add-ExposureEdge -SourceId $memberId -TargetId $roleId -EdgeType PrivilegedRole `
                    -Detail $role.DisplayName -Weight $Script:PrivilegedRoleWeight
            }
        }
    }
    finally {
        Complete-AuditProgress -Activity $activity
    }

    Write-AuditLog "  Privileged roles scanned: $($targetRoles.Count)."
}

function Collect-GroupsAndTeams {
    Write-AuditLog "`nScanning M365 Groups / Teams..."
    try {
        $groups = @(Get-MgGroup -All -Filter "groupTypes/any(c:c eq 'Unified')" -Property 'id,displayName,visibility,mail' -ErrorAction Stop)
    }
    catch {
        Write-AuditLog "Groups scan failed: $($_.Exception.Message)" Warn
        return
    }

    $activity = 'Scanning M365 Groups / Teams'
    $i = 0
    try {
        foreach ($group in $groups) {
            $i++
            Write-AuditProgress -Activity $activity -Current $i -Total $groups.Count -CurrentOperation ([string]$group.DisplayName)

            $score = 0
            $flags = [System.Collections.Generic.List[string]]::new()

            try {
                $members = @(Get-MgGroupMember -GroupId $group.Id -All -ErrorAction Stop)
            }
            catch {
                Write-AuditLog "  Members failed for $($group.DisplayName): $($_.Exception.Message)" Warn
                $members = @()
            }

            try {
                $owners = @(Get-MgGroupOwner -GroupId $group.Id -All -ErrorAction SilentlyContinue)
            }
            catch {
                $owners = @()
            }

            $guestCount = 0
            foreach ($member in $members) {
                $userType = $null
                if ($member.AdditionalProperties) {
                    try {
                        $userType = [string]$member.AdditionalProperties['userType']
                    }
                    catch {
                        $userType = [string](Get-GraphObjectProperty -Object $member.AdditionalProperties -PropertyName 'userType')
                    }
                }
                if ($userType -eq 'Guest') {
                    $guestCount++
                }
            }

            if ($group.Visibility -eq 'Public') {
                $score += 15
                $flags.Add('Public')
            }

            $memberCount = @($members).Count
            if ($memberCount -gt 100) {
                $score += 20
                $flags.Add('LargeMembership')
            }
            if ($memberCount -gt 500) {
                $score += 30
                $flags.Add('MassExposure')
            }
            if (@($owners).Count -eq 0) {
                $score += 25
                $flags.Add('NoOwner')
            }
            if ($guestCount -gt 0) {
                $guestScore = [Math]::Min(20, $guestCount * 2)
                $score += $guestScore
                $flags.Add("Guests:$guestCount")
            }

            $flagText = ($flags | Select-Object -Unique) -join ','
            $memberWeight = [Math]::Max(5, [Math]::Min(40, [math]::Round($score / 2.0)))

            Add-ExposureNode -Id $group.Id -Type Group -DisplayName $group.DisplayName -Score $score -RiskFlags $flagText -Extra "visibility=$($group.Visibility)"

            foreach ($member in $members) {
                if (-not $member.Id) { continue }
                $upn = Get-GraphObjectProperty -Object $member.AdditionalProperties -PropertyName 'userPrincipalName'
                if (-not $upn) { $upn = Get-GraphObjectProperty -Object $member -PropertyName 'userPrincipalName' }
                $display = Get-GraphObjectProperty -Object $member.AdditionalProperties -PropertyName 'displayName'
                if (-not $display) { $display = Get-GraphObjectProperty -Object $member -PropertyName 'displayName' }

                Add-ExposureNode -Id $member.Id -Type User -DisplayName ([string]$display) -UserPrincipalName ([string]$upn)
                Add-ExposureEdge -SourceId $member.Id -TargetId $group.Id -EdgeType MemberOf `
                    -Detail "Member of $($group.DisplayName)" -Weight $memberWeight
            }
        }
    }
    finally {
        Complete-AuditProgress -Activity $activity
    }

    Write-AuditLog "  Unified groups scanned: $($groups.Count)."
}

function Collect-TeamsAccess {
    Write-AuditLog "`nScanning Teams-native membership..."
    $Script:RunCoverage.TeamsOk = $false
    $Script:RunCoverage.TeamsCount = 0
    $Script:RunCoverage.TeamsChannelsOk = $false
    $Script:RunCoverage.TeamsChannelsSkipped = $false

    try {
        $teams = @(Get-MgTeam -All -ErrorAction Stop)
        $Script:RunCoverage.TeamsOk = $true
        $Script:RunCoverage.TeamsCount = $teams.Count
    }
    catch {
        Write-AuditLog "Teams scan failed: $($_.Exception.Message)" Warn
        return
    }

    $activity = 'Scanning Teams-native membership'
    $channelAccessAvailable = $true
    $i = 0
    try {
        foreach ($team in $teams) {
            $i++
            Write-AuditProgress -Activity $activity -Current $i -Total $teams.Count -CurrentOperation ([string]$team.DisplayName)

            try {
                $members = @(Get-MgTeamMember -TeamId $team.Id -All -ErrorAction Stop)
            }
            catch {
                Write-AuditLog "  Team members failed for $($team.DisplayName): $($_.Exception.Message)" Warn
                $members = @()
            }

            try {
                $owners = @(Get-MgGroupOwner -GroupId $team.Id -All -ErrorAction Stop)
            }
            catch {
                $owners = @()
            }

            $memberIds = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
            $ownerIds = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
            $guestCount = 0

            foreach ($member in $members) {
                $memberId = [string](Get-GraphObjectProperty -Object $member -PropertyName 'userId')
                if (-not $memberId) { continue }
                $additional = Get-GraphObjectProperty -Object $member -PropertyName 'additionalProperties'
                $display = [string](Get-GraphObjectProperty -Object $additional -PropertyName 'displayName')
                $upn = [string](Get-GraphObjectProperty -Object $additional -PropertyName 'userPrincipalName')
                if (-not $upn) { $upn = [string](Get-GraphObjectProperty -Object $additional -PropertyName 'email') }
                $userType = [string](Get-GraphObjectProperty -Object $additional -PropertyName 'userType')
                $roles = @(Get-GraphObjectProperty -Object $member -PropertyName 'roles')

                [void]$memberIds.Add($memberId)
                if ($userType -eq 'Guest') { $guestCount++ }
                Add-ExposureNode -Id $memberId -Type User -DisplayName $display -UserPrincipalName $upn
                if ($roles -contains 'owner') {
                    [void]$ownerIds.Add($memberId)
                    Add-ExposureEdge -SourceId $memberId -TargetId $team.Id -EdgeType TeamOwner `
                        -Detail "Owner of $($team.DisplayName)" -Weight 30
                }
                else {
                    Add-ExposureEdge -SourceId $memberId -TargetId $team.Id -EdgeType TeamMember `
                        -Detail "Member of $($team.DisplayName)" -Weight 8
                }
            }

            foreach ($owner in $owners) {
                $ownerId = [string](Get-GraphObjectProperty -Object $owner -PropertyName 'id')
                if (-not $ownerId -or -not $ownerIds.Add($ownerId)) { continue }
                $additional = Get-GraphObjectProperty -Object $owner -PropertyName 'additionalProperties'
                $display = [string](Get-GraphObjectProperty -Object $owner -PropertyName 'displayName')
                $upn = [string](Get-GraphObjectProperty -Object $owner -PropertyName 'userPrincipalName')
                if (-not $display) { $display = [string](Get-GraphObjectProperty -Object $additional -PropertyName 'displayName') }
                if (-not $upn) { $upn = [string](Get-GraphObjectProperty -Object $additional -PropertyName 'userPrincipalName') }
                Add-ExposureNode -Id $ownerId -Type User -DisplayName $display -UserPrincipalName $upn
                Add-ExposureEdge -SourceId $ownerId -TargetId $team.Id -EdgeType TeamOwner `
                    -Detail "Owner of $($team.DisplayName) (group owner)" -Weight 30
            }

            $memberCount = $memberIds.Count
            $ownerCount = $ownerIds.Count
            $guestRatio = if ($memberCount -gt 0) { [math]::Round($guestCount / $memberCount, 3) } else { 0 }
            $flags = [System.Collections.Generic.List[string]]::new()
            $score = 0
            if ($ownerCount -eq 0) { $score += 25; $flags.Add('TeamNoOwner') }
            if ($memberCount -ge 500) { $score += 30; $flags.Add('TeamMassExposure') }
            if ($guestCount -ge 10 -or ($guestCount -ge 5 -and $guestRatio -ge 0.2)) {
                $score += 20
                $flags.Add('TeamGuestHeavy')
            }

            $siteId = ''
            $siteUrl = ''
            try {
                $site = Get-MgGroupSite -GroupId $team.Id -ErrorAction Stop
                if ($site) {
                    $siteId = [string]$site.Id
                    $siteUrl = [string]$site.WebUrl
                }
            }
            catch {
                # A Team may not have a provisioned SharePoint site, or Sites.Read.All may be unavailable.
            }

            $extra = "IsTeam=true;TeamId=$($team.Id);MemberCount=$memberCount;OwnerCount=$ownerCount;GuestCount=$guestCount;GuestRatio=$guestRatio"
            if ($siteId) { $extra += ";SiteId=$siteId" }
            if ($siteUrl) { $extra += ";SiteUrl=$siteUrl" }
            Add-ExposureNode -Id $team.Id -Type Group -DisplayName $team.DisplayName -Score $score `
                -RiskFlags (($flags | Select-Object -Unique) -join ',') -Extra $extra

            if ($channelAccessAvailable) {
                try {
                    $channelResponse = Invoke-MgGraphRequest -Method GET `
                        -Uri "https://graph.microsoft.com/v1.0/teams/$($team.Id)/channels?`$select=id,displayName,membershipType" `
                        -ErrorAction Stop
                    $channels = @($channelResponse.value | Where-Object { $_.membershipType -in @('private', 'shared') })
                    foreach ($channel in $channels) {
                        $channelMembersResponse = Invoke-MgGraphRequest -Method GET `
                            -Uri "https://graph.microsoft.com/v1.0/teams/$($team.Id)/channels/$($channel.id)/members" `
                            -ErrorAction Stop
                        foreach ($channelMember in @($channelMembersResponse.value)) {
                            $channelMemberId = [string]$channelMember.userId
                            if (-not $channelMemberId) { continue }
                            $channelRoles = @($channelMember.roles)
                            $edgeType = if ($channelRoles -contains 'owner') { 'TeamOwner' } else { 'TeamMember' }
                            $weight = if ($edgeType -eq 'TeamOwner') { 30 } else { 8 }
                            Add-ExposureNode -Id $channelMemberId -Type User -DisplayName ([string]$channelMember.displayName) `
                                -UserPrincipalName ([string]$channelMember.email)
                            Add-ExposureEdge -SourceId $channelMemberId -TargetId $team.Id -EdgeType $edgeType `
                                -Detail "$($channel.membershipType) channel: $($channel.displayName)" -Weight $weight
                        }
                    }
                    $Script:RunCoverage.TeamsChannelsOk = $true
                }
                catch {
                    $channelAccessAvailable = $false
                    $Script:RunCoverage.TeamsChannelsSkipped = $true
                    Write-AuditLog '  Private/shared channel membership skipped. Consent Channel.ReadBasic.All to enable it.' Warn
                }
            }
        }
    }
    finally {
        Complete-AuditProgress -Activity $activity
    }

    Write-AuditLog "  Teams scanned: $($teams.Count)."
}

function Collect-ExchangeDelegations {
    if ($SkipExchange) {
        Write-AuditLog "`nSkipping Exchange scan (-SkipExchange)." Warn
        return
    }

    if (-not (Test-ExchangeOnlineConnected)) {
        $Script:ExchangeAvailable = $false
        if ($Script:GraphAuthMode -eq 'AppOnly') {
            Write-AuditLog "`nSkipping Exchange scan (EXO app-only session unavailable). Check certificate, Exchange.ManageAsApp consent, Exchange Administrator on the app SP, and *.onmicrosoft.com Organization domain." Warn
        }
        else {
            Write-AuditLog "`nSkipping Exchange scan (no active Exchange Online session). Use -ExchangeDeviceLogin or connect from an external PowerShell window." Warn
        }
        return
    }

    $Script:ExchangeAvailable = $true
    Write-AuditLog "`nScanning Exchange mailbox delegations..."
    try {
        $mailboxes = @(Get-EXOMailbox -ResultSize Unlimited -Properties PrimarySmtpAddress, DisplayName, ExternalDirectoryObjectId, RecipientTypeDetails -ErrorAction Stop)
    }
    catch {
        $Script:ExchangeAvailable = $false
        Write-AuditLog "EXO mailbox list failed: $($_.Exception.Message)" Warn
        Write-AuditLog 'Skipping Exchange scan (REST session not usable). Re-run with -ExchangeDeviceLogin or -SkipExchange.' Warn
        return
    }

    $activity = 'Scanning Exchange mailbox delegations'
    $processed = 0
    try {
        foreach ($mb in $mailboxes) {
            $processed++
            $mbKey = if ($mb.PrimarySmtpAddress) { [string]$mb.PrimarySmtpAddress } else { [string]$mb.UserPrincipalName }
            Write-AuditProgress -Activity $activity -Current $processed -Total $mailboxes.Count -CurrentOperation $(if ($mbKey) { $mbKey } else { 'mailbox' })
            if (-not $mbKey) { continue }

            $mailboxType = switch ([string]$mb.RecipientTypeDetails) {
                'UserMailbox'   { 'UserMailbox' }
                'SharedMailbox' { 'SharedMailbox' }
                'RoomMailbox'   { 'Room' }
                default         { 'Other' }
            }
            $mailboxScore = 0
            $flags = [System.Collections.Generic.List[string]]::new()

            try {
                $perms = @(Get-EXOMailboxPermission -Identity $mbKey -ErrorAction Stop | Where-Object {
                        -not $_.IsInherited -and
                        $_.User -notlike 'NT AUTHORITY\SELF' -and
                        ($_.AccessRights -contains 'FullAccess')
                    })
            }
            catch {
                try {
                    $perms = @(Get-MailboxPermission -Identity $mbKey -ErrorAction Stop | Where-Object {
                            -not $_.IsInherited -and
                            $_.User -notlike 'NT AUTHORITY\SELF' -and
                            ($_.AccessRights -contains 'FullAccess')
                        })
                }
                catch {
                    continue
                }
            }

            foreach ($perm in $perms) {
                $delegate = [string]$perm.User
                if ([string]::IsNullOrWhiteSpace($delegate)) { continue }

                $sourceId = $delegate
                try {
                    $resolved = Get-MgUser -UserId $delegate -Property 'id,displayName,userPrincipalName,mail' -ErrorAction SilentlyContinue
                    if ($resolved) {
                        $sourceId = $resolved.Id
                        Add-ExposureNode -Id $sourceId -Type User -DisplayName $resolved.DisplayName -UserPrincipalName $resolved.UserPrincipalName -Mail $resolved.Mail
                    }
                    else {
                        Add-ExposureNode -Id $sourceId -Type User -DisplayName $delegate -UserPrincipalName $(if ($delegate -match '@') { $delegate } else { '' })
                    }
                }
                catch {
                    Add-ExposureNode -Id $sourceId -Type User -DisplayName $delegate -UserPrincipalName $(if ($delegate -match '@') { $delegate } else { '' })
                }

                $mailboxScore = [Math]::Min($Script:MailboxScoreCap, $mailboxScore + $Script:MailboxDelegateWeight)
                $flags.Add('FullAccess')
                Add-ExposureEdge -SourceId $sourceId -TargetId "mailbox:$mbKey" -EdgeType MailboxDelegate `
                    -Detail "FullAccess on $mbKey" -Weight $Script:MailboxDelegateWeight
            }

            try {
                $sendAs = @(Get-RecipientPermission -Identity $mbKey -ErrorAction SilentlyContinue | Where-Object {
                        $_.AccessRights -contains 'SendAs' -and
                        $_.Trustee -notlike 'NT AUTHORITY\SELF'
                    })
            }
            catch {
                $sendAs = @()
            }

            foreach ($sa in $sendAs) {
                $trustee = [string]$sa.Trustee
                if ([string]::IsNullOrWhiteSpace($trustee)) { continue }
                $sourceId = $trustee
                try {
                    $resolved = Get-MgUser -UserId $trustee -Property 'id,displayName,userPrincipalName,mail' -ErrorAction SilentlyContinue
                    if ($resolved) {
                        $sourceId = $resolved.Id
                        Add-ExposureNode -Id $sourceId -Type User -DisplayName $resolved.DisplayName -UserPrincipalName $resolved.UserPrincipalName -Mail $resolved.Mail
                    }
                    else {
                        Add-ExposureNode -Id $sourceId -Type User -DisplayName $trustee -UserPrincipalName $(if ($trustee -match '@') { $trustee } else { '' })
                    }
                }
                catch {
                    Add-ExposureNode -Id $sourceId -Type User -DisplayName $trustee -UserPrincipalName $(if ($trustee -match '@') { $trustee } else { '' })
                }

                $mailboxScore = [Math]::Min($Script:MailboxScoreCap, $mailboxScore + 15)
                $flags.Add('SendAs')
                Add-ExposureEdge -SourceId $sourceId -TargetId "mailbox:$mbKey" -EdgeType SendAs `
                    -Detail "SendAs on $mbKey" -Weight 15
            }

            if ($mailboxScore -gt 0) {
                Add-ExposureNode -Id "mailbox:$mbKey" -Type Mailbox -DisplayName $mbKey -Score $mailboxScore `
                    -RiskFlags (($flags | Select-Object -Unique) -join ',') -Extra "MailboxType=$mailboxType"
            }
        }
    }
    finally {
        Complete-AuditProgress -Activity $activity
    }

    Write-AuditLog "  Mailboxes scanned: $($mailboxes.Count)."
}

function Collect-SharePointSitesFromGraph {
    Write-AuditLog "`nScanning SharePoint sites via Microsoft Graph (fallback)..."
    $Script:RunCoverage.SharePointInventoryMode = 'GraphFallback'
    $sites = [System.Collections.Generic.List[object]]::new()
    $activity = 'Scanning SharePoint sites (Graph)'

    try {
        $groups = @(Get-MgGroup -All -Filter "groupTypes/any(c:c eq 'Unified')" -Property 'id,displayName' -ErrorAction Stop)
        $gi = 0
        try {
            foreach ($group in $groups) {
                $gi++
                Write-AuditProgress -Activity $activity -Status "Resolving group sites $gi / $($groups.Count)" `
                    -Current $gi -Total $groups.Count -CurrentOperation ([string]$group.DisplayName)
                try {
                    $site = Get-MgGroupSite -GroupId $group.Id -ErrorAction Stop
                    if ($site) { $sites.Add($site) }
                }
                catch { }
            }
        }
        finally {
            Complete-AuditProgress -Activity $activity
        }
    }
    catch {
        Write-AuditLog "  Graph group sites failed: $($_.Exception.Message)" Warn
    }

    try {
        $search = @(Get-MgSite -Search '*' -ErrorAction SilentlyContinue)
        foreach ($site in $search) {
            if ($site -and $site.Id) { $sites.Add($site) }
        }
    }
    catch {
        Write-AuditLog "  Graph site search failed: $($_.Exception.Message)" Warn
    }

    $seen = @{}
    $unique = [System.Collections.Generic.List[object]]::new()
    foreach ($site in $sites) {
        $siteId = Get-NormalizedGraphSiteId -SiteOrId $site
        $webUrl = [string](Get-GraphObjectProperty -Object $site -PropertyName 'webUrl')
        $key = if ($siteId) { $siteId } elseif (-not [string]::IsNullOrWhiteSpace($webUrl)) { $webUrl.Trim() } else { '' }
        if (-not $key -or $seen.ContainsKey($key)) { continue }
        $seen[$key] = $true
        $unique.Add([PSCustomObject]@{
                Site     = $site
                SiteId   = $siteId
                WebUrl   = $webUrl
                Name     = [string](Get-GraphObjectProperty -Object $site -PropertyName 'displayName')
            })
    }
    $Script:RunCoverage.SitesTotal = $unique.Count

    $i = 0
    try {
        foreach ($entry in $unique) {
            $i++
            $webUrl = $entry.WebUrl
            if ([string]::IsNullOrWhiteSpace($webUrl)) { $webUrl = $entry.SiteId }
            $name = $entry.Name
            if ([string]::IsNullOrWhiteSpace($name)) { $name = $webUrl }
            if ([string]::IsNullOrWhiteSpace($webUrl)) { continue }

            Write-AuditProgress -Activity $activity -Current $i -Total $unique.Count -CurrentOperation $name
            $extra = if ($entry.SiteId) { "siteId=$($entry.SiteId)" } else { 'siteId=' }
            Add-ExposureNode -Id $webUrl -Type Site -DisplayName $name -Score 0 `
                -RiskFlags 'GraphInventory' -Extra $extra
        }
    }
    finally {
        Complete-AuditProgress -Activity $activity
    }

    Write-AuditLog "  Graph sites inventoried: $($unique.Count)."
}

function Collect-SharePointSites {
    if ($SkipSharePointSites) {
        $Script:RunCoverage.SharePointInventoryMode = 'Skipped'
        Write-AuditLog "`nSkipping SharePoint site-level scan." Warn
        return
    }

    if (-not $Script:SpoAvailable) {
        Collect-SharePointSitesFromGraph
        return
    }

    Write-AuditLog "`nScanning SharePoint sites (Everyone / external capability)..."
    try {
        $sites = @(Get-SPOSite -Limit All -ErrorAction Stop)
    }
    catch {
        Write-AuditLog "Get-SPOSite failed: $($_.Exception.Message)" Warn
        Collect-SharePointSitesFromGraph
        return
    }
    $Script:RunCoverage.SharePointInventoryMode = 'SPO'
    $Script:RunCoverage.SitesTotal = $sites.Count

    $activity = 'Scanning SharePoint sites'
    $i = 0
    try {
        foreach ($site in $sites) {
            $i++
            $siteLabel = if ($site.Title) { [string]$site.Title } else { [string]$site.Url }
            Write-AuditProgress -Activity $activity -Current $i -Total $sites.Count -CurrentOperation $siteLabel

            $flags = [System.Collections.Generic.List[string]]::new()
            $humanPrincipalCount = 0
            $siteMemberEdges = 0
            $siteMemberEdgeCapHit = $false
            $siteRoleEdges = 0
            $rolePrincipalIds = @{}

            if ($Script:PnpAvailable) {
                try {
                    $siteConnection = Connect-PnPOnline -Url $site.Url -Connection $Script:PnpConnection -ReturnConnection -ErrorAction Stop
                    $roleGroups = @(
                        [PSCustomObject]@{ Role = 'Owner'; Group = Get-PnPGroup -AssociatedOwnerGroup -Connection $siteConnection -ErrorAction Stop },
                        [PSCustomObject]@{ Role = 'Member'; Group = Get-PnPGroup -AssociatedMemberGroup -Connection $siteConnection -ErrorAction Stop },
                        [PSCustomObject]@{ Role = 'Visitor'; Group = Get-PnPGroup -AssociatedVisitorGroup -Connection $siteConnection -ErrorAction Stop }
                    )
                    foreach ($roleGroup in $roleGroups) {
                        if (-not $roleGroup.Group) { continue }
                        $roleMembers = @(Get-PnPGroupMember -Identity $roleGroup.Group -Connection $siteConnection -ErrorAction Stop)
                        foreach ($roleMember in $roleMembers) {
                            $login = [string](Get-GraphObjectProperty -Object $roleMember -PropertyName 'LoginName')
                            $title = [string](Get-GraphObjectProperty -Object $roleMember -PropertyName 'Title')
                            if (-not $title) { $title = [string](Get-GraphObjectProperty -Object $roleMember -PropertyName 'Email') }
                            if (-not $login -or (Test-IsSystemSharePointLogin -LoginName $login -AllowEntraGroupClaims)) { continue }

                            $principal = Resolve-SharePointPrincipal -LoginName $login -DisplayName $title
                            Add-ExposureNode -Id $principal.Id -Type $principal.Type -DisplayName $principal.DisplayName `
                                -UserPrincipalName $principal.Upn -Extra "SharePointLogin=$($principal.RawLogin)"
                            Add-ExposureEdge -SourceId $principal.Id -TargetId $site.Url -EdgeType SiteRole `
                                -Detail "$($roleGroup.Role) role; Login=$($principal.RawLogin)" -Weight $Script:SiteRoleWeights[$roleGroup.Role]
                            $rolePrincipalIds[$principal.Id] = $true
                            $rolePrincipalIds[$principal.RawLogin] = $true
                            $siteRoleEdges++

                            if ($principal.Type -eq 'Group') {
                                $expandedCount = Add-SharePointGroupRoleMembers -GroupId $principal.Id -SiteUrl $site.Url `
                                    -Role $roleGroup.Role -RolePrincipalIds $rolePrincipalIds
                                $groupNode = $Script:NodeIndex[$principal.Id]
                                $groupNode.Extra = "SharePointLogin=$($principal.RawLogin);ExpandedMemberCount=$expandedCount;ExpansionCap=$Script:SiteGroupExpansionMemberCap"
                                $siteRoleEdges += $expandedCount
                            }
                        }
                    }
                    if ($siteRoleEdges -gt 0) { $flags.Add("SiteRoles:$siteRoleEdges") }
                }
                catch {
                    Write-AuditLog "  PnP roles failed for $($site.Url); retaining SPO flat membership: $($_.Exception.Message)" Warn
                }
            }

            try {
                $users = @(Get-SPOUser -Site $site.Url -ErrorAction Stop)
                foreach ($user in $users) {
                    $login = [string]$user.LoginName
                    $title = [string]$user.DisplayName
                    $isBroad = (Test-IsBroadGroupName -Name $title) -or (Test-IsBroadShareLoginName -LoginName $login) -or ($login -match '(?i)Everyone')

                    if ($isBroad) {
                        $flags.Add('EveryoneAccess')
                        $broadId = "broad:$login"
                        Add-ExposureNode -Id $broadId -Type BroadPrincipal -DisplayName $(if ($title) { $title } else { $login }) -Score 40 -RiskFlags 'Everyone'
                        Add-ExposureEdge -SourceId $broadId -TargetId $site.Url -EdgeType SitePrincipal `
                            -Detail "Site principal $login" -Weight 40
                        continue
                    }

                    if (Test-IsSystemSharePointLogin -LoginName $login) { continue }

                    $humanPrincipalCount++
                    if ($siteMemberEdges -ge $Script:SiteMemberEdgeCap) {
                        if (-not $siteMemberEdgeCapHit) {
                            $Script:RunCoverage.SiteMemberEdgeCapHits++
                            $siteMemberEdgeCapHit = $true
                        }
                        continue
                    }

                    $principal = Resolve-SharePointPrincipal -LoginName $login -DisplayName $title
                    if ($rolePrincipalIds.ContainsKey($principal.Id) -or $rolePrincipalIds.ContainsKey($principal.RawLogin)) {
                        continue
                    }
                    Add-ExposureNode -Id $principal.Id -Type $principal.Type -DisplayName $principal.DisplayName `
                        -UserPrincipalName $principal.Upn -Extra "SharePointLogin=$($principal.RawLogin)"
                    Add-ExposureEdge -SourceId $principal.Id -TargetId $site.Url -EdgeType SiteMember `
                        -Detail "Site member $($principal.RawLogin)" -Weight $Script:SiteMemberWeight
                    $siteMemberEdges++
                }
            }
            catch {
                Write-AuditLog "  SPO users failed for $($site.Url): $($_.Exception.Message)" Warn
            }

            $sharing = [string]$site.SharingCapability
            if ($sharing -match 'External') {
                $flags.Add('ExternalSharing')
                Add-ExposureNode -Id 'capability:ExternalSharing' -Type BroadPrincipal -DisplayName 'External sharing capability' `
                    -Score $Script:SiteExternalSharingWeight -RiskFlags 'ExternalSharing'
                Add-ExposureEdge -SourceId 'capability:ExternalSharing' -TargetId $site.Url -EdgeType SiteCapability `
                    -Detail "SharingCapability=$sharing" -Weight $Script:SiteExternalSharingWeight
            }

            if ($humanPrincipalCount -gt 0) {
                $flags.Add("SiteMembers:$humanPrincipalCount")
            }

            Add-ExposureNode -Id $site.Url -Type Site -DisplayName $site.Title -Score 0 `
                -RiskFlags (($flags | Select-Object -Unique) -join ',') `
                -Extra "SharingCapability=$sharing;HumanPrincipals=$humanPrincipalCount"
        }
    }
    finally {
        Complete-AuditProgress -Activity $activity
    }

    Write-AuditLog "  Sites scanned: $($sites.Count)."
}

function Get-GraphDriveChildren {
    param([string]$DriveId, [string]$ItemId = 'root')

    if ($ItemId -eq 'root') {
        $uri = "https://graph.microsoft.com/v1.0/drives/$DriveId/root/children?`$top=100"
    }
    else {
        $uri = "https://graph.microsoft.com/v1.0/drives/$DriveId/items/$ItemId/children?`$top=100"
    }

    $children = [System.Collections.Generic.List[object]]::new()
    while ($uri) {
        $response = Invoke-MgGraphRequest -Method GET -Uri $uri -ErrorAction Stop
        foreach ($item in @((Get-GraphObjectProperty -Object $response -PropertyName 'value'))) {
            if ($item) { $children.Add($item) }
        }
        $uri = Get-GraphObjectProperty -Object $response -PropertyName '@odata.nextLink'
    }
    return $children
}

function Get-GraphUserDriveChildren {
    param(
        [string]$UserId,
        [string]$ItemId = 'root',
        [string]$Select = ''
    )

    $userKey = [uri]::EscapeDataString($UserId)
    $selectQs = if (-not [string]::IsNullOrWhiteSpace($Select)) { "&`$select=$Select" } else { '' }
    if ($ItemId -eq 'root') {
        $uri = "https://graph.microsoft.com/v1.0/users/$userKey/drive/root/children?`$top=100$selectQs"
    }
    else {
        $uri = "https://graph.microsoft.com/v1.0/users/$userKey/drive/items/$ItemId/children?`$top=100$selectQs"
    }

    $children = [System.Collections.Generic.List[object]]::new()
    while ($uri) {
        $response = Invoke-MgGraphRequest -Method GET -Uri $uri -ErrorAction Stop
        foreach ($item in @((Get-GraphObjectProperty -Object $response -PropertyName 'value'))) {
            if ($item) { $children.Add($item) }
        }
        $uri = Get-GraphObjectProperty -Object $response -PropertyName '@odata.nextLink'
    }
    return $children
}

function Invoke-GraphBatchRequest {
    param(
        [Parameter(Mandatory)][object[]]$Requests,
        [int]$ChunkSize = 20
    )

    # $Requests: objects with Id, Method, Url (relative Graph path, e.g. /users/{id}/drive)
    $byId = @{}
    if (-not $Requests -or $Requests.Count -eq 0) { return $byId }

    for ($offset = 0; $offset -lt $Requests.Count; $offset += $ChunkSize) {
        $end = [Math]::Min($offset + $ChunkSize - 1, $Requests.Count - 1)
        $chunk = @($Requests[$offset..$end])
        $payload = @{
            requests = @(
                foreach ($req in $chunk) {
                    @{
                        id     = [string]$req.Id
                        method = [string]$req.Method
                        url    = [string]$req.Url
                    }
                }
            )
        }

        $retry = 0
        $response = $null
        while ($true) {
            try {
                $response = Invoke-MgGraphRequest -Method POST `
                    -Uri 'https://graph.microsoft.com/v1.0/$batch' `
                    -Body ($payload | ConvertTo-Json -Depth 8) `
                    -ContentType 'application/json' `
                    -ErrorAction Stop
                break
            }
            catch {
                if ($retry -ge 4 -or $_.Exception.Message -notmatch '(?i)429|throttl') { throw }
                Start-Sleep -Seconds ([Math]::Pow(2, $retry))
                $retry++
            }
        }

        foreach ($entry in @((Get-GraphObjectProperty -Object $response -PropertyName 'responses'))) {
            if (-not $entry) { continue }
            $id = [string](Get-GraphObjectProperty -Object $entry -PropertyName 'id')
            if (-not $id) { continue }
            $byId[$id] = [PSCustomObject]@{
                Id     = $id
                Status = [int](Get-GraphObjectProperty -Object $entry -PropertyName 'status')
                Body   = (Get-GraphObjectProperty -Object $entry -PropertyName 'body')
            }
        }
    }

    return $byId
}

function Get-GraphDriveItemPermissions {
    param(
        [string]$DriveId,
        [string]$UserId,
        [string]$ItemId = 'root'
    )

    try {
        if ($UserId) {
            $userKey = [uri]::EscapeDataString($UserId)
            if ($ItemId -eq 'root') {
                $uri = "https://graph.microsoft.com/v1.0/users/$userKey/drive/root/permissions"
            }
            else {
                $uri = "https://graph.microsoft.com/v1.0/users/$userKey/drive/items/$ItemId/permissions"
            }
        }
        else {
            if ($ItemId -eq 'root') {
                $uri = "https://graph.microsoft.com/v1.0/drives/$DriveId/root/permissions"
            }
            else {
                $uri = "https://graph.microsoft.com/v1.0/drives/$DriveId/items/$ItemId/permissions"
            }
        }

        $response = Invoke-MgGraphRequest -Method GET -Uri $uri -ErrorAction Stop
        $permissions = Get-GraphObjectProperty -Object $response -PropertyName 'value'
        if ($permissions) { return @($permissions) }
        return @()
    }
    catch {
        $Script:RunCoverage.ContentPermissionFailures++
        return @()
    }
}

function Add-DriveItemPermissionEvidence {
    param(
        [string]$DriveId,
        [string]$UserId,
        [string]$OwnerLabel,
        [string]$ItemId,
        [string]$ItemPath
    )

    $grants = [System.Collections.Generic.List[object]]::new()
    foreach ($permission in (Get-GraphDriveItemPermissions -DriveId $DriveId -UserId $UserId -ItemId $ItemId)) {
        foreach ($grant in (Get-GraphPermissionBroadSharingGrants -Permission $permission)) {
            $grants.Add($grant)
        }
    }

    $targetId = "driveitem:${DriveId}:${ItemId}"
    foreach ($grant in @($grants | Where-Object { $_.GrantType -ne 'DirectSharePrincipal' })) {
        Add-ExposureNode -Id $targetId -Type DriveItem -DisplayName $ItemPath -Score $grant.Weight `
            -RiskFlags $grant.GrantType -Extra $OwnerLabel
        Add-ExposureNode -Id $grant.PrincipalId -Type $grant.PrincipalType -DisplayName $grant.Grantee
        Add-ExposureEdge -SourceId $grant.PrincipalId -TargetId $targetId -EdgeType BroadShare `
            -Detail "$($grant.Detail) @ $ItemPath ($OwnerLabel)" -Weight $grant.Weight

        # Owners can reach their own broadly shared content via Copilot.
        if ($UserId) {
            Add-ExposureEdge -SourceId $UserId -TargetId $targetId -EdgeType BroadShare `
                -Detail "Owner reach: $($grant.Detail) @ $ItemPath" -Weight ([Math]::Round($grant.Weight * 0.5))
        }
    }

    $directGrantees = @(
        $grants |
            Where-Object { $_.GrantType -eq 'DirectSharePrincipal' } |
            Group-Object -Property PrincipalId |
            ForEach-Object { $_.Group | Select-Object -First 1 }
    )
    $fanIn = $directGrantees.Count
    if ($fanIn -lt $DirectShareFanInThreshold) { return }

    $weight = [Math]::Min(40, [Math]::Max(15, [Math]::Round($fanIn * 1.5)))
    $principalId = "directShare:fanIn:$fanIn"
    Add-ExposureNode -Id $targetId -Type DriveItem -DisplayName $ItemPath -Score $weight `
        -RiskFlags 'DirectShareFanIn' -Extra $OwnerLabel
    Add-ExposureNode -Id $principalId -Type BroadPrincipal -DisplayName "Direct shares ($fanIn named principals)"
    Add-ExposureEdge -SourceId $principalId -TargetId $targetId -EdgeType DirectShareFanIn `
        -Detail "Distinct named user/group grants=$fanIn; Threshold=$DirectShareFanInThreshold @ $ItemPath ($OwnerLabel)" -Weight $weight
    $Script:RunCoverage.DirectShareFindings++
}

function Search-DriveBroadSharing {
    param(
        [string]$DriveId,
        [string]$UserId,
        [string]$OwnerLabel,
        [string]$ItemId = 'root',
        [string]$ItemPath = '\',
        [int]$Depth = 0,
        [ref]$ItemsScanned,
        [ref]$CapReached
    )

    if ($ItemsScanned.Value -ge $BroadSharingMaxItems) {
        $CapReached.Value = $true
        $Script:RunCoverage.ContentItemsSkippedCap++
        return
    }
    if ($Depth -gt $BroadSharingMaxDepth) {
        $Script:RunCoverage.ContentItemsSkippedDepth++
        return
    }

    Add-DriveItemPermissionEvidence -DriveId $DriveId -UserId $UserId -OwnerLabel $OwnerLabel `
        -ItemId $ItemId -ItemPath $ItemPath

    try {
        if ($UserId) {
            $children = @(Get-GraphUserDriveChildren -UserId $UserId -ItemId $ItemId)
        }
        else {
            $children = @(Get-GraphDriveChildren -DriveId $DriveId -ItemId $ItemId)
        }
    }
    catch {
        $Script:RunCoverage.ContentDriveFailures++
        return
    }

    foreach ($child in $children) {
        if ($ItemsScanned.Value -ge $BroadSharingMaxItems) {
            $CapReached.Value = $true
            $Script:RunCoverage.ContentItemsSkippedCap++
            return
        }

        $ItemsScanned.Value++
        $childName = [string](Get-GraphObjectProperty -Object $child -PropertyName 'name')
        $childId = [string](Get-GraphObjectProperty -Object $child -PropertyName 'id')
        if (-not $childId) { continue }
        $childPath = if ($ItemPath -eq '\') { $childName } else { Join-Path $ItemPath $childName }

        Add-DriveItemPermissionEvidence -DriveId $DriveId -UserId $UserId -OwnerLabel $OwnerLabel `
            -ItemId $childId -ItemPath $childPath

        if (Get-GraphObjectProperty -Object $child -PropertyName 'folder') {
            Search-DriveBroadSharing -DriveId $DriveId -UserId $UserId -OwnerLabel $OwnerLabel `
                -ItemId $childId -ItemPath $childPath -Depth ($Depth + 1) -ItemsScanned $ItemsScanned `
                -CapReached $CapReached
        }
    }
}

function Collect-OneDriveSamples {
    if ($SkipOneDriveSample -or $SkipSharePointContentSample) {
        Write-AuditLog "`nSkipping OneDrive content sample." Warn
        return
    }

    Write-AuditLog "`nSampling OneDrive broad sharing (max $BroadSharingMaxItems items, depth $BroadSharingMaxDepth)..."
    if ($Script:TargetUserScopeEnabled) {
        $users = @($Script:TargetUsers | Select-Object Id, DisplayName, UserPrincipalName)
        Write-AuditLog "  User scope active: OneDrive sample limited to $($users.Count) listed user(s)."
    }
    else {
        try {
            $users = @(Get-MgUser -All -Filter "accountEnabled eq true" -Property 'id,displayName,userPrincipalName' -ErrorAction Stop)
        }
        catch {
            Write-AuditLog "User list for OneDrive sample failed: $($_.Exception.Message)" Warn
            return
        }

        if ($MaxUsersForOneDriveSample -gt 0 -and $users.Count -gt $MaxUsersForOneDriveSample) {
            $users = $users | Select-Object -First $MaxUsersForOneDriveSample
            Write-AuditLog "  Capped OneDrive sample to $MaxUsersForOneDriveSample users."
        }
    }

    $activity = 'Sampling OneDrive broad sharing'
    $i = 0
    $sampled = 0
    try {
        foreach ($user in $users) {
            $i++
            Write-AuditProgress -Activity $activity -Current $i -Total $users.Count -CurrentOperation ([string]$user.UserPrincipalName)

            Add-ExposureNode -Id $user.Id -Type User -DisplayName $user.DisplayName -UserPrincipalName $user.UserPrincipalName | Out-Null

            $driveInfo = Get-GraphUserDrive -User $user -PreferMe
            $driveId = [string]$driveInfo.DriveId
            if (-not $driveId) {
                $Script:RunCoverage.ContentDriveFailures++
                $errText = if ($driveInfo.Errors) { ($driveInfo.Errors -join ' | ') } else { 'no drive id' }
                Write-AuditLog "  OneDrive unavailable for $($user.UserPrincipalName): $errText" Warn
                continue
            }

            $scanned = [ref]1
            $capReached = [ref]$false
            try {
                Search-DriveBroadSharing -DriveId $driveId -UserId $user.Id -OwnerLabel "OneDrive:$($user.UserPrincipalName)" `
                    -ItemsScanned $scanned -CapReached $capReached
                $sampled++
                $Script:RunCoverage.ContentItemsScanned += $scanned.Value
                if ($capReached.Value) { $Script:RunCoverage.ContentItemsCapped++ }
            }
            catch {
                $Script:RunCoverage.ContentDriveFailures++
                Write-AuditLog "  OneDrive sample failed for $($user.UserPrincipalName): $($_.Exception.Message)" Warn
            }
        }
    }
    finally {
        Complete-AuditProgress -Activity $activity
    }

    $Script:RunCoverage.OneDriveUsersSampled = $sampled
    Write-AuditLog "  OneDrive users sampled: $sampled / $($users.Count)."
}

function Collect-SharePointLibrarySamples {
    if ($SkipSharePointContentSample) {
        Write-AuditLog "`nSkipping SharePoint library content sample." Warn
        return
    }

    Write-AuditLog "`nSampling team/group SharePoint libraries (max $MaxSitesForContentSample sites)..."
    $siteCandidates = [System.Collections.Generic.List[object]]::new()
    $seenSiteIds = @{}

    try {
        $groups = @(Get-MgGroup -All -Filter "groupTypes/any(c:c eq 'Unified')" -Property 'id,displayName' -ErrorAction Stop)
    }
    catch {
        Write-AuditLog "Could not list groups for site sample: $($_.Exception.Message)" Warn
        return
    }

    foreach ($group in $groups) {
        try {
            $site = $null
            try { $site = Get-MgGroupSite -GroupId $group.Id -ErrorAction Stop } catch { }
            $siteId = Get-NormalizedGraphSiteId -SiteOrId $site
            $siteUrl = if ($site) { [string](Get-GraphObjectProperty -Object $site -PropertyName 'webUrl') } else { '' }
            $driveId = Get-GraphGroupDefaultDriveId -GroupId $group.Id
            if (-not $driveId -and -not $siteId -and [string]::IsNullOrWhiteSpace($siteUrl)) { continue }

            $dedupeKey = if ($driveId) { "drive:$driveId" } elseif ($siteId) { $siteId } else { $siteUrl }
            if ($seenSiteIds.ContainsKey($dedupeKey)) { continue }
            $seenSiteIds[$dedupeKey] = $true

            $siteNode = @($Script:Nodes | Where-Object {
                    $_.Type -eq 'Site' -and (
                        ($siteUrl -and $_.Id -eq $siteUrl) -or
                        ($siteId -and $_.Extra -match "(?i)(?:^|;)siteId=$([regex]::Escape($siteId))(?:;|$)")
                    )
                } | Select-Object -First 1)
            $hasPrioritySignal = $false
            if ($siteNode) {
                $hasPrioritySignal = $siteNode.RiskFlags -match '(?i)(?:^|,)(EveryoneAccess|ExternalSharing|Everyone|External)(?:,|$)'
                if (-not $hasPrioritySignal) {
                    $hasPrioritySignal = @($Script:Edges | Where-Object {
                            $_.TargetId -eq $siteNode.Id -and $_.EdgeType -in @('SitePrincipal', 'SiteCapability')
                        }).Count -gt 0
                }
            }
            $siteCandidates.Add([PSCustomObject]@{
                    GroupId     = [string]$group.Id
                    SiteId      = $siteId
                    WebUrl      = $siteUrl
                    DriveId     = $driveId
                    Label       = [string]$group.DisplayName
                    Prioritized = [bool]$hasPrioritySignal
                })
        }
        catch {
            # group may not have a site/drive
        }
    }

    $activity = 'Sampling SharePoint libraries'
    $entries = @($siteCandidates | Sort-Object @{ Expression = 'Prioritized'; Descending = $true }, Label | Select-Object -First $MaxSitesForContentSample)
    $Script:RunCoverage.ContentSitesPrioritized = @($entries | Where-Object { $_.Prioritized }).Count
    $i = 0
    $itemsInspected = 0
    try {
        foreach ($entry in $entries) {
            $i++
            $label = $entry.Label
            Write-AuditProgress -Activity $activity -Current $i -Total $entries.Count -CurrentOperation ([string]$label)

            $driveIds = [System.Collections.Generic.List[string]]::new()
            if ($entry.DriveId) { $driveIds.Add([string]$entry.DriveId) }
            foreach ($extraDriveId in @(Get-GraphSiteDriveIds -SiteId $entry.SiteId -WebUrl $entry.WebUrl)) {
                if ($extraDriveId -and -not ($driveIds -contains $extraDriveId)) {
                    $driveIds.Add($extraDriveId)
                }
            }

            if ($driveIds.Count -eq 0) {
                $Script:RunCoverage.ContentDriveFailures++
                Write-AuditLog "  Site drives failed for ${label}: no group/site drive id resolved" Warn
                continue
            }

            foreach ($driveId in $driveIds) {
                $scanned = [ref]1
                $capReached = [ref]$false
                try {
                    Search-DriveBroadSharing -DriveId $driveId -UserId $null -OwnerLabel "Site:$label" `
                        -ItemsScanned $scanned -CapReached $capReached
                    $itemsInspected += $scanned.Value
                    $Script:RunCoverage.ContentItemsScanned += $scanned.Value
                    if ($capReached.Value) { $Script:RunCoverage.ContentItemsCapped++ }
                }
                catch {
                    $Script:RunCoverage.ContentDriveFailures++
                    Write-AuditLog "  Library sample failed for ${label}: $($_.Exception.Message)" Warn
                }
            }
        }
    }
    finally {
        Complete-AuditProgress -Activity $activity
    }

    $Script:RunCoverage.SitesSampled = $entries.Count
    Write-AuditLog "  Library sites sampled: $($entries.Count); items inspected: $itemsInspected."
}

function Get-GraphPagedValueCollection {
    param(
        [Parameter(Mandatory)][string]$Uri,
        [int]$MaxItems = 500
    )

    $items = [System.Collections.Generic.List[object]]::new()
    $next = $Uri
    while ($next -and $items.Count -lt $MaxItems) {
        $response = Invoke-MgGraphRequest -Method GET -Uri $next -ErrorAction Stop
        foreach ($item in @((Get-GraphObjectProperty -Object $response -PropertyName 'value'))) {
            if ($item) { $items.Add($item) }
            if ($items.Count -ge $MaxItems) { break }
        }
        $next = Get-GraphObjectProperty -Object $response -PropertyName '@odata.nextLink'
    }
    return @($items)
}

function Test-SignedInUserMatchesPrincipal {
    param([Parameter(Mandatory)]$Principal)

    # App-only tokens have no signed-in user; /me discovery does not apply.
    if ($Script:GraphAuthMode -eq 'AppOnly') { return $false }

    $ctx = Get-MgContext -ErrorAction SilentlyContinue
    if (-not $ctx -or [string]::IsNullOrWhiteSpace([string]$ctx.Account)) { return $false }
    $account = [string]$ctx.Account
    foreach ($candidate in @($Principal.UserPrincipalName, $Principal.Mail, $Principal.Id)) {
        if ([string]::IsNullOrWhiteSpace([string]$candidate)) { continue }
        if ($account -ieq [string]$candidate) { return $true }
    }
    return $false
}

function Get-GraphSharedWithMeItems {
    param(
        [Parameter(Mandatory)]$Principal,
        [int]$MaxItems = 500
    )

    # Application permissions are not supported for sharedWithMe (always Forbidden under app-only).
    if ($Script:GraphAuthMode -eq 'AppOnly') {
        Write-AuditLog '  SharedWithMe skipped (not supported for app-only Graph; using insights + reverse OneDrive ACL).' Info
        return @()
    }

    # Official docs only document /me/drive/sharedWithMe. The API is deprecated and often
    # returns an empty 200 even when the OneDrive UI shows Shared with me items. Try several
    # shapes, prefer /me when the operator is the scoped user, then fall back.
    $userKey = [uri]::EscapeDataString([string]$Principal.Id)
    $candidates = [System.Collections.Generic.List[string]]::new()
    if (Test-SignedInUserMatchesPrincipal -Principal $Principal) {
        [void]$candidates.Add("https://graph.microsoft.com/v1.0/me/drive/sharedWithMe?allowexternal=true&`$top=100")
        [void]$candidates.Add("https://graph.microsoft.com/v1.0/me/drive/sharedWithMe?`$top=100")
    }
    [void]$candidates.Add("https://graph.microsoft.com/v1.0/users/$userKey/drive/sharedWithMe?allowexternal=true&`$top=100")
    [void]$candidates.Add("https://graph.microsoft.com/v1.0/users/$userKey/drive/sharedWithMe?`$top=100")

    $lastError = $null
    foreach ($uri in $candidates) {
        try {
            $items = @(Get-GraphPagedValueCollection -Uri $uri -MaxItems $MaxItems)
            if ($items.Count -gt 0) {
                return $items
            }
        }
        catch {
            $lastError = $_.Exception.Message
        }
    }

    if ($lastError -and $candidates.Count -gt 0) {
        # All attempts failed (not merely empty) — surface for coverage.
        throw "SharedWithMe returned no usable results. Last error: $lastError"
    }
    return @()
}

function Get-GraphUserInsightsSharedItems {
    param(
        [Parameter(Mandatory)][string]$UserId,
        [int]$MaxItems = 500
    )

    $userKey = [uri]::EscapeDataString($UserId)
    $uri = "https://graph.microsoft.com/v1.0/users/$userKey/insights/shared?`$top=100"
    try {
        return @(Get-GraphPagedValueCollection -Uri $uri -MaxItems $MaxItems)
    }
    catch {
        Write-AuditLog "  insights/shared unavailable for ${UserId}: $($_.Exception.Message)" Warn
        return @()
    }
}

function Test-IdentityMatchesTargetUser {
    param(
        [string]$PrincipalId = '',
        [string]$DisplayName = '',
        [string]$UpnOrMail = ''
    )

    foreach ($candidate in @($PrincipalId, $UpnOrMail, $DisplayName)) {
        if ([string]::IsNullOrWhiteSpace($candidate)) { continue }
        $key = $candidate.Trim().ToLowerInvariant()
        if ($Script:TargetUserIndex.ContainsKey($key)) {
            return $Script:TargetUserIndex[$key]
        }
    }
    return $null
}

function Get-PermissionStrengthFromRoles {
    param($Permission)

    $roles = @(Get-GraphObjectProperty -Object $Permission -PropertyName 'roles')
    $roleText = ($roles | ForEach-Object { [string]$_ }) -join ','
    if ($roleText -match '(?i)owner|full') { return 'FullControl' }
    if ($roleText -match '(?i)write|edit') { return 'Contribute' }
    if ($roleText -match '(?i)read') { return 'Read' }
    return 'Unknown'
}

function Get-SharedWithMeSharerInfo {
    param($DriveItem)

    $candidates = @(
        (Get-GraphObjectProperty -Object (Get-GraphObjectProperty -Object (Get-GraphObjectProperty -Object (Get-GraphObjectProperty -Object $DriveItem -PropertyName 'remoteItem') -PropertyName 'shared') -PropertyName 'sharedBy') -PropertyName 'user'),
        (Get-GraphObjectProperty -Object (Get-GraphObjectProperty -Object (Get-GraphObjectProperty -Object $DriveItem -PropertyName 'remoteItem') -PropertyName 'createdBy') -PropertyName 'user'),
        (Get-GraphObjectProperty -Object (Get-GraphObjectProperty -Object $DriveItem -PropertyName 'createdBy') -PropertyName 'user'),
        (Get-GraphObjectProperty -Object (Get-GraphObjectProperty -Object (Get-GraphObjectProperty -Object $DriveItem -PropertyName 'remoteItem') -PropertyName 'shared') -PropertyName 'owner')
    )

    foreach ($userObj in $candidates) {
        if ($null -eq $userObj) { continue }
        $id = [string](Get-GraphObjectProperty -Object $userObj -PropertyName 'id')
        $email = [string](Get-GraphObjectProperty -Object $userObj -PropertyName 'email')
        if (-not $email) { $email = [string](Get-GraphObjectProperty -Object $userObj -PropertyName 'userPrincipalName') }
        $displayName = [string](Get-GraphObjectProperty -Object $userObj -PropertyName 'displayName')
        if (-not $id -and -not $email -and -not $displayName) { continue }
        return [PSCustomObject]@{
            Id          = $id
            Upn         = $email
            DisplayName = $displayName
        }
    }

    return [PSCustomObject]@{
        Id          = ''
        Upn         = ''
        DisplayName = ''
    }
}

function New-UserReachSharedRow {
    param(
        [Parameter(Mandatory)]$Principal,
        [Parameter(Mandatory)][string]$Workload,
        [Parameter(Mandatory)][string]$ResourceType,
        [Parameter(Mandatory)][string]$ResourceId,
        [Parameter(Mandatory)][string]$ResourceName,
        [Parameter(Mandatory)][string]$AccessVia,
        [string]$PermissionStrength = 'Unknown',
        [string]$SharerId = '',
        [string]$SharerUpn = '',
        [string]$SharerDisplayName = '',
        [string]$Evidence = ''
    )

    return [PSCustomObject]@{
        PrincipalId          = [string]$Principal.Id
        PrincipalUpn         = [string]$Principal.UserPrincipalName
        PrincipalDisplayName = [string]$Principal.DisplayName
        Workload             = $Workload
        ResourceType         = $ResourceType
        ResourceId           = $ResourceId
        ResourceName         = $ResourceName
        AccessVia            = $AccessVia
        PermissionStrength   = $PermissionStrength
        SharerId             = $SharerId
        SharerUpn            = $SharerUpn
        SharerDisplayName    = $SharerDisplayName
        Evidence             = $Evidence
        SensitivityHint      = ''
        BaselineStatus       = 'Unknown'
    }
}

function Collect-UserReachReverseSiteAcl {
    param(
        [Parameter(Mandatory)][object[]]$TargetUsers,
        [int]$MaxSites = 20
    )

    if (-not $Script:SpoAvailable) {
        return 0
    }

    $siteIds = @(
        $Script:Edges |
            Where-Object { $_.EdgeType -in @('SitePrincipal', 'SiteCapability', 'SiteRole') -and $_.TargetId } |
            Select-Object -ExpandProperty TargetId -Unique |
            Where-Object { $_ -match '^https?://' } |
            Select-Object -First $MaxSites
    )
    if ($siteIds.Count -eq 0) { return 0 }

    $scanned = 0
    $activity = 'User reach reverse site ACL'
    $i = 0
    try {
        foreach ($siteUrl in $siteIds) {
            $i++
            Write-AuditProgress -Activity $activity -Current $i -Total $siteIds.Count -CurrentOperation $siteUrl
            try {
                $spoUsers = @(Get-SPOUser -Site $siteUrl -ErrorAction Stop)
            }
            catch {
                Write-AuditLog "  Reverse ACL skipped for ${siteUrl}: $($_.Exception.Message)" Warn
                continue
            }
            $scanned++

            foreach ($spoUser in $spoUsers) {
                $login = [string]$spoUser.LoginName
                $email = [string]$spoUser.Email
                $title = [string]$spoUser.Title
                if (Test-IsSystemSharePointLogin -LoginName $login) { continue }
                if (Test-IsBroadShareLoginName -LoginName $login) { continue }

                $matched = $null
                foreach ($candidate in @($email, $login, $title)) {
                    if ([string]::IsNullOrWhiteSpace($candidate)) { continue }
                    $key = $candidate.Trim().ToLowerInvariant()
                    if ($key -match '[\\|/]') {
                        $key = ($key -split '[\\|/]')[-1]
                    }
                    if ($Script:TargetUserIndex.ContainsKey($key)) {
                        $matched = $Script:TargetUserIndex[$key]
                        break
                    }
                    if ($Script:TargetUserIndex.ContainsKey($candidate.Trim().ToLowerInvariant())) {
                        $matched = $Script:TargetUserIndex[$candidate.Trim().ToLowerInvariant()]
                        break
                    }
                }
                if ($null -eq $matched) { continue }

                $isSiteAdmin = $false
                try { $isSiteAdmin = [bool]$spoUser.IsSiteAdmin } catch { }
                $strength = if ($isSiteAdmin) { 'FullControl' } else { 'Contribute' }
                $evidence = "Get-SPOUser LoginName=$login; IsSiteAdmin=$isSiteAdmin"
                $Script:UserReachSharedRows.Add((New-UserReachSharedRow -Principal $matched `
                            -Workload 'SharePoint' -ResourceType 'Site' -ResourceId $siteUrl `
                            -ResourceName $siteUrl -AccessVia 'SiteAclGrant' -PermissionStrength $strength `
                            -Evidence $evidence))

                Add-ExposureNode -Id $matched.Id -Type User -DisplayName $matched.DisplayName `
                    -UserPrincipalName $matched.UserPrincipalName -Mail $matched.Mail
                Add-ExposureNode -Id $siteUrl -Type Site -DisplayName $siteUrl
                Add-ExposureEdge -SourceId $matched.Id -TargetId $siteUrl -EdgeType SiteAclGrant `
                    -Detail $evidence -Weight $(if ($isSiteAdmin) { 25 } else { 8 })
            }
        }
    }
    finally {
        Complete-AuditProgress -Activity $activity
    }

    return $scanned
}

function Add-UserReachSharedDriveItem {
    param(
        [Parameter(Mandatory)]$Principal,
        [Parameter(Mandatory)]$DriveItem,
        [Parameter(Mandatory)][string]$AccessVia,
        [string]$EvidencePrefix = 'Graph sharedWithMe',
        $Owner = $null,
        [string]$PermissionStrength = 'Unknown'
    )

    $remote = Get-GraphObjectProperty -Object $DriveItem -PropertyName 'remoteItem'
    $parent = Get-GraphObjectProperty -Object $remote -PropertyName 'parentReference'
    if (-not $parent) {
        $parent = Get-GraphObjectProperty -Object $DriveItem -PropertyName 'parentReference'
    }
    $driveId = [string](Get-GraphObjectProperty -Object $parent -PropertyName 'driveId')
    $itemId = [string](Get-GraphObjectProperty -Object $remote -PropertyName 'id')
    if (-not $itemId) { $itemId = [string](Get-GraphObjectProperty -Object $DriveItem -PropertyName 'id') }
    $name = [string](Get-GraphObjectProperty -Object $remote -PropertyName 'name')
    if (-not $name) { $name = [string](Get-GraphObjectProperty -Object $DriveItem -PropertyName 'name') }
    if (-not $name) { $name = $itemId }
    $webUrl = [string](Get-GraphObjectProperty -Object $remote -PropertyName 'webUrl')
    if (-not $webUrl) { $webUrl = [string](Get-GraphObjectProperty -Object $DriveItem -PropertyName 'webUrl') }

    if (-not $driveId -or -not $itemId) {
        $resourceId = "sharedwithme:$($Principal.Id):$name"
    }
    else {
        $resourceId = "driveitem:${driveId}:${itemId}"
    }

    $sharer = Get-SharedWithMeSharerInfo -DriveItem $DriveItem
    if ((-not $sharer.Id -and -not $sharer.Upn) -and $Owner) {
        $sharer = [PSCustomObject]@{
            Id          = [string]$Owner.Id
            Upn         = [string]$Owner.UserPrincipalName
            DisplayName = [string]$Owner.DisplayName
        }
    }

    $workload = if ($webUrl -match 'sharepoint\.com' -and $webUrl -notmatch '-my\.sharepoint\.com') {
        'SharePoint'
    }
    else {
        'OneDrive'
    }

    $evidenceParts = @($EvidencePrefix)
    if ($webUrl) { $evidenceParts += "webUrl=$webUrl" }
    if ($sharer.DisplayName -or $sharer.Upn -or $sharer.Id) {
        $evidenceParts += ("sharedBy={0}" -f ($(if ($sharer.Upn) { $sharer.Upn } elseif ($sharer.DisplayName) { $sharer.DisplayName } else { $sharer.Id })))
    }
    $evidence = $evidenceParts -join '; '

    $Script:UserReachSharedRows.Add((New-UserReachSharedRow -Principal $Principal `
                -Workload $workload -ResourceType 'DriveItem' -ResourceId $resourceId `
                -ResourceName $name -AccessVia $AccessVia -PermissionStrength $PermissionStrength `
                -SharerId $sharer.Id -SharerUpn $sharer.Upn -SharerDisplayName $sharer.DisplayName `
                -Evidence $evidence))

    Add-ExposureNode -Id $resourceId -Type DriveItem -DisplayName $name -Extra $(
        if ($sharer.Id -or $sharer.Upn) { "SharedBy=$(if ($sharer.Upn) { $sharer.Upn } else { $sharer.Id })" } else { '' }
    ) | Out-Null
    if ($sharer.Id) {
        Add-ExposureNode -Id $sharer.Id -Type User -DisplayName $sharer.DisplayName `
            -UserPrincipalName $sharer.Upn -Mail $sharer.Upn | Out-Null
    }
    Add-ExposureEdge -SourceId $Principal.Id -TargetId $resourceId -EdgeType SharedWith `
        -Detail $evidence -Weight 5
}

function Add-UserReachInsightSharedItem {
    param(
        [Parameter(Mandatory)]$Principal,
        [Parameter(Mandatory)]$Insight
    )

    $viz = Get-GraphObjectProperty -Object $Insight -PropertyName 'resourceVisualization'
    $reference = Get-GraphObjectProperty -Object $Insight -PropertyName 'resourceReference'
    $shared = Get-GraphObjectProperty -Object $Insight -PropertyName 'lastShared'
    if (-not $shared) { $shared = Get-GraphObjectProperty -Object $Insight -PropertyName 'shared' }
    $sharedBy = Get-GraphObjectProperty -Object (Get-GraphObjectProperty -Object $shared -PropertyName 'sharedBy') -PropertyName 'user'
    if (-not $sharedBy) {
        $sharedBy = Get-GraphObjectProperty -Object (Get-GraphObjectProperty -Object $Insight -PropertyName 'shared') -PropertyName 'sharedBy'
        $sharedBy = Get-GraphObjectProperty -Object $sharedBy -PropertyName 'user'
    }

    $title = [string](Get-GraphObjectProperty -Object $viz -PropertyName 'title')
    if (-not $title) { $title = [string](Get-GraphObjectProperty -Object $viz -PropertyName 'mediaType') }
    $webUrl = [string](Get-GraphObjectProperty -Object $reference -PropertyName 'webUrl')
    $resourceIdRaw = [string](Get-GraphObjectProperty -Object $reference -PropertyName 'id')
    $resourceId = if ($resourceIdRaw) { "insight:$resourceIdRaw" } elseif ($webUrl) { "insight:$webUrl" } else { "insight:$($Principal.Id):$title" }
    if (-not $title) { $title = $resourceId }

    $sharerId = [string](Get-GraphObjectProperty -Object $sharedBy -PropertyName 'id')
    $sharerUpn = [string](Get-GraphObjectProperty -Object $sharedBy -PropertyName 'address')
    if (-not $sharerUpn) { $sharerUpn = [string](Get-GraphObjectProperty -Object $sharedBy -PropertyName 'email') }
    $sharerName = [string](Get-GraphObjectProperty -Object $sharedBy -PropertyName 'displayName')

    $workload = if ($webUrl -match 'sharepoint\.com' -and $webUrl -notmatch '-my\.sharepoint\.com') { 'SharePoint' } else { 'OneDrive' }
    $evidence = "Graph insights/shared; webUrl=$webUrl"

    $Script:UserReachSharedRows.Add((New-UserReachSharedRow -Principal $Principal `
                -Workload $workload -ResourceType 'DriveItem' -ResourceId $resourceId `
                -ResourceName $title -AccessVia 'SharedInsight' -PermissionStrength 'Unknown' `
                -SharerId $sharerId -SharerUpn $sharerUpn -SharerDisplayName $sharerName `
                -Evidence $evidence))

    Add-ExposureNode -Id $resourceId -Type DriveItem -DisplayName $title | Out-Null
    Add-ExposureEdge -SourceId $Principal.Id -TargetId $resourceId -EdgeType SharedWith `
        -Detail $evidence -Weight 5
}

function Test-GraphPermissionIsInherited {
    param($Permission)

    if ($null -eq $Permission) { return $false }
    $inheritedFrom = Get-GraphObjectProperty -Object $Permission -PropertyName 'inheritedFrom'
    if ($null -eq $inheritedFrom) { return $false }
    # inheritedFrom is an itemReference; treat any populated value as inherited.
    if ($inheritedFrom -is [string]) { return -not [string]::IsNullOrWhiteSpace($inheritedFrom) }
    $inheritedId = [string](Get-GraphObjectProperty -Object $inheritedFrom -PropertyName 'id')
    $inheritedPath = [string](Get-GraphObjectProperty -Object $inheritedFrom -PropertyName 'path')
    return (-not [string]::IsNullOrWhiteSpace($inheritedId) -or -not [string]::IsNullOrWhiteSpace($inheritedPath))
}

function Test-DriveItemHasSharedFacet {
    param($DriveItem)
    return $null -ne (Get-GraphObjectProperty -Object $DriveItem -PropertyName 'shared')
}

function Resolve-TargetUserFromIndex {
    param(
        [hashtable]$TargetIndex,
        [string]$PrincipalId = '',
        [string]$DisplayName = '',
        [string]$UpnOrMail = ''
    )

    if ($null -eq $TargetIndex) { return $null }
    foreach ($candidate in @($PrincipalId, $UpnOrMail, $DisplayName)) {
        if ([string]::IsNullOrWhiteSpace($candidate)) { continue }
        $key = $candidate.Trim().ToLowerInvariant()
        if ($TargetIndex.ContainsKey($key)) { return $TargetIndex[$key] }
    }
    return $null
}

function Get-GraphPermissionDirectShareGrants {
    param($Permission)

    # Lean extractor for reverse grant scan (named user/group only; no Script: dependencies).
    $grants = [System.Collections.Generic.List[object]]::new()
    if ($null -eq $Permission) { return @($grants) }

    $identitySets = [System.Collections.Generic.List[object]]::new()
    foreach ($propName in @('grantedToIdentitiesV2', 'grantedToIdentities', 'grantedToV2', 'grantedTo')) {
        $collection = Get-GraphObjectProperty -Object $Permission -PropertyName $propName
        if ($collection) {
            foreach ($entry in @($collection)) { if ($entry) { $identitySets.Add($entry) } }
        }
    }

    foreach ($identitySet in $identitySets) {
        foreach ($entityType in @('user', 'group')) {
            $entity = Get-GraphObjectProperty -Object $identitySet -PropertyName $entityType
            if (-not $entity) { continue }

            $displayName = [string](Get-GraphObjectProperty -Object $entity -PropertyName 'displayName')
            $entityId = [string](Get-GraphObjectProperty -Object $entity -PropertyName 'id')
            $email = [string](Get-GraphObjectProperty -Object $entity -PropertyName 'email')
            if (-not $email) { $email = [string](Get-GraphObjectProperty -Object $entity -PropertyName 'userPrincipalName') }
            $principalId = if ($entityId) { $entityId } elseif ($email) { $email } elseif ($displayName) { "direct:${entityType}:$displayName" } else { '' }
            if (-not $principalId) { continue }

            $grants.Add([PSCustomObject]@{
                    GrantType   = 'DirectSharePrincipal'
                    Grantee     = $displayName
                    Email       = $email
                    Detail      = "Named $entityType grant: $(if ($email) { $email } else { $displayName })"
                    PrincipalId = $principalId
                })
        }
    }
    return @($grants)
}

function Invoke-UserReachOwnerDriveGrantScan {
    param(
        [Parameter(Mandatory)]$Owner,
        [Parameter(Mandatory)][string]$DriveId,
        [Parameter(Mandatory)][hashtable]$TargetIndex,
        [int]$MaxDepth = 3,
        [int]$MaxFolders = 60
    )

    # Returns hit records only (caller merges into reach map / exposure graph).
    # Walk folders; /permissions only on root + items with Graph shared facet; batch sibling ACLs.
    $hits = [System.Collections.Generic.List[object]]::new()
    $foldersScanned = 0
    $capReached = $false
    $userKey = [uri]::EscapeDataString([string]$Owner.Id)
    $ownerUpn = [string]$Owner.UserPrincipalName
    $ownerDisplay = [string]$Owner.DisplayName
    $ownerId = [string]$Owner.Id

    $queue = [System.Collections.Generic.Queue[object]]::new()
    $queue.Enqueue([PSCustomObject]@{
            ItemId           = 'root'
            ItemPath         = '\'
            Depth            = 0
            CheckPermissions = $true
            StopUnder        = $false
        })

    while ($queue.Count -gt 0) {
        $levelCount = $queue.Count
        $levelNodes = [System.Collections.Generic.List[object]]::new()
        for ($i = 0; $i -lt $levelCount; $i++) {
            $levelNodes.Add($queue.Dequeue())
        }

        $permRequests = [System.Collections.Generic.List[object]]::new()
        foreach ($node in $levelNodes) {
            if (-not $node.CheckPermissions) { continue }
            $reqUrl = if ($node.ItemId -eq 'root') {
                "/users/$userKey/drive/root/permissions"
            }
            else {
                "/users/$userKey/drive/items/$($node.ItemId)/permissions"
            }
            $permRequests.Add([PSCustomObject]@{
                    Id     = [string]$node.ItemId
                    Method = 'GET'
                    Url    = $reqUrl
                    Node   = $node
                })
        }

        $permByItem = @{}
        if ($permRequests.Count -gt 0) {
            try {
                $batchResults = Invoke-GraphBatchRequest -Requests @($permRequests | ForEach-Object {
                        [PSCustomObject]@{ Id = $_.Id; Method = $_.Method; Url = $_.Url }
                    })
            }
            catch {
                $batchResults = @{}
                # Fallback: sequential for this level
                foreach ($req in $permRequests) {
                    try {
                        $absolute = "https://graph.microsoft.com/v1.0$($req.Url)"
                        $body = Invoke-MgGraphRequest -Method GET -Uri $absolute -ErrorAction Stop
                        $batchResults[$req.Id] = [PSCustomObject]@{ Id = $req.Id; Status = 200; Body = $body }
                    }
                    catch {
                        if ($_.Exception.Message -match '(?i)429|throttl') {
                            Start-Sleep -Seconds 2
                        }
                    }
                }
            }

            foreach ($req in $permRequests) {
                $entry = $batchResults[$req.Id]
                if (-not $entry -or $entry.Status -lt 200 -or $entry.Status -ge 300) { continue }
                $value = Get-GraphObjectProperty -Object $entry.Body -PropertyName 'value'
                $permByItem[$req.Id] = @($value)
            }
        }

        foreach ($node in $levelNodes) {
            $explicitShareHit = $false
            if ($node.CheckPermissions -and $permByItem.ContainsKey([string]$node.ItemId)) {
                foreach ($permission in @($permByItem[[string]$node.ItemId])) {
                    if (Test-GraphPermissionIsInherited -Permission $permission) { continue }
                    foreach ($grant in @(Get-GraphPermissionDirectShareGrants -Permission $permission)) {
                        $matched = Resolve-TargetUserFromIndex -TargetIndex $TargetIndex `
                            -PrincipalId $grant.PrincipalId -DisplayName $grant.Grantee -UpnOrMail $grant.Email
                        if ($null -eq $matched) { continue }
                        if ([string]$matched.Id -ieq $ownerId) { continue }

                        $name = if ($node.ItemPath -eq '\') { "OneDrive root ($ownerUpn)" } else { $node.ItemPath }
                        $strength = Get-PermissionStrengthFromRoles -Permission $permission
                        $evidence = "Reverse OneDrive ACL share root (non-inherited); owner=$ownerUpn; $($grant.Detail) @ $($node.ItemPath)"
                        $hits.Add([PSCustomObject]@{
                                MatchedId          = [string]$matched.Id
                                MatchedDisplayName = [string]$matched.DisplayName
                                MatchedUpn         = [string]$matched.UserPrincipalName
                                MatchedMail        = [string]$matched.Mail
                                OwnerId            = $ownerId
                                OwnerUpn           = $ownerUpn
                                OwnerDisplayName   = $ownerDisplay
                                DriveId            = $DriveId
                                ItemId             = [string]$node.ItemId
                                ItemPath           = $name
                                Strength           = $strength
                                Evidence           = $evidence
                            })
                        $explicitShareHit = $true
                    }
                }
            }

            # Shared folder root: do not descend (children inherit). Root may still have nested shares.
            if ($explicitShareHit -and $node.ItemId -ne 'root') { continue }
            if ($node.Depth -ge $MaxDepth) { continue }

            try {
                $children = @(Get-GraphUserDriveChildren -UserId $ownerId -ItemId $node.ItemId -Select 'id,name,folder,shared')
            }
            catch {
                if ($_.Exception.Message -match '(?i)429|throttl') {
                    Start-Sleep -Seconds 2
                    try {
                        $children = @(Get-GraphUserDriveChildren -UserId $ownerId -ItemId $node.ItemId -Select 'id,name,folder,shared')
                    }
                    catch { continue }
                }
                else { continue }
            }

            foreach ($child in $children) {
                if (-not (Get-GraphObjectProperty -Object $child -PropertyName 'folder')) { continue }
                if ($foldersScanned -ge $MaxFolders) {
                    $capReached = $true
                    break
                }

                $foldersScanned++
                $childId = [string](Get-GraphObjectProperty -Object $child -PropertyName 'id')
                $childName = [string](Get-GraphObjectProperty -Object $child -PropertyName 'name')
                if (-not $childId) { continue }
                $childPath = if ($node.ItemPath -eq '\') { $childName } else { Join-Path $node.ItemPath $childName }
                $hasShared = Test-DriveItemHasSharedFacet -DriveItem $child

                $queue.Enqueue([PSCustomObject]@{
                        ItemId           = $childId
                        ItemPath         = $childPath
                        Depth            = ($node.Depth + 1)
                        CheckPermissions = $hasShared
                        StopUnder        = $false
                    })
            }
            if ($capReached) { break }
        }
        if ($capReached) { break }
    }

    return [PSCustomObject]@{
        FoldersScanned = $foldersScanned
        CapReached     = $capReached
        Hits           = @($hits)
    }
}

function Add-UserReachDirectGrantHits {
    param([object[]]$Hits)

    $added = 0
    foreach ($hit in @($Hits)) {
        if (-not $hit) { continue }
        $principal = [PSCustomObject]@{
            Id                = $hit.MatchedId
            DisplayName       = $hit.MatchedDisplayName
            UserPrincipalName = $hit.MatchedUpn
            Mail              = $hit.MatchedMail
        }
        $resourceId = "driveitem:$($hit.DriveId):$($hit.ItemId)"
        $Script:UserReachSharedRows.Add((New-UserReachSharedRow -Principal $principal `
                    -Workload 'OneDrive' -ResourceType 'DriveItem' -ResourceId $resourceId `
                    -ResourceName $hit.ItemPath -AccessVia 'DirectGrant' -PermissionStrength $hit.Strength `
                    -SharerId $hit.OwnerId -SharerUpn $hit.OwnerUpn -SharerDisplayName $hit.OwnerDisplayName `
                    -Evidence $hit.Evidence))

        Add-ExposureNode -Id $hit.MatchedId -Type User -DisplayName $hit.MatchedDisplayName `
            -UserPrincipalName $hit.MatchedUpn -Mail $hit.MatchedMail
        Add-ExposureNode -Id $hit.OwnerId -Type User -DisplayName $hit.OwnerDisplayName `
            -UserPrincipalName $hit.OwnerUpn
        Add-ExposureNode -Id $resourceId -Type DriveItem -DisplayName $hit.ItemPath `
            -Extra "SharedBy=$($hit.OwnerUpn);ShareRoot=true"
        Add-ExposureEdge -SourceId $hit.MatchedId -TargetId $resourceId -EdgeType SharedWith `
            -Detail $hit.Evidence -Weight 8
        $added++
    }
    return $added
}

function Get-GraphDriveSearchItems {
    param(
        [Parameter(Mandatory)][string]$DriveUriPrefix,
        [Parameter(Mandatory)][string]$Query,
        [int]$MaxItems = 200
    )

    $encoded = [uri]::EscapeDataString($Query)
    # Drive-level search (not root/search) includes items shared with the drive owner (remoteItem).
    $uri = "$DriveUriPrefix/search(q='$encoded')?`$top=50"
    return @(Get-GraphPagedValueCollection -Uri $uri -MaxItems $MaxItems)
}

function Get-GraphMicrosoftSearchDriveItems {
    param([int]$MaxItems = 100)

    $body = @{
        requests = @(
            @{
                entityTypes = @('driveItem')
                query       = @{ queryString = 'isDocument=true OR isContainer=true' }
                from        = 0
                size        = [Math]::Min(100, $MaxItems)
                fields      = @('id', 'name', 'webUrl', 'createdBy', 'lastModifiedBy', 'parentReference')
            }
        )
    }

    try {
        $response = Invoke-MgGraphRequest -Method POST -Uri 'https://graph.microsoft.com/v1.0/search/query' `
            -Body ($body | ConvertTo-Json -Depth 6) -ContentType 'application/json' -ErrorAction Stop
    }
    catch {
        return @()
    }

    $hits = [System.Collections.Generic.List[object]]::new()
    foreach ($container in @((Get-GraphObjectProperty -Object $response -PropertyName 'value'))) {
        foreach ($containerHits in @((Get-GraphObjectProperty -Object $container -PropertyName 'hitsContainers'))) {
            foreach ($hit in @((Get-GraphObjectProperty -Object $containerHits -PropertyName 'hits'))) {
                $resource = Get-GraphObjectProperty -Object $hit -PropertyName 'resource'
                if ($resource) { $hits.Add($resource) }
                if ($hits.Count -ge $MaxItems) { return @($hits) }
            }
        }
    }
    return @($hits)
}

function Test-DriveItemLooksSharedIn {
    param($DriveItem)

    if (Get-GraphObjectProperty -Object $DriveItem -PropertyName 'remoteItem') { return $true }
    $shared = Get-GraphObjectProperty -Object $DriveItem -PropertyName 'shared'
    if ($shared) { return $true }
    $parent = Get-GraphObjectProperty -Object $DriveItem -PropertyName 'parentReference'
    $driveType = [string](Get-GraphObjectProperty -Object $parent -PropertyName 'driveType')
    # Items from another user's personal drive often appear via search with remoteItem; if absent,
    # treat documentLibrary/business items with a distinct shareId as shared-in.
    $shareId = [string](Get-GraphObjectProperty -Object (Get-GraphObjectProperty -Object $DriveItem -PropertyName 'sharepointIds') -PropertyName 'listItemUniqueId')
    if ($driveType -and $driveType -ne 'personal' -and $shareId) { return $true }
    return $false
}

function Collect-UserReachAccessibleSharedItems {
    param([Parameter(Mandatory)]$Principal)

    # When the operator is the scoped user, discover inbound shares via APIs that work with
    # delegated Files.Read.All (search/recent/search-API). Reverse ACL of other users' OneDrives
    # often returns 0 drives because delegated tokens cannot open arbitrary personal drives.
    if (-not (Test-SignedInUserMatchesPrincipal -Principal $Principal)) {
        return 0
    }

    $meDrive = Get-GraphUserDrive -User $Principal -PreferMe
    if (-not $meDrive.DriveId) {
        return 0
    }

    $added = 0
    $seen = @{}
    $candidates = [System.Collections.Generic.List[object]]::new()

    foreach ($q in @('.', 'e', 'a', 'the', 'doc', 'folder', 'shared')) {
        try {
            foreach ($item in @(Get-GraphDriveSearchItems -DriveUriPrefix 'https://graph.microsoft.com/v1.0/me/drive' -Query $q -MaxItems 100)) {
                $candidates.Add($item)
            }
        }
        catch { }
    }

    try {
        foreach ($item in @(Get-GraphPagedValueCollection -Uri 'https://graph.microsoft.com/v1.0/me/drive/recent?$top=50' -MaxItems 100)) {
            $candidates.Add($item)
        }
    }
    catch { }

    foreach ($item in @(Get-GraphMicrosoftSearchDriveItems -MaxItems 100)) {
        $candidates.Add($item)
    }

    foreach ($item in $candidates) {
        $remote = Get-GraphObjectProperty -Object $item -PropertyName 'remoteItem'
        $parent = Get-GraphObjectProperty -Object $remote -PropertyName 'parentReference'
        if (-not $parent) { $parent = Get-GraphObjectProperty -Object $item -PropertyName 'parentReference' }
        $driveId = [string](Get-GraphObjectProperty -Object $parent -PropertyName 'driveId')
        $itemId = [string](Get-GraphObjectProperty -Object $remote -PropertyName 'id')
        if (-not $itemId) { $itemId = [string](Get-GraphObjectProperty -Object $item -PropertyName 'id') }

        $isRemote = $null -ne $remote
        $hasSharedFacet = $null -ne (Get-GraphObjectProperty -Object $item -PropertyName 'shared')
        $isOtherDrive = $driveId -and ($driveId -ine $meDrive.DriveId)
        if (-not ($isRemote -or $hasSharedFacet -or $isOtherDrive)) { continue }

        $key = if ($driveId -and $itemId) { "${driveId}:${itemId}" } else { [string](Get-GraphObjectProperty -Object $item -PropertyName 'webUrl') }
        if (-not $key -or $seen.ContainsKey($key)) { continue }
        $seen[$key] = $true

        Add-UserReachSharedDriveItem -Principal $Principal -DriveItem $item -AccessVia 'AccessibleShare' `
            -EvidencePrefix 'Graph /me search|recent|microsoftSearch (shared/remote item)'
        $added++
    }

    Write-AuditLog "  Accessible-share discovery (/me search/recent/Search API): $added inbound item(s)."
    return $added
}

function Invoke-ParallelUserReachDriveScans {
    param(
        [Parameter(Mandatory)][object[]]$WorkItems,
        [Parameter(Mandatory)][hashtable]$TargetIndex,
        [int]$MaxDepth,
        [int]$MaxFolders,
        [int]$Throttle = 4
    )

    if ($WorkItems.Count -eq 0) { return @() }

    $funcNames = @(
        'Get-GraphObjectProperty',
        'Invoke-GraphBatchRequest',
        'Get-GraphUserDriveChildren',
        'Test-GraphPermissionIsInherited',
        'Get-GraphPermissionDirectShareGrants',
        'Get-PermissionStrengthFromRoles',
        'Test-DriveItemHasSharedFacet',
        'Resolve-TargetUserFromIndex',
        'Invoke-UserReachOwnerDriveGrantScan'
    )

    $iss = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
    try { $iss.ImportPSModule('Microsoft.Graph.Authentication') } catch { }

    foreach ($name in $funcNames) {
        $cmd = Get-Command -Name $name -ErrorAction Stop
        $iss.Commands.Add([System.Management.Automation.Runspaces.SessionStateFunctionEntry]::new($name, $cmd.Definition))
    }

    $pool = [runspacefactory]::CreateRunspacePool(1, [Math]::Max(1, $Throttle), $iss, $Host)
    $pool.Open()

    $jobs = [System.Collections.Generic.List[object]]::new()
    try {
        foreach ($item in $WorkItems) {
            $ps = [powershell]::Create()
            $ps.RunspacePool = $pool
            [void]$ps.AddScript({
                    param($Owner, $DriveId, $TargetIndex, $MaxDepth, $MaxFolders)
                    try {
                        $scan = Invoke-UserReachOwnerDriveGrantScan -Owner $Owner -DriveId $DriveId `
                            -TargetIndex $TargetIndex -MaxDepth $MaxDepth -MaxFolders $MaxFolders
                        return [PSCustomObject]@{ Ok = $true; Scan = $scan; Error = '' }
                    }
                    catch {
                        return [PSCustomObject]@{ Ok = $false; Scan = $null; Error = $_.Exception.Message }
                    }
                }).AddArgument($item.Owner).AddArgument($item.DriveId).AddArgument($TargetIndex).AddArgument($MaxDepth).AddArgument($MaxFolders)

            $jobs.Add([PSCustomObject]@{
                    PS         = $ps
                    Handle     = $ps.BeginInvoke()
                    Label      = [string]$item.Label
                    Completed  = $false
                    Output     = $null
                })
        }

        $activity = 'User reach reverse OneDrive grants'
        $done = 0
        $total = $jobs.Count
        $outputs = [System.Collections.Generic.List[object]]::new()
        while ($done -lt $total) {
            Start-Sleep -Milliseconds 250
            foreach ($job in $jobs) {
                if ($job.Completed) { continue }
                if (-not $job.Handle.IsCompleted) { continue }

                $job.Completed = $true
                $done++
                try {
                    $raw = @($job.PS.EndInvoke($job.Handle))
                    $job.Output = if ($raw.Count -gt 0) { $raw[-1] } else { $null }
                }
                catch {
                    $job.Output = [PSCustomObject]@{ Ok = $false; Scan = $null; Error = $_.Exception.Message }
                }
                finally {
                    $job.PS.Dispose()
                }
                $outputs.Add([PSCustomObject]@{ Label = $job.Label; Result = $job.Output })
                Write-AuditProgress -Activity $activity -Current $done -Total $total
            }
        }
        return @($outputs)
    }
    finally {
        Complete-AuditProgress -Activity 'User reach reverse OneDrive grants'
        $pool.Close()
        $pool.Dispose()
    }
}

function Collect-UserReachIncomingDirectGrants {
    param([int]$MaxOwnerDrives = 100)

    $Script:RunCoverage.UserReachOwnerDrivesScanned = 0
    $Script:RunCoverage.UserReachDirectGrantCount = 0
    $Script:RunCoverage.UserReachFoldersScanned = 0
    $driveFailures = 0
    $grantHits = 0
    $foldersTotal = 0

    try {
        $owners = @(Get-MgUser -All -Filter "accountEnabled eq true" -Property 'id,displayName,userPrincipalName,mail' -ErrorAction Stop)
    }
    catch {
        Write-AuditLog "User list for reverse OneDrive grant scan failed: $($_.Exception.Message)" Warn
        return 0
    }

    # Inbound shares live on other people's drives — skip scoped targets.
    $targetIds = @($Script:TargetUsers | ForEach-Object { [string]$_.Id } | Where-Object { $_ })
    $owners = @($owners | Where-Object { $targetIds -notcontains [string]$_.Id })
    Write-AuditLog "  Reverse OneDrive grant scan candidate owners: $($owners.Count) (targets excluded)."
    if ($owners.Count -eq 0) { return 0 }

    if ($MaxOwnerDrives -gt 0 -and $owners.Count -gt $MaxOwnerDrives) {
        $owners = @($owners | Select-Object -First $MaxOwnerDrives)
        Write-AuditLog "  Reverse OneDrive grant scan capped to $($owners.Count) owner drive(s) (UserReachMaxOwnerDrives=$MaxOwnerDrives)."
    }

    $targetIndex = @{}
    foreach ($key in @($Script:TargetUserIndex.Keys)) {
        $targetIndex[$key] = $Script:TargetUserIndex[$key]
    }

    # Open drives on the main thread (auth-safe), then scan up to 4 drives in parallel.
    $openActivity = 'User reach reverse OneDrive open drives'
    $workItems = [System.Collections.Generic.List[object]]::new()
    $oi = 0
    try {
        foreach ($owner in $owners) {
            $oi++
            Write-AuditProgress -Activity $openActivity -Current $oi -Total $owners.Count
            $label = if ($owner.UserPrincipalName) { [string]$owner.UserPrincipalName } else { [string]$owner.Id }
            $driveInfo = Get-GraphUserDrive -User $owner
            $driveId = [string]$driveInfo.DriveId
            if (-not $driveId) {
                $driveFailures++
                continue
            }
            $workItems.Add([PSCustomObject]@{
                    Owner   = $owner
                    DriveId = $driveId
                    Label   = $label
                })
        }
    }
    finally {
        Complete-AuditProgress -Activity $openActivity
    }

    Write-AuditLog "  Reverse OneDrive drives opened: $($workItems.Count); open failures: $driveFailures. Scanning (depth=$UserReachReverseMaxDepth, maxFolders=$UserReachReverseMaxFolders, parallel=4)..."

    $scanResults = @()
    if ($workItems.Count -gt 0) {
        $useSequential = $false
        try {
            $scanResults = @(Invoke-ParallelUserReachDriveScans -WorkItems @($workItems) `
                    -TargetIndex $targetIndex -MaxDepth $UserReachReverseMaxDepth `
                    -MaxFolders $UserReachReverseMaxFolders -Throttle 4)
            $okCount = @($scanResults | Where-Object { $_.Result -and $_.Result.Ok }).Count
            if ($okCount -eq 0 -and $workItems.Count -gt 0) {
                Write-AuditLog '  Parallel reverse scan returned 0 successful drives; falling back to sequential.' Warn
                $useSequential = $true
            }
        }
        catch {
            Write-AuditLog "  Parallel reverse scan failed ($($_.Exception.Message)); falling back to sequential." Warn
            $useSequential = $true
        }

        if ($useSequential) {
            $scanResults = @()
            $activity = 'User reach reverse OneDrive grants'
            $si = 0
            try {
                foreach ($item in $workItems) {
                    $si++
                    Write-AuditProgress -Activity $activity -Current $si -Total $workItems.Count
                    try {
                        $scan = Invoke-UserReachOwnerDriveGrantScan -Owner $item.Owner -DriveId $item.DriveId `
                            -TargetIndex $targetIndex -MaxDepth $UserReachReverseMaxDepth -MaxFolders $UserReachReverseMaxFolders
                        $scanResults += [PSCustomObject]@{
                            Label  = $item.Label
                            Result = [PSCustomObject]@{ Ok = $true; Scan = $scan; Error = '' }
                        }
                    }
                    catch {
                        $scanResults += [PSCustomObject]@{
                            Label  = $item.Label
                            Result = [PSCustomObject]@{ Ok = $false; Scan = $null; Error = $_.Exception.Message }
                        }
                    }
                }
            }
            finally {
                Complete-AuditProgress -Activity $activity
            }
        }
    }

    foreach ($entry in $scanResults) {
        $result = $entry.Result
        if (-not $result -or -not $result.Ok -or -not $result.Scan) { continue }
        $Script:RunCoverage.UserReachOwnerDrivesScanned++
        $foldersTotal += [int]$result.Scan.FoldersScanned
        $grantHits += [int](Add-UserReachDirectGrantHits -Hits @($result.Scan.Hits))
    }

    $Script:RunCoverage.UserReachDirectGrantCount = $grantHits
    $Script:RunCoverage.UserReachFoldersScanned = $foldersTotal

    if ($driveFailures -gt 0) {
        Write-AuditLog "  Reverse OneDrive grant scan: $($Script:RunCoverage.UserReachOwnerDrivesScanned) drive(s) scanned, $driveFailures open failure(s), $foldersTotal folder(s), $grantHits grant hit(s)." Warn
        if ($Script:GraphAuthMode -eq 'AppOnly') {
            Write-AuditLog '  Note: Some OneDrives were unprovisioned or inaccessible under app-only Graph.' Warn
        }
        else {
            Write-AuditLog '  Note: Delegated Graph cannot open arbitrary personal OneDrives. Prefer -GraphAppId app-only.' Warn
        }
    }
    else {
        Write-AuditLog "  Reverse OneDrive grant scan: $($Script:RunCoverage.UserReachOwnerDrivesScanned) drive(s), $foldersTotal folder(s), $grantHits grant hit(s)."
    }
    return $grantHits
}

function Collect-UserReachMap {
    $Script:UserReachSharedRows.Clear()
    $Script:RunCoverage.UserReachSharedWithMeOk = $false
    $Script:RunCoverage.UserReachItemCount = 0
    $Script:RunCoverage.UserReachGraphEdgeCount = 0
    $Script:RunCoverage.UserReachReverseAclSites = 0
    $Script:RunCoverage.UserReachOwnerDrivesScanned = 0
    $Script:RunCoverage.UserReachDirectGrantCount = 0
    $Script:RunCoverage.UserReachFoldersScanned = 0
    $Script:RunCoverage.UserReachLimitation = ''

    if ($SkipUserReachMap) {
        $Script:RunCoverage.UserReachMap = 'SkippedBySwitch'
        Write-AuditLog 'User reach map skipped (-SkipUserReachMap).'
        return
    }

    if (-not (Test-ShouldCollectUserReachMap)) {
        $Script:RunCoverage.UserReachMap = 'SkippedNoScope'
        Write-AuditLog 'User reach map skipped (no user scope; use -Users / -UserListPath / -CopilotLicensedOnly or -IncludeUserReachMap).'
        return
    }

    if (-not $Script:TargetUserScopeEnabled -or $Script:TargetUsers.Count -eq 0) {
        $Script:RunCoverage.UserReachMap = 'SkippedNoScope'
        Write-AuditLog 'User reach map skipped (IncludeUserReachMap set but no resolved target users).' Warn
        return
    }

    $Script:RunCoverage.UserReachMap = 'Ran'
    $limitations = [System.Collections.Generic.List[string]]::new()
    $sharedWithMeHitAny = $false
    $sharedWithMeFailAny = $false
    $sharedWithMeEmptyAny = $false
    $cappedAny = $false

    Write-AuditLog "Collecting user reach map for $($Script:TargetUsers.Count) scoped user(s)..."
    if ($Script:GraphAuthMode -eq 'AppOnly') {
        Write-AuditLog '  App-only mode: SharedWithMe skipped; using insights/shared + reverse OneDrive ACL.'
    }
    else {
        Write-AuditLog '  Note: Graph sharedWithMe is deprecated/degraded; empty results are common. Reverse OneDrive ACL scan follows.'
    }
    $activity = 'User reach inbound shares'
    $ui = 0
    try {
        foreach ($user in $Script:TargetUsers) {
            $ui++
            $label = if ($user.UserPrincipalName) { $user.UserPrincipalName } else { $user.Id }
            Write-AuditProgress -Activity $activity -Current $ui -Total $Script:TargetUsers.Count -CurrentOperation $label

            Add-ExposureNode -Id $user.Id -Type User -DisplayName $user.DisplayName `
                -UserPrincipalName $user.UserPrincipalName -Mail $user.Mail | Out-Null

            try {
                $items = @(Get-GraphSharedWithMeItems -Principal $user -MaxItems $UserReachMaxItems)
                if ($items.Count -ge $UserReachMaxItems) { $cappedAny = $true }
                if ($items.Count -eq 0) {
                    $sharedWithMeEmptyAny = $true
                }
                else {
                    $sharedWithMeHitAny = $true
                    foreach ($item in $items) {
                        Add-UserReachSharedDriveItem -Principal $user -DriveItem $item -AccessVia 'SharedWithMe'
                    }
                }
            }
            catch {
                $sharedWithMeFailAny = $true
                Write-AuditLog "  SharedWithMe failed for ${label}: $($_.Exception.Message)" Warn
            }

            $insights = @(Get-GraphUserInsightsSharedItems -UserId $user.Id -MaxItems $UserReachMaxItems)
            foreach ($insight in $insights) {
                Add-UserReachInsightSharedItem -Principal $user -Insight $insight
            }

            # Best path when auditing yourself: search/recent see remoteItem shares SharedWithMe misses.
            [void](Collect-UserReachAccessibleSharedItems -Principal $user)
        }
    }
    finally {
        Complete-AuditProgress -Activity $activity
    }

    $Script:RunCoverage.UserReachSharedWithMeOk = $sharedWithMeHitAny
    $sharedWithMeCount = @($Script:UserReachSharedRows | Where-Object { $_.AccessVia -eq 'SharedWithMe' }).Count
    $accessibleCount = @($Script:UserReachSharedRows | Where-Object { $_.AccessVia -eq 'AccessibleShare' }).Count
    $Script:RunCoverage.UserReachItemCount = $sharedWithMeCount + $accessibleCount

    # Secondary path: reverse ACL on owner drives the signed-in user can open (often few/none).
    [void](Collect-UserReachIncomingDirectGrants -MaxOwnerDrives $UserReachMaxOwnerDrives)

    if ($UserReachReverseSiteAcl) {
        $Script:RunCoverage.UserReachReverseAclSites = Collect-UserReachReverseSiteAcl -TargetUsers @($Script:TargetUsers) -MaxSites 20
        if ($Script:RunCoverage.UserReachReverseAclSites -eq 0 -and -not $Script:SpoAvailable) {
            [void]$limitations.Add('Reverse site ACL requested but SharePoint Online module/session unavailable.')
        }
    }

    if ($sharedWithMeFailAny) {
        [void]$limitations.Add('SharedWithMe failed for one or more scoped users.')
    }
    if ($sharedWithMeEmptyAny -and -not $sharedWithMeHitAny) {
        [void]$limitations.Add('SharedWithMe returned 0 items (deprecated/degraded Graph API). Used /me search|recent and reverse ACL fallbacks.')
        if ($accessibleCount -eq 0 -and $Script:RunCoverage.UserReachDirectGrantCount -eq 0) {
            $Script:RunCoverage.UserReachMap = 'Partial'
        }
    }
    if ($Script:RunCoverage.UserReachOwnerDrivesScanned -eq 0) {
        if ($Script:GraphAuthMode -eq 'AppOnly') {
            [void]$limitations.Add('Reverse OneDrive ACL opened 0 owner drives under app-only Graph. Verify application Files.Read.All / Sites.Read.All admin consent and that target users have provisioned OneDrive.')
        }
        else {
            [void]$limitations.Add('Reverse OneDrive ACL opened 0 owner drives (delegated Graph cannot open arbitrary personal OneDrives). Use -GraphAppId app-only auth, or sign in as the scoped user for /me search discovery.')
        }
    }
    if ($cappedAny) {
        [void]$limitations.Add("SharedWithMe capped at $UserReachMaxItems item(s) per user.")
    }
    if ($UserReachMaxOwnerDrives -gt 0) {
        [void]$limitations.Add("Reverse OneDrive grant scan finds folder share roots (shared facet + non-inherited grants) on up to $UserReachMaxOwnerDrives owner drives (depth=$UserReachReverseMaxDepth, maxFolders=$UserReachReverseMaxFolders, parallel=4); skips target-owned drives and inherited children.")
    }
    $Script:RunCoverage.UserReachLimitation = ($limitations -join ' ')

    Write-AuditLog "  User reach rows: $($Script:UserReachSharedRows.Count) (SharedWithMe=$sharedWithMeCount; DirectGrant=$($Script:RunCoverage.UserReachDirectGrantCount); reverse sites=$($Script:RunCoverage.UserReachReverseAclSites))."
}
#endregion

#region Aggregation + export
function Clear-AuditFindings {
    $Script:Findings.Clear()
    $Script:FindingIndex = @{}
}

function Add-AuditFinding {
    param(
        [Parameter(Mandatory)][string]$Workload,
        [Parameter(Mandatory)][string]$ResourceType,
        [Parameter(Mandatory)][string]$ResourceId,
        [Parameter(Mandatory)][string]$ResourceName,
        [Parameter(Mandatory)][string]$PrincipalId,
        [string]$PrincipalUpn = '',
        [Parameter(Mandatory)][string]$Permission,
        [Parameter(Mandatory)][string]$PermissionStrength,
        [int]$FanIn = 0,
        [string]$SensitivityHint = '',
        [ValidateSet('Expected', 'Unexpected', 'Unknown')]
        [string]$BaselineStatus = 'Unknown',
        [ValidateSet('Critical', 'High', 'Medium', 'Low')]
        [string]$Severity,
        [Parameter(Mandatory)][string]$CopilotImpact,
        [Parameter(Mandatory)][string]$Recommendation,
        [Parameter(Mandatory)][string]$Evidence
    )

    $dedupeKey = '{0}|{1}|{2}|{3}' -f $Workload, $ResourceId, $PrincipalId, $Permission
    if ($Script:FindingIndex.ContainsKey($dedupeKey)) {
        return $Script:FindingIndex[$dedupeKey]
    }

    $finding = [PSCustomObject][ordered]@{
        Workload           = $Workload
        ResourceType       = $ResourceType
        ResourceId         = $ResourceId
        ResourceName       = $ResourceName
        PrincipalId        = $PrincipalId
        PrincipalUpn       = $PrincipalUpn
        Permission         = $Permission
        PermissionStrength = $PermissionStrength
        FanIn              = $FanIn
        SensitivityHint    = $SensitivityHint
        BaselineStatus     = $BaselineStatus
        Severity           = $Severity
        CopilotImpact      = $CopilotImpact
        Recommendation     = $Recommendation
        Evidence           = $Evidence
    }
    $Script:Findings.Add($finding)
    $Script:FindingIndex[$dedupeKey] = $finding
    return $finding
}

function Get-AuditFindings {
    $severityOrder = @{ Critical = 0; High = 1; Medium = 2; Low = 3 }
    return @(
        $Script:Findings |
            Sort-Object @{ Expression = { $severityOrder[$_.Severity] } }, `
                @{ Expression = 'FanIn'; Descending = $true }, ResourceName, Permission
    )
}

function Export-FindingsCsv {
    param([Parameter(Mandatory)][string]$RunFolder)

    $path = Join-Path $RunFolder 'findings.csv'
    $findings = @(Get-AuditFindings)
    if ($findings.Count -eq 0) {
        [System.IO.File]::WriteAllText(
            $path,
            (($Script:FindingColumns -join ',') + [Environment]::NewLine),
            [System.Text.UTF8Encoding]::new($false)
        )
    }
    else {
        $findings | Select-Object $Script:FindingColumns | Export-Csv -Path $path -NoTypeInformation -Encoding UTF8
    }
    return $path
}

function Get-FindingSensitivityHint {
    param($Node)

    if ($null -eq $Node) { return '' }
    $signals = @($Node.DisplayName, $Node.RiskFlags, $Node.Extra) -join ' '
    if ($signals -match $Script:SensitiveNamePatternRegex -or $signals -match '(?i)\b(restricted|secret|sensitive)\b') {
        return 'Name or collector metadata indicates sensitive content'
    }
    return ''
}

function Import-AccessBaseline {
    param([string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path)) { return @() }
    $resolvedPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)
    if (-not (Test-Path -LiteralPath $resolvedPath)) {
        throw "Baseline CSV not found: $resolvedPath"
    }

    $rows = @(Import-Csv -LiteralPath $resolvedPath)
    foreach ($row in $rows) {
        foreach ($column in @('UserPrincipalName', 'ResourceType', 'ResourceId', 'ExpectedRole')) {
            $property = $row.PSObject.Properties | Where-Object { $_.Name -ieq $column } | Select-Object -First 1
            if (-not $property -or [string]::IsNullOrWhiteSpace([string]$property.Value)) {
                throw "Baseline CSV row is missing required '$column': $resolvedPath"
            }
        }
    }

    return @(
        $rows | ForEach-Object {
            [PSCustomObject]@{
                UserPrincipalName = ([string]$_.UserPrincipalName).Trim()
                ResourceType      = ([string]$_.ResourceType).Trim()
                ResourceId        = ([string]$_.ResourceId).Trim()
                ExpectedRole      = ([string]$_.ExpectedRole).Trim()
            }
        }
    )
}

function Test-BaselineResourceMatch {
    param(
        [Parameter(Mandatory)]$BaselineRow,
        [string]$ResourceId,
        [string]$ResourceName
    )

    $baselineResource = [string]$BaselineRow.ResourceId
    return (
        $ResourceId -eq $baselineResource -or
        $ResourceName -eq $baselineResource -or
        ($ResourceName -and $ResourceName -like "*$baselineResource*") -or
        ($ResourceId -and $ResourceId -like "*$baselineResource*")
    )
}

function Get-MembershipBaselineStatus {
    param(
        [Parameter(Mandatory)]$Edge,
        [Parameter(Mandatory)][string]$ResourceType,
        [Parameter(Mandatory)][string]$ResourceId,
        [Parameter(Mandatory)][string]$ResourceName,
        [Parameter(Mandatory)][string]$Permission
    )

    if (-not $Script:RunCoverage.BaselineLoaded) { return 'Unknown' }
    $principalUpn = [string]$Edge.SourceUserPrincipalName
    if (-not $principalUpn -and $Script:NodeIndex.ContainsKey($Edge.SourceId)) {
        $principalUpn = [string]$Script:NodeIndex[$Edge.SourceId].UserPrincipalName
    }
    if (-not $principalUpn) { return 'Unknown' }

    foreach ($row in $Script:AccessBaseline) {
        if (
            $row.UserPrincipalName -ieq $principalUpn -and
            $row.ResourceType -ieq $ResourceType -and
            $row.ExpectedRole -ieq $Permission -and
            (Test-BaselineResourceMatch -BaselineRow $row -ResourceId $ResourceId -ResourceName $ResourceName)
        ) {
            return 'Expected'
        }
    }
    return 'Unexpected'
}

function Get-ElevatedFindingSeverity {
    param(
        [Parameter(Mandatory)][ValidateSet('Critical', 'High', 'Medium', 'Low')][string]$Severity,
        [string]$BaselineStatus = 'Unknown',
        [string]$SensitivityHint = ''
    )

    # Start at base severity; elevate one band per trigger (Unexpected, then SensitivityHint), capped at Critical.
    $result = $Severity
    if ($BaselineStatus -eq 'Unexpected') {
        $result = switch ($result) {
            'Low' { 'Medium' }
            'Medium' { 'High' }
            'High' { 'Critical' }
            default { 'Critical' }
        }
    }
    if ($SensitivityHint -and $result -ne 'Critical') {
        $result = switch ($result) {
            'Low' { 'Medium' }
            'Medium' { 'High' }
            'High' { 'Critical' }
            default { 'Critical' }
        }
    }
    return $result
}

function Get-FindingResourceRow {
    param(
        [hashtable]$ResourceIndex,
        [string]$ResourceId
    )

    if ($ResourceIndex.ContainsKey($ResourceId)) {
        return $ResourceIndex[$ResourceId]
    }
    return $null
}

function Build-FindingsFromGraph {
    param([object[]]$ResourceRows)

    Clear-AuditFindings
    $resourceIndex = @{}
    foreach ($row in @($ResourceRows)) {
        $resourceIndex[$row.ResourceId] = $row
    }

    foreach ($edge in @($Script:Edges | Where-Object { $_.EdgeType -in @('MemberOf', 'TeamMember', 'SiteRole') })) {
        $targetNode = if ($Script:NodeIndex.ContainsKey($edge.TargetId)) { $Script:NodeIndex[$edge.TargetId] } else { $null }
        if (-not $targetNode) { continue }

        $resourceName = if ($targetNode.DisplayName) { [string]$targetNode.DisplayName } else { [string]$edge.TargetDisplayName }
        $resourceType = switch ($edge.EdgeType) {
            'MemberOf' { 'Group' }
            'TeamMember' { 'Team' }
            default { 'Site' }
        }
        $workload = switch ($edge.EdgeType) {
            'MemberOf' { 'TeamsOrGroups' }
            'TeamMember' { 'Teams' }
            default { 'SharePoint' }
        }
        $permission = if ($edge.EdgeType -eq 'SiteRole' -and $edge.Detail -match '^(Owner|Member|Visitor)\b') {
            $Matches[1]
        }
        else {
            'Member'
        }
        $permissionStrength = switch ($permission) {
            'Owner' { 'FullControl' }
            'Member' { 'ReadWrite' }
            'Visitor' { 'Read' }
            default { 'Read' }
        }
        $baseSeverity = switch ($permission) {
            'Owner' { 'High' }
            'Member' { if ($edge.EdgeType -eq 'TeamMember') { 'Medium' } else { 'Low' } }
            'Visitor' { 'Low' }
            default { 'Low' }
        }
        $sensitivityHint = Get-FindingSensitivityHint -Node $targetNode
        $baselineStatus = Get-MembershipBaselineStatus -Edge $edge -ResourceType $resourceType `
            -ResourceId $edge.TargetId -ResourceName $resourceName -Permission $permission
        $severity = Get-ElevatedFindingSeverity -Severity $baseSeverity -BaselineStatus $baselineStatus `
            -SensitivityHint $sensitivityHint
        $principalUpn = if ($edge.SourceUserPrincipalName) {
            [string]$edge.SourceUserPrincipalName
        }
        elseif ($Script:NodeIndex.ContainsKey($edge.SourceId)) {
            [string]$Script:NodeIndex[$edge.SourceId].UserPrincipalName
        }
        else {
            ''
        }

        $null = Add-AuditFinding -Workload $workload -ResourceType $resourceType -ResourceId $edge.TargetId `
            -ResourceName $resourceName -PrincipalId $edge.SourceId -PrincipalUpn $principalUpn `
            -Permission $permission -PermissionStrength $permissionStrength -FanIn 1 `
            -SensitivityHint $sensitivityHint -BaselineStatus $baselineStatus -Severity $severity `
            -CopilotImpact 'This membership may allow Copilot to retrieve or summarize content available through the resource.' `
            -Recommendation 'Validate this membership against the approved access baseline and remove or narrow access where it is not required.' `
            -Evidence "$($edge.EdgeType) edge; $($edge.Detail)"
    }

    foreach ($edge in $Script:Edges) {
        $targetNode = if ($Script:NodeIndex.ContainsKey($edge.TargetId)) { $Script:NodeIndex[$edge.TargetId] } else { $null }
        $resource = Get-FindingResourceRow -ResourceIndex $resourceIndex -ResourceId $edge.TargetId
        $fanIn = if ($resource) { [int]$resource.PermissionFanIn } else { 1 }

        if ($edge.EdgeType -eq 'SitePrincipal') {
            $sensitivityHint = Get-FindingSensitivityHint -Node $targetNode
            $severity = if ($sensitivityHint) { 'Critical' } else { 'High' }
            $null = Add-AuditFinding -Workload 'SharePoint' -ResourceType 'Site' -ResourceId $edge.TargetId `
                -ResourceName $edge.TargetDisplayName -PrincipalId $edge.SourceId `
                -PrincipalUpn $edge.SourceUserPrincipalName -Permission 'EveryoneOrOrgWide' `
                -PermissionStrength 'Read' -FanIn $fanIn -SensitivityHint $sensitivityHint `
                -Severity $severity -CopilotImpact 'Copilot may retrieve content from this site for a broad tenant-wide principal.' `
                -Recommendation 'Review site membership and remove or narrow the Everyone or organization-wide grant.' `
                -Evidence "SitePrincipal edge; $($edge.Detail)"
            continue
        }

        if ($edge.EdgeType -eq 'SiteCapability') {
            $sensitivityHint = Get-FindingSensitivityHint -Node $targetNode
            $null = Add-AuditFinding -Workload 'SharePoint' -ResourceType 'Site' -ResourceId $edge.TargetId `
                -ResourceName $edge.TargetDisplayName -PrincipalId $edge.SourceId `
                -PrincipalUpn $edge.SourceUserPrincipalName -Permission 'ExternalSharing' `
                -PermissionStrength 'BroadLink' -FanIn $fanIn -SensitivityHint $sensitivityHint `
                -Severity 'High' -CopilotImpact 'External sharing capability increases the chance that Copilot-accessible site content is shared beyond intended users.' `
                -Recommendation 'Confirm external sharing is required and restrict the site sharing capability where it is not.' `
                -Evidence "SiteCapability edge; $($edge.Detail)"
            continue
        }

        if ($edge.EdgeType -eq 'DirectShareFanIn') {
            $ownerLabel = if ($targetNode) { [string]$targetNode.Extra } else { '' }
            $workload = if ($ownerLabel -match '(?i)^OneDrive:') { 'OneDrive' } else { 'SharePoint' }
            $directShareFanIn = if ($edge.Detail -match 'Distinct named user/group grants=(\d+)') { [int]$Matches[1] } else { $fanIn }
            $sensitivityHint = Get-FindingSensitivityHint -Node $targetNode
            $severity = if ($sensitivityHint -or $directShareFanIn -ge ($DirectShareFanInThreshold * 2)) { 'High' } else { 'Medium' }
            $null = Add-AuditFinding -Workload $workload -ResourceType 'DriveItem' -ResourceId $edge.TargetId `
                -ResourceName $edge.TargetDisplayName -PrincipalId $edge.SourceId `
                -PrincipalUpn '' -Permission 'DirectShareFanIn' -PermissionStrength 'NamedGrant' `
                -FanIn $directShareFanIn -SensitivityHint $sensitivityHint -Severity $severity `
                -CopilotImpact 'A large set of named users or groups can retrieve this sampled item, increasing the content population Copilot may access.' `
                -Recommendation 'Review the named recipients and groups, remove obsolete grants, and replace broad collaboration access with the least privilege required.' `
                -Evidence "DirectShareFanIn edge; owner=$ownerLabel; $($edge.Detail)"
            continue
        }

        if ($edge.EdgeType -eq 'BroadShare') {
            # Owner-reach edges model the owner's graph reach; they are not a sharing grant.
            if ([string]$edge.Detail -match '(?i)^\s*Owner reach:') {
                continue
            }
            $ownerLabel = if ($targetNode) { [string]$targetNode.Extra } else { '' }
            $workload = if ($ownerLabel -match '(?i)^OneDrive:') { 'OneDrive' } else { 'SharePoint' }
            $scope = if ($edge.SourceId -match '(?i)anonymous' -or $edge.Detail -match '(?i)scope:\s*anonymous') {
                'AnonymousLink'
            }
            elseif ($edge.SourceId -match '(?i)organization' -or $edge.Detail -match '(?i)scope:\s*organization') {
                'OrganizationLink'
            }
            else {
                'EveryoneOrOrgWide'
            }
            $sensitivityHint = Get-FindingSensitivityHint -Node $targetNode
            $severity = if ($sensitivityHint -and $scope -in @('AnonymousLink', 'EveryoneOrOrgWide', 'OrganizationLink')) { 'Critical' } else { 'High' }
            $null = Add-AuditFinding -Workload $workload -ResourceType 'DriveItem' -ResourceId $edge.TargetId `
                -ResourceName $edge.TargetDisplayName -PrincipalId $edge.SourceId `
                -PrincipalUpn $edge.SourceUserPrincipalName -Permission $scope `
                -PermissionStrength 'BroadLink' -FanIn $fanIn -SensitivityHint $sensitivityHint `
                -Severity $severity -CopilotImpact 'Copilot may retrieve this sampled item because it has an organization-wide or anonymous sharing grant.' `
                -Recommendation 'Remove the broad sharing link or replace it with named recipients and the least privilege required.' `
                -Evidence "BroadShare edge; owner=$ownerLabel; $($edge.Detail)"
        }
    }

    foreach ($row in @($ResourceRows | Where-Object { $_.Type -eq 'Site' })) {
        $siteRoleEdges = @($Script:Edges | Where-Object { $_.TargetId -eq $row.ResourceId -and $_.EdgeType -eq 'SiteRole' })
        $ownerRoleEdges = @($siteRoleEdges | Where-Object { $_.Detail -match '(?i)^Owner\s+role|^Owner\s+via' })
        $ownerFanIn = @($ownerRoleEdges | Select-Object -ExpandProperty SourceId -Unique).Count
        if ($ownerFanIn -ge $Script:SiteRoleOwnerFanInFindingThreshold) {
            $targetNode = if ($Script:NodeIndex.ContainsKey($row.ResourceId)) { $Script:NodeIndex[$row.ResourceId] } else { $null }
            $sensitivityHint = Get-FindingSensitivityHint -Node $targetNode
            $severity = if ($sensitivityHint -or $ownerFanIn -ge ($Script:SiteRoleOwnerFanInFindingThreshold * 2)) { 'High' } else { 'Medium' }
            $null = Add-AuditFinding -Workload 'SharePoint' -ResourceType 'Site' -ResourceId $row.ResourceId `
                -ResourceName $row.DisplayName -PrincipalId 'siterole:owners:fanin' -Permission 'SiteRoleOwnerFanIn' `
                -PermissionStrength 'FullControl' -FanIn $ownerFanIn -SensitivityHint $sensitivityHint -Severity $severity `
                -CopilotImpact 'Multiple site owners can manage site permissions and access content that Copilot may retrieve or summarize.' `
                -Recommendation 'Validate site owners, remove obsolete ownership, and use Member or Visitor access where administration is not required.' `
                -Evidence "SiteRole Owner edges=$($ownerRoleEdges.Count); UniqueOwnerSources=$ownerFanIn; Threshold=$Script:SiteRoleOwnerFanInFindingThreshold"
        }

        # PnP role edges are more precise than flat Get-SPOUser membership. Do not double-count
        # equal-weight SiteMember fan-in when the site returned role evidence.
        if ($siteRoleEdges.Count -gt 0) { continue }
        $siteMemberEdges = @($Script:Edges | Where-Object { $_.TargetId -eq $row.ResourceId -and $_.EdgeType -eq 'SiteMember' })
        $siteMemberFanIn = @($siteMemberEdges | Select-Object -ExpandProperty SourceId -Unique).Count
        if ($siteMemberFanIn -lt $Script:SiteMemberFanInFindingThreshold) { continue }
        $null = Add-AuditFinding -Workload 'SharePoint' -ResourceType 'Site' -ResourceId $row.ResourceId `
            -ResourceName $row.DisplayName -PrincipalId 'sitemembers:fanin' -Permission 'SiteMemberFanIn' `
            -PermissionStrength 'Read' -FanIn $siteMemberFanIn -Severity 'Medium' `
            -CopilotImpact 'A large number of site members may be able to retrieve or summarize this site''s content with Copilot.' `
            -Recommendation 'Review site membership and remove inactive, unnecessary, or overly broad member access.' `
            -Evidence "SiteMember edges=$($siteMemberEdges.Count); UniqueSiteMemberSources=$siteMemberFanIn; Threshold=$Script:SiteMemberFanInFindingThreshold"
    }

    foreach ($row in @($ResourceRows | Where-Object { $_.Type -eq 'Mailbox' })) {
        $fullAccessEdges = @($Script:Edges | Where-Object { $_.TargetId -eq $row.ResourceId -and $_.EdgeType -eq 'MailboxDelegate' })
        $fullAccessFanIn = @($fullAccessEdges | Select-Object -ExpandProperty SourceId -Unique).Count
        $sendAsEdges = @($Script:Edges | Where-Object { $_.TargetId -eq $row.ResourceId -and $_.EdgeType -eq 'SendAs' })
        $sendAsFanIn = @($sendAsEdges | Select-Object -ExpandProperty SourceId -Unique).Count

        if ($fullAccessFanIn -ge 5) {
            $targetNode = if ($Script:NodeIndex.ContainsKey($row.ResourceId)) { $Script:NodeIndex[$row.ResourceId] } else { $null }
            $mailboxType = if ($targetNode -and $targetNode.Extra -match '(?i)(?:^|;)MailboxType=([^;]+)') { $Matches[1] } else { 'Other' }
            $recommendation = switch ($mailboxType) {
                'SharedMailbox' { 'Validate the shared mailbox delegate list, remove obsolete FullAccess, and use a dedicated shared mailbox with least-privilege access for team workflows.' }
                'UserMailbox' { 'Validate each user mailbox FullAccess delegate, remove obsolete access, and use narrower delegation where possible.' }
                default { 'Validate each FullAccess delegate and remove obsolete access; use narrower delegation where possible.' }
            }
            $sendAsEvidence = if ($sendAsFanIn -gt 0) { "; SendAs edges=$($sendAsEdges.Count); SendAsFanIn=$sendAsFanIn" } else { '' }
            $null = Add-AuditFinding -Workload 'Exchange' -ResourceType 'Mailbox' -ResourceId $row.ResourceId `
                -ResourceName $row.DisplayName -PrincipalId 'delegates:fullaccess' -Permission 'FullAccess' `
                -PermissionStrength 'FullAccess' -FanIn $fullAccessFanIn -Severity 'High' `
                -CopilotImpact 'Multiple FullAccess delegates can use Copilot to retrieve or summarize mailbox content.' `
                -Recommendation $recommendation `
                -Evidence "MailboxDelegate edges=$($fullAccessEdges.Count); FullAccessFanIn=$fullAccessFanIn; PermissionFanIn=$($row.PermissionFanIn); MailboxType=$mailboxType$sendAsEvidence"
            continue
        }

        if ($sendAsFanIn -ge 5) {
            $null = Add-AuditFinding -Workload 'Exchange' -ResourceType 'Mailbox' -ResourceId $row.ResourceId `
                -ResourceName $row.DisplayName -PrincipalId 'delegates:sendas' -Permission 'SendAsFanIn' `
                -PermissionStrength 'SendAs' -FanIn $sendAsFanIn -Severity 'Low' `
                -CopilotImpact 'SendAs does not itself grant mailbox content access, but a large trustee population increases the risk of unauthorized message impersonation.' `
                -Recommendation 'Review SendAs trustees, remove obsolete delegation, and restrict SendAs to approved business workflows.' `
                -Evidence "SendAs edges=$($sendAsEdges.Count); SendAsFanIn=$sendAsFanIn; FullAccessFanIn=$fullAccessFanIn; PermissionFanIn=$($row.PermissionFanIn)"
        }
    }

    foreach ($group in @($Script:Nodes | Where-Object { $_.Type -eq 'Group' })) {
        $flags = @($group.RiskFlags -split ',' | Where-Object { $_ -in @('MassExposure', 'LargeMembership', 'Public') })
        if ($flags.Count -eq 0) { continue }
        $resource = Get-FindingResourceRow -ResourceIndex $resourceIndex -ResourceId $group.Id
        $fanIn = if ($resource) { [int]$resource.PermissionFanIn } else { 1 }
        foreach ($flag in $flags) {
            $severity = if ($flag -eq 'MassExposure') { 'High' } else { 'Medium' }
            $null = Add-AuditFinding -Workload 'TeamsOrGroups' -ResourceType 'Group' -ResourceId $group.Id `
                -ResourceName $group.DisplayName -PrincipalId $group.Id -Permission $flag `
                -PermissionStrength 'Read' -FanIn $fanIn -SensitivityHint '' -Severity $severity `
                -CopilotImpact 'Copilot may retrieve group-connected content for a broad or publicly discoverable membership.' `
                -Recommendation 'Review group membership, privacy, and connected SharePoint content; reduce unnecessary broad access.' `
                -Evidence "Group flags=$($group.RiskFlags); $($group.Extra)"
        }
    }

    foreach ($team in @($Script:Nodes | Where-Object {
                $_.Type -eq 'Group' -and $_.Extra -match '(?i)(?:^|;)IsTeam=true(?:;|$)'
            })) {
        $resource = Get-FindingResourceRow -ResourceIndex $resourceIndex -ResourceId $team.Id
        $fanIn = if ($resource) { [int]$resource.PermissionFanIn } else { 1 }
        $memberCount = if ($team.Extra -match '(?i)(?:^|;)MemberCount=(\d+)') { [int]$Matches[1] } else { 0 }
        $ownerCount = if ($team.Extra -match '(?i)(?:^|;)OwnerCount=(\d+)') { [int]$Matches[1] } else { 0 }
        $guestCount = if ($team.Extra -match '(?i)(?:^|;)GuestCount=(\d+)') { [int]$Matches[1] } else { 0 }
        $guestRatio = if ($team.Extra -match '(?i)(?:^|;)GuestRatio=([0-9.]+)') { [double]$Matches[1] } else { 0 }

        if ($team.RiskFlags -match '(?i)(?:^|,)TeamNoOwner(?:,|$)') {
            $null = Add-AuditFinding -Workload 'Teams' -ResourceType 'Team' -ResourceId $team.Id `
                -ResourceName $team.DisplayName -PrincipalId 'team:owners:none' -Permission 'OwnerlessTeam' `
                -PermissionStrength 'Owner' -FanIn $fanIn -Severity 'High' `
                -CopilotImpact 'An ownerless Team has no accountable administrator to review membership and the connected content Copilot may retrieve.' `
                -Recommendation 'Assign at least two appropriate Team owners, then validate member and guest access.' `
                -Evidence "OwnerCount=$ownerCount; MemberCount=$memberCount; $($team.Extra)"
        }
        if ($team.RiskFlags -match '(?i)(?:^|,)TeamMassExposure(?:,|$)') {
            $null = Add-AuditFinding -Workload 'Teams' -ResourceType 'Team' -ResourceId $team.Id `
                -ResourceName $team.DisplayName -PrincipalId 'team:members:mass' -Permission 'MassTeamMembership' `
                -PermissionStrength 'Member' -FanIn $fanIn -Severity 'High' `
                -CopilotImpact 'A very large Team membership broadens access to Team conversations and connected SharePoint content that Copilot may retrieve.' `
                -Recommendation 'Validate that the Team needs tenant-scale membership; split audiences or remove inactive members where practical.' `
                -Evidence "MemberCount=$memberCount; OwnerCount=$ownerCount; $($team.Extra)"
        }
        if ($team.RiskFlags -match '(?i)(?:^|,)TeamGuestHeavy(?:,|$)') {
            $null = Add-AuditFinding -Workload 'Teams' -ResourceType 'Team' -ResourceId $team.Id `
                -ResourceName $team.DisplayName -PrincipalId 'team:guests:heavy' -Permission 'GuestHeavyTeam' `
                -PermissionStrength 'Member' -FanIn $fanIn -Severity 'Medium' `
                -CopilotImpact 'A high guest population increases the risk that Team and connected SharePoint content is accessible outside the organization.' `
                -Recommendation 'Review guest business need, expiration, and Team/channel membership; remove guests that no longer need access.' `
                -Evidence "GuestCount=$guestCount; GuestRatio=$guestRatio; MemberCount=$memberCount; $($team.Extra)"
        }
    }

    return @(Get-AuditFindings)
}

function Escape-HtmlText {
    param([string]$Text)
    if ($null -eq $Text) { return '' }
    return [System.Net.WebUtility]::HtmlEncode([string]$Text)
}

function Get-UserBlastRadiusRows {
    param([object[]]$Findings = @())

    $edgesBySource = @{}
    foreach ($edge in $Script:Edges) {
        if (-not $edgesBySource.ContainsKey($edge.SourceId)) {
            $edgesBySource[$edge.SourceId] = [System.Collections.Generic.List[object]]::new()
        }
        $edgesBySource[$edge.SourceId].Add($edge)
    }

    $rows = [System.Collections.Generic.List[object]]::new()
    $findingsByPrincipal = @{}
    foreach ($finding in @($Findings)) {
        if (-not $finding.PrincipalId) { continue }
        if (-not $findingsByPrincipal.ContainsKey($finding.PrincipalId)) {
            $findingsByPrincipal[$finding.PrincipalId] = [System.Collections.Generic.List[object]]::new()
        }
        $findingsByPrincipal[$finding.PrincipalId].Add($finding)
    }

    foreach ($node in $Script:Nodes) {
        if ($node.Type -ne 'User') { continue }
        if (-not $edgesBySource.ContainsKey($node.Id)) { continue }
        if (-not (Test-IsInTargetUserScope -UserId $node.Id -ObjectId $node.ObjectId -UserPrincipalName $node.UserPrincipalName -Mail $node.Mail)) {
            continue
        }

        $targetWeights = @{}
        $flagSet = [System.Collections.Generic.HashSet[string]]::new()

        foreach ($edge in $edgesBySource[$node.Id]) {
            $w = [double]$edge.Weight
            if (-not $targetWeights.ContainsKey($edge.TargetId) -or $w -gt $targetWeights[$edge.TargetId]) {
                $targetWeights[$edge.TargetId] = $w
            }
            [void]$flagSet.Add($edge.EdgeType)
        }

        $blast = 0.0
        foreach ($w in $targetWeights.Values) { $blast += $w }

        $topTargets = (
            $targetWeights.GetEnumerator() |
                Sort-Object Value -Descending |
                Select-Object -First 5 |
                ForEach-Object {
                    $t = $_.Key
                    $label = Get-NodeLabel -NodeId $t
                    $name = if ($label.UserPrincipalName) { $label.UserPrincipalName } else { $label.DisplayName }
                    "{0} [{1}] ({2})" -f $name, $(if ($label.ObjectId) { $label.ObjectId } else { $t }), $_.Value
                }
        ) -join '; '
        $userFindings = if ($findingsByPrincipal.ContainsKey($node.Id)) { @($findingsByPrincipal[$node.Id]) } else { @() }
        $criticalFindingCount = @($userFindings | Where-Object { $_.Severity -eq 'Critical' }).Count
        $highFindingCount = @($userFindings | Where-Object { $_.Severity -eq 'High' }).Count

        $rows.Add([PSCustomObject]@{
            UserId             = $node.Id
            ObjectId           = $(if ($node.ObjectId) { $node.ObjectId } else { $node.Id })
            UserPrincipalName  = $node.UserPrincipalName
            Mail               = $node.Mail
            DisplayName        = $node.DisplayName
            BlastScore         = [math]::Round($blast, 2)
            Severity           = (Get-SeverityFromScore -Score $blast)
            EdgeCount          = @($edgesBySource[$node.Id]).Count
            DistinctTargets    = $targetWeights.Count
            FindingCriticalCount = $criticalFindingCount
            FindingHighCount   = $highFindingCount
            TopTargets         = $topTargets
            RiskFlags          = ($flagSet | Sort-Object) -join ','
        })
    }

    return $rows | Sort-Object `
        @{ Expression = { $_.FindingCriticalCount + $_.FindingHighCount }; Descending = $true }, `
        @{ Expression = 'FindingCriticalCount'; Descending = $true }, `
        @{ Expression = 'FindingHighCount'; Descending = $true }, `
        @{ Expression = 'BlastScore'; Descending = $true }
}

function Get-ResourceBlastRadiusRows {
    $edgesByTarget = @{}
    foreach ($edge in $Script:Edges) {
        if (-not $edgesByTarget.ContainsKey($edge.TargetId)) {
            $edgesByTarget[$edge.TargetId] = [System.Collections.Generic.List[object]]::new()
        }
        $edgesByTarget[$edge.TargetId].Add($edge)
    }

    $rows = [System.Collections.Generic.List[object]]::new()

    foreach ($node in $Script:Nodes) {
        if ($node.Type -eq 'User') { continue }
        if (-not $edgesByTarget.ContainsKey($node.Id)) { continue }

        $sourceWeights = @{}
        $edgeTypeSet = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        $inboundEdges = @($edgesByTarget[$node.Id])

        foreach ($edge in $inboundEdges) {
            $w = [double]$edge.Weight
            if (-not $sourceWeights.ContainsKey($edge.SourceId) -or $w -gt $sourceWeights[$edge.SourceId]) {
                $sourceWeights[$edge.SourceId] = $w
            }
            if ($edge.EdgeType) { [void]$edgeTypeSet.Add([string]$edge.EdgeType) }
        }

        $edgeWeightSum = 0.0
        foreach ($w in $sourceWeights.Values) { $edgeWeightSum += $w }

        $cap = Get-ResourceBlastRadiusCap -Type $node.Type
        $blast = [Math]::Min($cap, $edgeWeightSum)
        $fanIn = $sourceWeights.Count

        $node.Score = [math]::Round($blast, 2)
        $node.Severity = Get-SeverityFromScore -Score $blast

        $flagParts = [System.Collections.Generic.List[string]]::new()
        foreach ($part in @(($node.RiskFlags -split ',') | Where-Object { $_ -and $_ -notmatch '^FanIn:' })) {
            $flagParts.Add($part)
        }
        $flagParts.Add("FanIn:$fanIn")
        foreach ($edgeType in ($edgeTypeSet | Sort-Object)) {
            if ($flagParts -notcontains $edgeType) { $flagParts.Add($edgeType) }
        }
        $node.RiskFlags = ($flagParts | Select-Object -Unique) -join ','

        $topPrincipals = (
            $sourceWeights.GetEnumerator() |
                Sort-Object Value -Descending |
                Select-Object -First 5 |
                ForEach-Object {
                    $label = Get-NodeLabel -NodeId $_.Key
                    $name = if ($label.UserPrincipalName) { $label.UserPrincipalName }
                        elseif ($label.DisplayName) { $label.DisplayName }
                        else { $_.Key }
                    '{0} ({1})' -f $name, $_.Value
                }
        ) -join '; '

        $rows.Add([PSCustomObject]@{
            ResourceId       = $node.Id
            ObjectId         = $(if ($node.ObjectId) { $node.ObjectId } else { $node.Id })
            Type             = $node.Type
            DisplayName      = $node.DisplayName
            BlastScore       = [math]::Round($blast, 2)
            Severity         = $node.Severity
            PermissionFanIn  = $fanIn
            EdgeCount        = $inboundEdges.Count
            EdgeWeightSum    = [math]::Round($edgeWeightSum, 2)
            RiskFlags        = $node.RiskFlags
            TopPrincipals    = $topPrincipals
            Extra            = $node.Extra
        })
    }

    return $rows | Sort-Object `
        @{ Expression = 'BlastScore'; Descending = $true }, `
        @{ Expression = 'PermissionFanIn'; Descending = $true }
}

function Get-UserReachPermissionStrength {
    param(
        [string]$AccessVia,
        [string]$Detail = ''
    )

    switch -Regex ($AccessVia) {
        '^MailboxDelegate$' { return 'FullAccess' }
        '^SendAs$' { return 'SendAs' }
        '^(TeamOwner)$' { return 'FullControl' }
        '^(TeamMember|MemberOf|SiteMember)$' { return 'Contribute' }
        '^SiteRole$' {
            if ($Detail -match '^(Owner)\b') { return 'FullControl' }
            if ($Detail -match '^(Visitor)\b') { return 'Read' }
            return 'Contribute'
        }
        '^(BroadShare|SiteAclGrant)$' {
            if ($Detail -match '(?i)IsSiteAdmin=True|Owner') { return 'FullControl' }
            if ($AccessVia -eq 'BroadShare') { return 'BroadLink' }
            return 'Contribute'
        }
        default { return 'Unknown' }
    }
}

function Get-UserReachWorkload {
    param(
        [string]$AccessVia,
        [string]$TargetId
    )

    switch ($AccessVia) {
        'MailboxDelegate' { return 'Exchange' }
        'SendAs' { return 'Exchange' }
        'MemberOf' { return 'TeamsOrGroups' }
        'TeamMember' { return 'TeamsOrGroups' }
        'TeamOwner' { return 'TeamsOrGroups' }
        'SiteMember' { return 'SharePoint' }
        'SiteRole' { return 'SharePoint' }
        'SiteAclGrant' { return 'SharePoint' }
        'BroadShare' {
            if ($TargetId -like 'driveitem:*') { return 'OneDrive' }
            return 'SharePoint'
        }
        'SharedWith' {
            if ($TargetId -like 'driveitem:*') { return 'OneDrive' }
            return 'SharePoint'
        }
        default { return 'Other' }
    }
}

function Get-UserReachResourceType {
    param(
        [string]$AccessVia,
        [string]$TargetId
    )

    if ($TargetId -like 'driveitem:*') { return 'DriveItem' }
    if ($TargetId -like 'mailbox:*') { return 'Mailbox' }
    if ($TargetId -match '^https?://') { return 'Site' }
    switch ($AccessVia) {
        'MemberOf' { return 'Group' }
        'TeamMember' { return 'Team' }
        'TeamOwner' { return 'Team' }
        default {
            if ($Script:NodeIndex.ContainsKey($TargetId)) {
                return [string]$Script:NodeIndex[$TargetId].Type
            }
            return 'Other'
        }
    }
}

function Test-EdgeMatchesPrincipal {
    param(
        [Parameter(Mandatory)]$Edge,
        [Parameter(Mandatory)]$Principal
    )

    $keys = @(
        [string]$Principal.Id
        [string]$Principal.UserPrincipalName
        [string]$Principal.Mail
    ) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
        ForEach-Object { $_.Trim().ToLowerInvariant() }

    foreach ($candidate in @(
            $Edge.SourceId,
            $Edge.SourceObjectId,
            $Edge.SourceUserPrincipalName,
            $Edge.SourceMail
        )) {
        if ([string]::IsNullOrWhiteSpace([string]$candidate)) { continue }
        if ($keys -contains ([string]$candidate).Trim().ToLowerInvariant()) { return $true }
    }
    return $false
}

function Get-UserReachSensitivityHint {
    param(
        [string]$ResourceName,
        [string]$Evidence = '',
        [string]$SharerDisplayName = ''
    )

    $signals = @($ResourceName, $Evidence, $SharerDisplayName) -join ' '
    if ($signals -match $Script:SensitiveNamePatternRegex -or $signals -match '(?i)\b(restricted|secret|sensitive)\b') {
        return 'Name or collector metadata indicates sensitive content'
    }
    return ''
}

function Build-UserReachRows {
    $rows = [System.Collections.Generic.List[object]]::new()
    $seen = @{}

    if (-not $Script:TargetUserScopeEnabled -or $Script:TargetUsers.Count -eq 0) {
        $Script:RunCoverage.UserReachGraphEdgeCount = 0
        return @()
    }

    foreach ($shared in $Script:UserReachSharedRows) {
        $shared.SensitivityHint = Get-UserReachSensitivityHint -ResourceName $shared.ResourceName `
            -Evidence $shared.Evidence -SharerDisplayName $shared.SharerDisplayName
        $key = '{0}|{1}|{2}' -f $shared.PrincipalId, $shared.ResourceId, $shared.AccessVia
        if (-not $seen.ContainsKey($key)) {
            $seen[$key] = $true
            $rows.Add($shared)
        }
    }

    $reachEdgeTypes = @(
        'MemberOf', 'TeamMember', 'TeamOwner', 'SiteMember', 'SiteRole',
        'MailboxDelegate', 'SendAs', 'SharedWith', 'SiteAclGrant', 'BroadShare'
    )
    $graphEdgeRows = 0

    foreach ($principal in $Script:TargetUsers) {
        $principalEdges = @(
            $Script:Edges | Where-Object {
                $_.EdgeType -in $reachEdgeTypes -and
                (Test-EdgeMatchesPrincipal -Edge $_ -Principal $principal)
            }
        )

        foreach ($edge in $principalEdges) {
            if ($edge.EdgeType -eq 'BroadShare' -and [string]$edge.Detail -like 'Owner reach:*') {
                continue
            }

            $accessVia = [string]$edge.EdgeType
            $resourceId = [string]$edge.TargetId
            # SharedWith edges mirror SharedWithMe collector rows; keep the richer SharedWithMe row only.
            if ($accessVia -eq 'SharedWith') {
                $sharedKey = '{0}|{1}|SharedWithMe' -f $principal.Id, $resourceId
                if ($seen.ContainsKey($sharedKey)) { continue }
            }
            $key = '{0}|{1}|{2}' -f $principal.Id, $resourceId, $accessVia
            if ($seen.ContainsKey($key)) { continue }
            $seen[$key] = $true

            $resourceName = if ($edge.TargetDisplayName) { [string]$edge.TargetDisplayName } else { $resourceId }
            $resourceType = Get-UserReachResourceType -AccessVia $accessVia -TargetId $resourceId
            $workload = Get-UserReachWorkload -AccessVia $accessVia -TargetId $resourceId
            $strength = Get-UserReachPermissionStrength -AccessVia $accessVia -Detail ([string]$edge.Detail)
            $sensitivity = Get-UserReachSensitivityHint -ResourceName $resourceName -Evidence ([string]$edge.Detail)

            $baselineStatus = 'Unknown'
            if ($accessVia -in @('MemberOf', 'TeamMember', 'SiteRole')) {
                $baselineStatus = Get-MembershipBaselineStatus -Edge $edge -ResourceType $resourceType `
                    -ResourceId $resourceId -ResourceName $resourceName -Permission $(
                    if ($accessVia -eq 'SiteRole' -and $edge.Detail -match '^(Owner|Member|Visitor)\b') { $Matches[1] }
                    elseif ($accessVia -eq 'TeamMember') { 'Member' }
                    else { 'Member' }
                )
            }

            $rows.Add([PSCustomObject]@{
                    PrincipalId          = [string]$principal.Id
                    PrincipalUpn         = [string]$principal.UserPrincipalName
                    PrincipalDisplayName = [string]$principal.DisplayName
                    Workload             = $workload
                    ResourceType         = $resourceType
                    ResourceId           = $resourceId
                    ResourceName         = $resourceName
                    AccessVia            = $accessVia
                    PermissionStrength   = $strength
                    SharerId             = ''
                    SharerUpn            = ''
                    SharerDisplayName    = ''
                    Evidence             = [string]$edge.Detail
                    SensitivityHint      = $sensitivity
                    BaselineStatus       = $baselineStatus
                })
            if ($accessVia -notin @('SharedWith', 'SiteAclGrant')) {
                $graphEdgeRows++
            }
        }
    }

    $Script:RunCoverage.UserReachGraphEdgeCount = $graphEdgeRows
    return @($rows | Sort-Object PrincipalUpn, AccessVia, ResourceName)
}

function Add-UserReachFindings {
    param([object[]]$ReachRows)

    if (-not $ReachRows -or $ReachRows.Count -eq 0) { return }

    $byPrincipal = $ReachRows | Group-Object -Property PrincipalId
    foreach ($group in $byPrincipal) {
        $sample = $group.Group | Select-Object -First 1
        $sharedRows = @($group.Group | Where-Object { $_.AccessVia -in @('SharedWithMe', 'DirectGrant', 'SharedInsight', 'AccessibleShare') })
        $sharedCount = $sharedRows.Count
        $sensitiveShared = @($sharedRows | Where-Object { $_.SensitivityHint }).Count
        $distinctSharers = @(
            $sharedRows |
                Where-Object { $_.SharerId -or $_.SharerUpn -or $_.SharerDisplayName } |
                ForEach-Object {
                    if ($_.SharerId) { $_.SharerId }
                    elseif ($_.SharerUpn) { $_.SharerUpn }
                    else { $_.SharerDisplayName }
                } |
                Select-Object -Unique
        ).Count

        if ($sharedCount -ge $UserReachIncomingShareFindingThreshold) {
            $severity = if ($sensitiveShared -gt 0 -or $sharedCount -ge ($UserReachIncomingShareFindingThreshold * 2)) {
                'High'
            }
            else {
                'Medium'
            }
            Add-AuditFinding -Workload 'OneDrive' -ResourceType 'UserReach' `
                -ResourceId ("userreach:{0}" -f $sample.PrincipalId) `
                -ResourceName ("Incoming shares for {0}" -f $(if ($sample.PrincipalUpn) { $sample.PrincipalUpn } else { $sample.PrincipalDisplayName })) `
                -PrincipalId $sample.PrincipalId -PrincipalUpn $sample.PrincipalUpn `
                -Permission 'IncomingShare' -PermissionStrength 'Unknown' -FanIn $sharedCount `
                -SensitivityHint $(if ($sensitiveShared -gt 0) { 'One or more inbound shares match sensitive name patterns' } else { '' }) `
                -BaselineStatus 'Unknown' -Severity $severity `
                -CopilotImpact 'Copilot can surface content shared to this user from other owners/sites, expanding effective reach beyond their own OneDrive.' `
                -Recommendation 'Review inbound shares with the user; remove stale grants and prefer site membership with least privilege.' `
                -Evidence ("SharedWithMeCount=$sharedCount; DistinctSharers=$distinctSharers; Threshold=$UserReachIncomingShareFindingThreshold")
        }
        elseif ($distinctSharers -ge 10) {
            Add-AuditFinding -Workload 'OneDrive' -ResourceType 'UserReach' `
                -ResourceId ("userreach:{0}" -f $sample.PrincipalId) `
                -ResourceName ("Many distinct sharers for {0}" -f $(if ($sample.PrincipalUpn) { $sample.PrincipalUpn } else { $sample.PrincipalDisplayName })) `
                -PrincipalId $sample.PrincipalId -PrincipalUpn $sample.PrincipalUpn `
                -Permission 'IncomingShare' -PermissionStrength 'Unknown' -FanIn $distinctSharers `
                -BaselineStatus 'Unknown' -Severity 'Medium' `
                -CopilotImpact 'Many distinct owners have shared content with this user; Copilot may draw from a wide personal share set.' `
                -Recommendation 'Ask the user to review Shared with me and remove unneeded grants.' `
                -Evidence ("SharedWithMeCount=$sharedCount; DistinctSharers=$distinctSharers")
        }
    }
}

function Export-UserReachCsv {
    param(
        [Parameter(Mandatory)][string]$RunFolder,
        [object[]]$ReachRows
    )

    $path = Join-Path $RunFolder 'user-reach-by-principal.csv'
    if (-not $ReachRows -or $ReachRows.Count -eq 0) {
        [System.IO.File]::WriteAllText(
            $path,
            (($Script:UserReachColumns -join ',') + [Environment]::NewLine),
            [System.Text.UTF8Encoding]::new($false)
        )
    }
    else {
        $ReachRows | Select-Object $Script:UserReachColumns | Export-Csv -Path $path -NoTypeInformation -Encoding UTF8
    }
    return $path
}

function New-ExecutiveHtmlReport {
    param(
        [string]$RunFolder,
        [string]$TenantLabel,
        [string]$TenantId,
        [string]$OrganizationDomain,
        [object[]]$Users,
        [object[]]$Resources,
        [object[]]$Findings,
        [object[]]$UserReachRows = @(),
        [datetime]$GeneratedAt
    )

    $totalNodes = $Script:Nodes.Count
    $totalEdges = $Script:Edges.Count
    $userCount = @($Users).Count
    $resourceCount = @($Resources).Count
    $criticalUsers = @($Users | Where-Object { $_.Severity -eq 'Critical' }).Count
    $highUsers = @($Users | Where-Object { $_.Severity -eq 'High' }).Count
    $mediumUsers = @($Users | Where-Object { $_.Severity -eq 'Medium' }).Count
    $lowUsers = @($Users | Where-Object { $_.Severity -eq 'Low' }).Count
    $criticalResources = @($Resources | Where-Object { $_.Severity -eq 'Critical' }).Count
    $highResources = @($Resources | Where-Object { $_.Severity -eq 'High' }).Count
    $criticalFindings = @($Findings | Where-Object { $_.Severity -eq 'Critical' }).Count
    $highFindings = @($Findings | Where-Object { $_.Severity -eq 'High' }).Count

    $privEdges = @($Script:Edges | Where-Object { $_.EdgeType -eq 'PrivilegedRole' }).Count
    $memberEdges = @($Script:Edges | Where-Object { $_.EdgeType -eq 'MemberOf' }).Count
    $mailboxEdges = @($Script:Edges | Where-Object { $_.EdgeType -in @('MailboxDelegate', 'SendAs') }).Count
    $broadEdges = @($Script:Edges | Where-Object { $_.EdgeType -eq 'BroadShare' }).Count
    $siteEdges = @($Script:Edges | Where-Object { $_.EdgeType -in @('SitePrincipal', 'SiteMember', 'SiteRole', 'SiteCapability') }).Count

    $coverage = $Script:RunCoverage
    $graphStatus = if ($coverage.GraphOk) {
        $mode = if ($coverage.GraphAuthMode) { [string]$coverage.GraphAuthMode } else { 'Delegated' }
        $appBit = if ($coverage.GraphAppId) { "; AppId=$($coverage.GraphAppId)" } else { '' }
        $unattended = if ($coverage.UnattendedAppOnly) { '; unattended' } else { '' }
        "Connected and tenant-pinned ($mode$appBit$unattended)"
    }
    else { 'Unavailable' }
    $exchangeStatus = if ($coverage.ExchangeOk) {
        'Connected'
    }
    elseif ($coverage.ExchangeSkippedReason) {
        "Skipped ($($coverage.ExchangeSkippedReason))"
    }
    else { 'Unavailable or skipped' }
    $spoStatus = if ($coverage.SpoOk) {
        'Connected'
    }
    elseif ($coverage.SpoSkippedReason) {
        "Skipped ($($coverage.SpoSkippedReason)); Graph inventory used"
    }
    else { 'Unavailable or skipped' }
    $pnpStatus = if ($coverage.PnpOk) { 'Connected (associated Owners/Members/Visitors)' } else { 'Unavailable; flat SPO membership fallback' }
    $siteInventoryStatus = switch ($coverage.SharePointInventoryMode) {
        'SPO' { 'SPO site scan' }
        'GraphFallback' { 'Graph inventory only' }
        'Skipped' { 'Skipped' }
        default { 'Not collected' }
    }
    $spoConfidence = switch ($coverage.SharePointInventoryMode) {
        'SPO' { 'SPO can evaluate site principals and external-sharing capability.' }
        'GraphFallback' { 'Graph inventory-only: Everyone/site-principal membership coverage is unavailable.' }
        'Skipped' { 'Site-principal and external-sharing findings are absent when SharePoint is unavailable or skipped.' }
        default {
            if ($coverage.SpoOk) {
                'Graph inventory-only: Everyone/site-principal membership coverage is unavailable.'
            }
            else {
                'Site-principal and external-sharing findings are absent when SharePoint is unavailable or skipped.'
            }
        }
    }
    $scopeStatus = if ($coverage.UserScopeActive) { 'Active (user reporting and OneDrive sampling limited)' } else { 'Tenant-wide' }

    $topResources = @($Resources | Select-Object -First 15)

    $privUsers = @(
        $Script:Edges |
            Where-Object { $_.EdgeType -eq 'PrivilegedRole' } |
            Select-Object -Property SourceDisplayName, SourceUserPrincipalName, SourceObjectId, TargetDisplayName, Detail -Unique |
            Sort-Object SourceUserPrincipalName, TargetDisplayName |
            Select-Object -First 25
    )

    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.AppendLine('<!DOCTYPE html>')
    [void]$sb.AppendLine('<html lang="en"><head><meta charset="utf-8" />')
    [void]$sb.AppendLine('<meta name="viewport" content="width=device-width, initial-scale=1" />')
    [void]$sb.AppendLine('<title>Copilot Over-Permissioning Executive Report</title>')
    [void]$sb.AppendLine(@'
<style>
  :root {
    --ink: #1a2332;
    --muted: #5c6b7a;
    --line: #d7dee7;
    --bg: #f3f6f9;
    --card: #ffffff;
    --accent: #0f5c6e;
    --critical: #9b1c1c;
    --high: #b45309;
    --medium: #a16207;
    --low: #3f6212;
  }
  * { box-sizing: border-box; }
  body {
    margin: 0;
    font-family: "Segoe UI", Calibri, Geneva, sans-serif;
    color: var(--ink);
    background:
      radial-gradient(1200px 500px at 10% -10%, #d9e8ee 0%, transparent 55%),
      radial-gradient(900px 400px at 100% 0%, #e7eef3 0%, transparent 50%),
      var(--bg);
  }
  header {
    padding: 2.2rem 2rem 1.4rem;
    border-bottom: 1px solid var(--line);
    background: linear-gradient(180deg, rgba(255,255,255,.92), rgba(255,255,255,.72));
  }
  header h1 {
    margin: 0 0 .35rem;
    font-size: 1.85rem;
    letter-spacing: -.02em;
    color: var(--accent);
  }
  header p { margin: .15rem 0; color: var(--muted); }
  main { padding: 1.5rem 2rem 3rem; max-width: 1200px; margin: 0 auto; }
  .kpis {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
    gap: 0.85rem;
    margin: 1rem 0 1.5rem;
  }
  .kpi {
    background: var(--card);
    border: 1px solid var(--line);
    border-radius: 10px;
    padding: 0.95rem 1rem;
  }
  .kpi .label { font-size: .78rem; text-transform: uppercase; letter-spacing: .04em; color: var(--muted); }
  .kpi .value { font-size: 1.55rem; font-weight: 650; margin-top: .25rem; }
  section {
    background: var(--card);
    border: 1px solid var(--line);
    border-radius: 12px;
    padding: 1.15rem 1.25rem 1.35rem;
    margin-bottom: 1.15rem;
  }
  section h2 {
    margin: 0 0 .85rem;
    font-size: 1.15rem;
    color: var(--accent);
  }
  table { width: 100%; border-collapse: collapse; font-size: .92rem; }
  th, td { text-align: left; padding: .55rem .45rem; border-bottom: 1px solid var(--line); vertical-align: top; }
  th { font-size: .75rem; text-transform: uppercase; letter-spacing: .04em; color: var(--muted); }
  .sev {
    display: inline-block;
    padding: .15rem .5rem;
    border-radius: 999px;
    font-size: .75rem;
    font-weight: 600;
  }
  .sev-Critical { background: #fee2e2; color: var(--critical); }
  .sev-High { background: #ffedd5; color: var(--high); }
  .sev-Medium { background: #fef3c7; color: var(--medium); }
  .sev-Low { background: #ecfccb; color: var(--low); }
  .mono { font-family: Consolas, "Courier New", monospace; font-size: .82rem; color: #334155; word-break: break-all; }
  .muted { color: var(--muted); }
  footer { margin-top: 1rem; color: var(--muted); font-size: .85rem; }
</style>
</head><body>
'@)

    [void]$sb.AppendLine('<header>')
    [void]$sb.AppendLine('<h1>Copilot Over-Permissioning Executive Report</h1>')
    [void]$sb.AppendLine("<p>Tenant: <strong>$(Escape-HtmlText $TenantLabel)</strong></p>")
    if ($TenantId) {
        [void]$sb.AppendLine("<p>Tenant ID: <strong>$(Escape-HtmlText $TenantId)</strong></p>")
    }
    if ($OrganizationDomain) {
        [void]$sb.AppendLine("<p>Organization domain: <strong>$(Escape-HtmlText $OrganizationDomain)</strong></p>")
    }
    [void]$sb.AppendLine("<p>Generated: $(Escape-HtmlText ($GeneratedAt.ToString('yyyy-MM-dd HH:mm:ss'))) &nbsp;|&nbsp; Depth B graph (roles, groups, Exchange, SPO/Graph sites, capped content sample)</p>")
    if ($Script:TargetUserScopeEnabled) {
        [void]$sb.AppendLine("<p>User scope: <strong>$($Script:TargetUsers.Count)</strong> resolved / <strong>$($Script:TargetUserInputCount)</strong> input (user report + OneDrive/enrichment limited; resources tenant-wide).</p>")
    }
    [void]$sb.AppendLine('</header><main>')

    [void]$sb.AppendLine('<div class="kpis">')
    foreach ($kpi in @(
            @{ L = 'Nodes'; V = $totalNodes },
            @{ L = 'Edges'; V = $totalEdges },
            @{ L = 'Users w/ exposure'; V = $userCount },
            @{ L = 'Resources w/ exposure'; V = $resourceCount },
            @{ L = 'Critical / High findings'; V = "$criticalFindings / $highFindings" },
            @{ L = 'Critical / High users'; V = "$criticalUsers / $highUsers" },
            @{ L = 'Critical / High resources'; V = "$criticalResources / $highResources" }
        )) {
        [void]$sb.AppendLine("<div class='kpi'><div class='label'>$($kpi.L)</div><div class='value'>$($kpi.V)</div></div>")
    }
    [void]$sb.AppendLine('</div>')

    [void]$sb.AppendLine('<section><h2>Audit coverage</h2>')
    [void]$sb.AppendLine('<p class="muted">Coverage describes the evidence collected for this run. Findings are not a statement that unscanned or capped content has no exposure.</p>')
    [void]$sb.AppendLine('<table><thead><tr><th>Area</th><th>Coverage</th><th>Confidence boundary</th></tr></thead><tbody>')
    [void]$sb.AppendLine("<tr><td>Microsoft Graph</td><td>$(Escape-HtmlText $graphStatus)</td><td>Required for identity and content collectors.</td></tr>")
    [void]$sb.AppendLine("<tr><td>Exchange Online</td><td>$(Escape-HtmlText $exchangeStatus)</td><td>Mailbox delegation findings are absent when Exchange is unavailable or skipped.</td></tr>")
    [void]$sb.AppendLine("<tr><td>SharePoint Online</td><td>$(Escape-HtmlText $spoStatus); $(Escape-HtmlText $siteInventoryStatus)</td><td>$(Escape-HtmlText $spoConfidence)</td></tr>")
    [void]$sb.AppendLine("<tr><td>SharePoint role fidelity</td><td>$(Escape-HtmlText $pnpStatus); mode=$(Escape-HtmlText $coverage.SharePointRoleMode)</td><td>PnP role evidence is optional. When available, associated role groups supersede equivalent flat membership edges.</td></tr>")
    $teamsStatus = if ($coverage.TeamsOk) { "$($coverage.TeamsCount) team(s) scanned" } else { 'Unavailable or skipped' }
    $teamsBoundary = if ($coverage.TeamsChannelsSkipped) {
        'Private/shared channel membership was skipped; consent Channel.ReadBasic.All to collect it.'
    }
    elseif ($coverage.TeamsChannelsOk) {
        'Private/shared channel membership was collected where exposed by Graph.'
    }
    else {
        'Team membership was collected; no private/shared channels were returned.'
    }
    [void]$sb.AppendLine("<tr><td>Teams-native membership</td><td>$(Escape-HtmlText $teamsStatus)</td><td>$(Escape-HtmlText $teamsBoundary)</td></tr>")
    [void]$sb.AppendLine("<tr><td>SharePoint content sampling</td><td>$($coverage.SitesSampled) library site(s) sampled / $($coverage.SitesTotal) site(s) discovered; $($coverage.ContentSitesPrioritized) prioritized for Everyone/external signals</td><td>Flagged unified-group sites are sampled first; library scanning is still capped and is not a complete tenant-wide content review.</td></tr>")
    [void]$sb.AppendLine("<tr><td>Content items</td><td>$($coverage.ContentItemsScanned) item(s) inspected; $($coverage.ContentItemsCapped) drive/library crawl(s) reached the $BroadSharingMaxItems item cap; $($coverage.ContentItemsSkippedCap) item/folder branch(es) skipped at cap; $($coverage.ContentItemsSkippedDepth) folder branch(es) skipped beyond depth $BroadSharingMaxDepth</td><td>Items beyond a capped crawl and folders beyond the configured depth are not assessed.</td></tr>")
    [void]$sb.AppendLine("<tr><td>Content sampling failures</td><td>$($coverage.ContentDriveFailures) drive access failure(s); $($coverage.ContentPermissionFailures) permission read failure(s)</td><td>Failed drives or permission reads are excluded from broad-sharing evidence for that path.</td></tr>")
    [void]$sb.AppendLine("<tr><td>OneDrive content sampling</td><td>$($coverage.OneDriveUsersSampled) user drive(s) sampled</td><td>Per-drive item depth and item count are capped; unavailable drives are excluded.</td></tr>")
    [void]$sb.AppendLine("<tr><td>Named-share fan-in</td><td>$($coverage.DirectShareFindings) sampled item(s) with high named-grant fan-in</td><td>Named grants are aggregated per item; findings require at least $DirectShareFanInThreshold distinct user/group grants.</td></tr>")
    [void]$sb.AppendLine("<tr><td>Site membership edge cap</td><td>$($coverage.SiteMemberEdgeCapHits) site(s) reached the $Script:SiteMemberEdgeCap edge cap</td><td>Membership fan-in is truncated for each capped site.</td></tr>")
    [void]$sb.AppendLine("<tr><td>User scope</td><td>$(Escape-HtmlText $scopeStatus)</td><td>Resources remain tenant-wide; scoped runs limit user reporting and OneDrive sampling.</td></tr>")
    [void]$sb.AppendLine("<tr><td>Copilot-licensed scope</td><td>$($coverage.CopilotLicensedOnly)</td><td>Applied only when no explicit user scope was supplied.</td></tr>")
    [void]$sb.AppendLine("<tr><td>Access baseline</td><td>$($coverage.BaselineLoaded)</td><td>Expected versus unexpected status is evaluated for Group, Team, and Site role memberships.</td></tr>")
    [void]$sb.AppendLine("<tr><td>Sensitive name patterns</td><td>$($coverage.SensitivePatternsCount) configured</td><td>Name-pattern sensitivity is heuristic and is not Microsoft Purview label coverage.</td></tr>")
    $reachStatus = "$($coverage.UserReachMap); SharedWithMeOk=$($coverage.UserReachSharedWithMeOk); sharedWithMe=$($coverage.UserReachItemCount); directGrants=$($coverage.UserReachDirectGrantCount); ownerDrives=$($coverage.UserReachOwnerDrivesScanned); folders=$($coverage.UserReachFoldersScanned); graphEdges=$($coverage.UserReachGraphEdgeCount); reverseSites=$($coverage.UserReachReverseAclSites)"
    $reachBoundary = if ($coverage.UserReachLimitation) {
        [string]$coverage.UserReachLimitation
    }
    else {
        'User reach map runs when a user scope is active (or -IncludeUserReachMap). It is not a full tenant reverse ACL crawl.'
    }
    [void]$sb.AppendLine("<tr><td>User Copilot reach map</td><td>$(Escape-HtmlText $reachStatus)</td><td>$(Escape-HtmlText $reachBoundary)</td></tr>")
    [void]$sb.AppendLine('</tbody></table></section>')

    [void]$sb.AppendLine('<section><h2>Executive summary</h2>')
    $scopeNote = if ($Script:TargetUserScopeEnabled) {
        " User blast-radius table is limited to the scoped user list ($($Script:TargetUsers.Count) resolved); resource ranking remains tenant-wide."
    }
    else { '' }
    [void]$sb.AppendLine("<p>This report prioritizes <strong>over-permissioning and Copilot content exposure</strong>: <strong>$criticalFindings Critical</strong> and <strong>$highFindings High</strong> findings identify broad sharing, excessive membership, and delegated access requiring review. User blast radius and resource fan-in are secondary analysis to help prioritize remediation. $($criticalUsers + $highUsers) user(s) and $($criticalResources + $highResources) resource(s) scored High or Critical.$scopeNote</p>")
    $edgeMix = "Edge mix - PrivilegedRole: $privEdges | MemberOf: $memberEdges | Mailbox/SendAs: $mailboxEdges | BroadShare: $broadEdges | Site access: $siteEdges. User severity - Critical $criticalUsers | High $highUsers | Medium $mediumUsers | Low $lowUsers."
    [void]$sb.AppendLine("<p class='muted'>$(Escape-HtmlText $edgeMix)</p>")
    [void]$sb.AppendLine('</section>')

    [void]$sb.AppendLine('<section><h2>Top over-permissioning findings</h2>')
    [void]$sb.AppendLine('<p class="muted">Findings prioritize broad grants and delegated access that could let Copilot reach unintended content. Review evidence and recommendation before remediation.</p>')
    [void]$sb.AppendLine('<table><thead><tr><th>Severity</th><th>Workload</th><th>Resource</th><th>Permission</th><th>Principal</th><th>Fan-in</th><th>Copilot impact</th><th>Recommendation</th></tr></thead><tbody>')
    foreach ($finding in @($Findings | Select-Object -First 25)) {
        $severity = Escape-HtmlText $finding.Severity
        $principal = if ($finding.PrincipalUpn) { $finding.PrincipalUpn } else { $finding.PrincipalId }
        [void]$sb.AppendLine("<tr><td><span class='sev sev-$severity'>$severity</span></td><td>$(Escape-HtmlText $finding.Workload)</td><td>$(Escape-HtmlText $finding.ResourceName)</td><td>$(Escape-HtmlText $finding.Permission)</td><td class='mono'>$(Escape-HtmlText $principal)</td><td>$($finding.FanIn)</td><td>$(Escape-HtmlText $finding.CopilotImpact)</td><td>$(Escape-HtmlText $finding.Recommendation)</td></tr>")
    }
    if (@($Findings).Count -eq 0) {
        [void]$sb.AppendLine('<tr><td colspan="8" class="muted">No over-permissioning findings were produced from the available collector data.</td></tr>')
    }
    [void]$sb.AppendLine('</tbody></table></section>')

    [void]$sb.AppendLine('<section><h2>Copilot content reach (scoped users)</h2>')
    [void]$sb.AppendLine('<p class="muted">Incoming access for scoped users: SharedWithMe items (sharer when Graph provides it), plus membership and delegation edges already in the permission graph. See <code>user-reach-by-principal.csv</code>.</p>')
    [void]$sb.AppendLine('<table><thead><tr><th>User</th><th>Access via</th><th>Resource</th><th>Workload</th><th>Sharer</th><th>Strength</th><th>Evidence</th></tr></thead><tbody>')
    $reachForHtml = @($UserReachRows | Select-Object -First 40)
    foreach ($reach in $reachForHtml) {
        $userLabel = if ($reach.PrincipalUpn) { $reach.PrincipalUpn } else { $reach.PrincipalDisplayName }
        $sharerLabel = if ($reach.SharerUpn) { $reach.SharerUpn } elseif ($reach.SharerDisplayName) { $reach.SharerDisplayName } else { '' }
        [void]$sb.AppendLine("<tr><td class='mono'>$(Escape-HtmlText $userLabel)</td><td>$(Escape-HtmlText $reach.AccessVia)</td><td>$(Escape-HtmlText $reach.ResourceName)</td><td>$(Escape-HtmlText $reach.Workload)</td><td class='mono'>$(Escape-HtmlText $sharerLabel)</td><td>$(Escape-HtmlText $reach.PermissionStrength)</td><td class='muted'>$(Escape-HtmlText $reach.Evidence)</td></tr>")
    }
    if ($reachForHtml.Count -eq 0) {
        [void]$sb.AppendLine('<tr><td colspan="7" class="muted">No scoped-user reach rows in this run (no user scope, skipped, or empty SharedWithMe/membership set).</td></tr>')
    }
    [void]$sb.AppendLine('</tbody></table></section>')

    [void]$sb.AppendLine('<section><h2>Secondary analysis: users by Copilot blast radius</h2>')
    [void]$sb.AppendLine('<table><thead><tr><th>User</th><th>UPN / Mail</th><th>Object ID</th><th>Score</th><th>Severity</th><th>Edges</th><th>Flags</th><th>Top targets</th></tr></thead><tbody>')
    foreach ($u in @($Users | Select-Object -First 25)) {
        $name = Escape-HtmlText $u.DisplayName
        $upn = Escape-HtmlText $(if ($u.UserPrincipalName) { $u.UserPrincipalName } else { $u.Mail })
        $oid = Escape-HtmlText $u.ObjectId
        $sev = Escape-HtmlText $u.Severity
        [void]$sb.AppendLine("<tr><td>$name</td><td>$upn</td><td class='mono'>$oid</td><td>$($u.BlastScore)</td><td><span class='sev sev-$sev'>$sev</span></td><td>$($u.EdgeCount)</td><td>$(Escape-HtmlText $u.RiskFlags)</td><td class='muted'>$(Escape-HtmlText $u.TopTargets)</td></tr>")
    }
    [void]$sb.AppendLine('</tbody></table></section>')

    [void]$sb.AppendLine('<section><h2>Secondary analysis: resources by permission fan-in</h2>')
    [void]$sb.AppendLine('<p class="muted">Resource score = inbound permission weight (unique principals), soft-capped by type. Mailboxes rise with FullAccess/SendAs delegates; sites rise with Everyone/external grants and human site members.</p>')
    [void]$sb.AppendLine('<table><thead><tr><th>Resource</th><th>Type</th><th>Id / Object ID</th><th>Score</th><th>Severity</th><th>Fan-in</th><th>Flags</th><th>Top principals</th></tr></thead><tbody>')
    foreach ($r in $topResources) {
        $oid = if ($r.ObjectId) { $r.ObjectId } else { $r.ResourceId }
        [void]$sb.AppendLine("<tr><td>$(Escape-HtmlText $r.DisplayName)</td><td>$(Escape-HtmlText $r.Type)</td><td class='mono'>$(Escape-HtmlText $oid)</td><td>$($r.BlastScore)</td><td><span class='sev sev-$(Escape-HtmlText $r.Severity)'>$(Escape-HtmlText $r.Severity)</span></td><td>$($r.PermissionFanIn)</td><td>$(Escape-HtmlText $r.RiskFlags)</td><td class='muted'>$(Escape-HtmlText $r.TopPrincipals)</td></tr>")
    }
    if ($topResources.Count -eq 0) {
        [void]$sb.AppendLine('<tr><td colspan="8" class="muted">No scored non-user resources with inbound permissions in this run.</td></tr>')
    }
    [void]$sb.AppendLine('</tbody></table></section>')

    [void]$sb.AppendLine('<section><h2>Privileged Entra role assignments</h2>')
    [void]$sb.AppendLine('<table><thead><tr><th>User</th><th>UPN</th><th>Object ID</th><th>Role</th></tr></thead><tbody>')
    foreach ($p in $privUsers) {
        [void]$sb.AppendLine("<tr><td>$(Escape-HtmlText $p.SourceDisplayName)</td><td>$(Escape-HtmlText $p.SourceUserPrincipalName)</td><td class='mono'>$(Escape-HtmlText $p.SourceObjectId)</td><td>$(Escape-HtmlText $(if ($p.Detail) { $p.Detail } else { $p.TargetDisplayName }))</td></tr>")
    }
    if ($privUsers.Count -eq 0) {
        [void]$sb.AppendLine('<tr><td colspan="4" class="muted">No privileged role edges found (or role scan unavailable).</td></tr>')
    }
    [void]$sb.AppendLine('</tbody></table></section>')

    [void]$sb.AppendLine('<section><h2>How to read this</h2>')
    [void]$sb.AppendLine('<p>CSV companions in this folder: <code>findings.csv</code>, <code>user-reach-by-principal.csv</code>, <code>nodes.csv</code>, <code>edges.csv</code>, <code>users-by-blast-radius.csv</code>, <code>resources-by-blast-radius.csv</code>. Identity columns include GUIDs (<code>ObjectId</code> / <code>SourceObjectId</code> / <code>TargetObjectId</code>) plus display name, UPN, and mail where resolvable.</p>')
    [void]$sb.AppendLine('<p class="muted">User scores = outbound reach. Resource scores = inbound permission fan-in (soft-capped by type). Medium-depth content sampling is capped by BroadSharingMaxItems / Depth and MaxSitesForContentSample. SPO site member fan-in requires SharePoint Online Management Shell. Scoped-user reach maps SharedWithMe plus graph memberships; it is not a full reverse ACL of every drive.</p>')
    [void]$sb.AppendLine('</section>')

    [void]$sb.AppendLine("<footer>Output folder: $(Escape-HtmlText $RunFolder)</footer>")
    [void]$sb.AppendLine('</main></body></html>')

    $htmlPath = Join-Path $RunFolder 'executive-report.html'
    [System.IO.File]::WriteAllText($htmlPath, $sb.ToString(), [System.Text.UTF8Encoding]::new($false))
    return $htmlPath
}

function Export-ExposureGraph {
    param(
        [string]$RunFolder,
        [string]$TenantLabel,
        [string]$TenantId,
        [string]$OrganizationDomain
    )

    if (-not (Test-Path -LiteralPath $RunFolder)) {
        New-Item -ItemType Directory -Path $RunFolder -Force | Out-Null
    }

    Complete-UserIdentityLabels
    Update-EdgeIdentityLabels

    $resources = @(Get-ResourceBlastRadiusRows)
    $findings = @(Build-FindingsFromGraph -ResourceRows $resources)
    $reachRows = @(Build-UserReachRows)
    Add-UserReachFindings -ReachRows $reachRows
    $findings = @(Get-AuditFindings)
    $users = @(Get-UserBlastRadiusRows -Findings $findings)
    $Script:RunCoverage.FindingsCount = $findings.Count

    foreach ($node in $Script:Nodes) {
        $node.Severity = Get-SeverityFromScore -Score ([double]$node.Score)
    }

    $nodesPath = Join-Path $RunFolder 'nodes.csv'
    $edgesPath = Join-Path $RunFolder 'edges.csv'
    $usersPath = Join-Path $RunFolder 'users-by-blast-radius.csv'
    $resourcesPath = Join-Path $RunFolder 'resources-by-blast-radius.csv'
    $findingsPath = Export-FindingsCsv -RunFolder $RunFolder
    $reachPath = Export-UserReachCsv -RunFolder $RunFolder -ReachRows $reachRows
    $coveragePath = Join-Path $RunFolder 'coverage.json'
    [System.IO.File]::WriteAllText(
        $coveragePath,
        ($Script:RunCoverage | ConvertTo-Json -Depth 4),
        [System.Text.UTF8Encoding]::new($false)
    )

    $Script:Nodes | Export-Csv -Path $nodesPath -NoTypeInformation -Encoding UTF8
    $Script:Edges | Export-Csv -Path $edgesPath -NoTypeInformation -Encoding UTF8
    $users | Export-Csv -Path $usersPath -NoTypeInformation -Encoding UTF8
    $resources | Export-Csv -Path $resourcesPath -NoTypeInformation -Encoding UTF8

    $htmlPath = New-ExecutiveHtmlReport -RunFolder $RunFolder -TenantLabel $TenantLabel `
        -TenantId $TenantId -OrganizationDomain $OrganizationDomain -Users $users -Resources $resources `
        -Findings $findings -UserReachRows $reachRows -GeneratedAt (Get-Date)

    Write-AuditLog "`nExported:"
    Write-AuditLog "  $findingsPath  ($($findings.Count) over-permissioning findings)"
    Write-AuditLog "  $reachPath  ($($reachRows.Count) user-reach rows)"
    Write-AuditLog "  $nodesPath  ($($Script:Nodes.Count) nodes)"
    Write-AuditLog "  $edgesPath  ($($Script:Edges.Count) edges)"
    Write-AuditLog "  $usersPath  ($($users.Count) users with edges)"
    Write-AuditLog "  $resourcesPath  ($($resources.Count) resources with inbound permissions)"
    Write-AuditLog "  $coveragePath"
    Write-AuditLog "  $htmlPath"

    Write-Host "`nTop over-permissioning findings:" -ForegroundColor Green
    $findings | Select-Object -First 20 Severity, Workload, ResourceName, Permission, PrincipalUpn, FanIn, Recommendation |
        Format-Table -AutoSize

    if ($reachRows.Count -gt 0) {
        Write-Host "`nUser Copilot reach (scoped):" -ForegroundColor Green
        $reachRows |
            Group-Object PrincipalUpn |
            ForEach-Object {
                [PSCustomObject]@{
                    User      = $_.Name
                    ReachRows = $_.Count
                    SharedWithMe = @($_.Group | Where-Object { $_.AccessVia -eq 'SharedWithMe' }).Count
                    AccessibleShare = @($_.Group | Where-Object { $_.AccessVia -eq 'AccessibleShare' }).Count
                    DirectGrant = @($_.Group | Where-Object { $_.AccessVia -eq 'DirectGrant' }).Count
                    Memberships = @($_.Group | Where-Object { $_.AccessVia -notin @('SharedWithMe', 'DirectGrant', 'SharedInsight', 'AccessibleShare') }).Count
                }
            } |
            Format-Table -AutoSize
    }

    Write-Host "`nTop exposure users (blast radius):" -ForegroundColor Green
    $users | Select-Object -First 20 DisplayName, UserPrincipalName, ObjectId, FindingCriticalCount, FindingHighCount, BlastScore, Severity, EdgeCount, RiskFlags |
        Format-Table -AutoSize

    Write-Host "`nTop resources (permission blast radius):" -ForegroundColor Green
    $resources | Select-Object -First 20 DisplayName, Type, BlastScore, Severity, PermissionFanIn, RiskFlags |
        Format-Table -AutoSize

    return $RunFolder
}
#endregion

#region Main
if (-not $CleanChildProcess -and -not $NoCleanRelaunch) {
    Start-ExposureGraphCleanProcess -ScriptPath $PSCommandPath
}

Write-Host '========================================' -ForegroundColor Cyan
Write-Host 'Copilot Tenant Exposure Graph Engine' -ForegroundColor Cyan
Write-Host 'Depth: B (site signals + capped content sample)' -ForegroundColor Cyan
Write-Host '========================================' -ForegroundColor Cyan

$Script:AuditTenant = Resolve-AuditTenantTarget -Name $TenantName
Write-AuditLog "Target tenant: Id=$($Script:AuditTenant.TenantId); Org=$(if ($Script:AuditTenant.OrganizationDomain) { $Script:AuditTenant.OrganizationDomain } else { '(resolve after Graph)' }); SPO prefix=$($Script:AuditTenant.SharePointPrefix)"
if ($TenantName -ne $Script:AuditTenant.SharePointPrefix -and -not (Test-LooksLikeGuid -Value $TenantName)) {
    Write-AuditLog "TenantName '$TenantName' normalized to SharePoint prefix '$($Script:AuditTenant.SharePointPrefix)'."
}

$timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$runFolder = Join-Path $OutputPath "run-$timestamp"

try {
    Connect-ExposureServices -TenantTarget $Script:AuditTenant
    if ($Script:ExitAfterGraphRegistration) {
        Write-AuditLog "`nDone (app registration only)."
        return
    }
    if ($BaselinePath) {
        $Script:AccessBaseline = @(Import-AccessBaseline -Path $BaselinePath)
        $Script:RunCoverage.BaselineLoaded = $true
        Write-AuditLog "Loaded $($Script:AccessBaseline.Count) baseline access row(s)."
    }
    Initialize-TargetUserScope

    Collect-PrivilegedRoles
    Collect-GroupsAndTeams
    Collect-TeamsAccess
    Collect-ExchangeDelegations
    Collect-SharePointSites
    Collect-OneDriveSamples
    Collect-SharePointLibrarySamples
    Collect-UserReachMap

    Export-ExposureGraph -RunFolder $runFolder -TenantLabel $TenantName `
        -TenantId $Script:AuditTenant.TenantId -OrganizationDomain $Script:AuditTenant.OrganizationDomain | Out-Null
    Write-AuditLog "`nDone."
}
catch {
    Write-AuditLog "Fatal: $($_.Exception.Message)" Error
    throw
}
#endregion
