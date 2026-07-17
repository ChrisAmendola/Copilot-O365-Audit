#Requires -Version 5.1
<#
.SYNOPSIS
    Legacy per-user Copilot permission audit (use copilot_audit.ps1 for tenant-wide runs).

.DESCRIPTION
    Audits Microsoft 365 permissions that expand Microsoft Copilot data exposure for a
    single user or all Copilot-licensed users. Uses Microsoft Graph, Exchange Online,
    and optionally PnP PowerShell. Combines heuristic risk rules with an optional baseline
    CSV for "should have" comparisons.

    Copilot can only surface content the user can already access; this script helps find
    over-permissioned users before or during Copilot rollouts.

    NOTE — Tenant-wide over-permissioning audits should use copilot_audit.ps1 (findings,
    coverage.json, executive-report.html, and tenant graph exports). This sibling script
    remains for legacy per-user deep dives when the single-user workflow is still needed.
.PARAMETER UserPrincipalName
    Audit a single user.
.PARAMETER AllCopilotLicensedUsers
    Audit all users assigned a Copilot-related license SKU.
.PARAMETER BaselineCsvPath
    CSV defining expected access. Columns: UserPrincipalName, ResourceType, ResourceId, ExpectedRole
    ResourceType: Group | Site | Team
    ResourceId: group GUID, site URL, team GUID, or display name match.
.PARAMETER TenantName
    SharePoint tenant prefix (e.g. contoso for contoso.sharepoint.com). Required for PnP scan.
.PARAMETER OutputPath
    Directory for CSV output files.
.PARAMETER IncludeSharePointSiteScan
    Deep scan of SharePoint site groups via PnP (slow on large tenants).
.PARAMETER IncludeBroadSharingScan
    Scan OneDrive for items shared with large audiences: org/anyone links, Everyone,
    All Users, All Company, and similar group grants (recursive, depth/item limits apply).
.PARAMETER IncludeSharePointBroadSharingScan
    Also scan SharePoint document libraries on sites the user can access (slow; requires PnP).
.PARAMETER PnPClientId
    Optional Entra app (client) ID for PnP.PowerShell sign-in. Defaults to the same app as
    your Microsoft Graph session, or the Microsoft Graph PowerShell public client.
.PARAMETER BroadSharingMaxItems
    Maximum number of drive/list items to inspect per library during broad-sharing scan.
.PARAMETER BroadSharingMaxDepth
    Maximum folder depth when recursing OneDrive and document libraries.
.PARAMETER BroadGroupNamePatterns
    Display names (regex alternation) treated as broad group sharing, e.g. Everyone, All Users.
.PARAMETER SensitiveNamePatterns
    Regex alternation used to flag sensitive group/site/team names in heuristics.
.EXAMPLE
    .\Copilot-OverPermissionAudit.ps1 -UserPrincipalName 'jsmith@contoso.com' -TenantName contoso
.EXAMPLE
    .\Copilot-OverPermissionAudit.ps1 -UserPrincipalName 'jsmith@contoso.com' -TenantName contoso `
        -IncludeSharePointBroadSharingScan
.NOTES
    Required modules (installed automatically if missing):
    - Microsoft.Graph.*
    - ExchangeOnlineManagement
    - PnP.PowerShell (when -IncludeSharePointSiteScan or SharePoint broad-sharing scan is used)
#>

[CmdletBinding(DefaultParameterSetName = 'Single')]
param(
    [Parameter(ParameterSetName = 'Single')]
    [string]$UserPrincipalName,

    [Parameter(ParameterSetName = 'Bulk')]
    [switch]$AllCopilotLicensedUsers,

    [switch]$CleanChildProcess,
    [switch]$NoCleanRelaunch,

    [string]$BaselineCsvPath,
    [Parameter(Mandatory)]
    [string]$TenantName,
    [string]$OutputPath = (Join-Path $PSScriptRoot 'CopilotAuditOutput'),
    [switch]$IncludeSharePointSiteScan,
    [switch]$IncludeBroadSharingScan = $true,
    [switch]$IncludeSharePointBroadSharingScan,
    [string]$PnPClientId,
    [int]$BroadSharingMaxItems = 500,
    [int]$BroadSharingMaxDepth = 8,
    [string[]]$BroadGroupNamePatterns = @(
        'Everyone',
        'Everyone except external users',
        'All Users',
        'All Company',
        'All Staff',
        'Company',
        'Authenticated Users',
        'Org-Wide',
        'Organization'
    ),
    [string[]]$SensitiveNamePatterns = @('Finance', 'HR', 'Legal', 'Executive', 'Payroll', 'M&A', 'Confidential', 'Board')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ($env:COPILOT_AUDIT_BROAD_PATTERNS) {
    $BroadGroupNamePatterns = $env:COPILOT_AUDIT_BROAD_PATTERNS -split [char]0x1F
    Remove-Item Env:COPILOT_AUDIT_BROAD_PATTERNS -ErrorAction SilentlyContinue
}
if ($env:COPILOT_AUDIT_SENSITIVE_PATTERNS) {
    $SensitiveNamePatterns = $env:COPILOT_AUDIT_SENSITIVE_PATTERNS -split [char]0x1F
    Remove-Item Env:COPILOT_AUDIT_SENSITIVE_PATTERNS -ErrorAction SilentlyContinue
}
if ($env:COPILOT_AUDIT_PNP_CLIENT_ID) {
    $PnPClientId = $env:COPILOT_AUDIT_PNP_CLIENT_ID
    Remove-Item Env:COPILOT_AUDIT_PNP_CLIENT_ID -ErrorAction SilentlyContinue
}

#region Configuration
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

$Script:HighSharePointPermissionNames = @(
    'Full Control',
    'Owner',
    'Manage Hierarchy',
    'Design'
)

$Script:SensitivePatternRegex = ($SensitiveNamePatterns | ForEach-Object { [regex]::Escape($_) }) -join '|'
$Script:BroadGroupPatternRegex = ($BroadGroupNamePatterns | ForEach-Object { [regex]::Escape($_) }) -join '|'
$Script:BroadShareLoginPatterns = @(
    'spo-grid-all-users',
    'spo-grid-all-members',
    'everyone\s+except\s+external',
    'c:0.*everyone',
    'sharinglinks'
)
$Script:ExchangeConnected = $false
$Script:PnPConnection = $null
$Script:PnPAvailable = $false
# Microsoft Graph PowerShell — present in most tenants after Connect-MgGraph.
$Script:DefaultPnPClientId = '14d82eec-204b-4c2f-b7e8-296a70dab67e'
$Script:GraphSubModules = @(
    'Microsoft.Graph.Authentication',
    'Microsoft.Graph.Users',
    'Microsoft.Graph.Groups',
    'Microsoft.Graph.Identity.DirectoryManagement',
    'Microsoft.Graph.Sites',
    'Microsoft.Graph.Teams'
)
#endregion

#region Logging and modules
function Write-AuditLog {
    param(
        [string]$Message,
        [ValidateSet('Info', 'Warn', 'Ok', 'Err')]
        [string]$Level = 'Info'
    )
    $color = switch ($Level) {
        'Info' { 'Cyan' }
        'Warn' { 'Yellow' }
        'Ok'   { 'Green' }
        'Err'  { 'Red' }
    }
    Write-Host $Message -ForegroundColor $color
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
    if ($authVersions.Count -gt 1) {
        Write-AuditLog "Multiple Microsoft.Graph.Authentication versions installed: $($authVersions -join ', ')" Warn
        Write-AuditLog "Using aligned version $version for this run." Info
    }

    Get-Module -Name 'Microsoft.Graph*' -ErrorAction SilentlyContinue |
        Remove-Module -Force -ErrorAction SilentlyContinue

    foreach ($subModule in $Script:GraphSubModules) {
        Import-Module -Name $subModule -RequiredVersion $version -Force -ErrorAction Stop
    }
}

function Start-CopilotAuditCleanProcess {
    param([string]$ScriptPath)

    Write-AuditLog 'Relaunching in an isolated -NoProfile PowerShell session (avoids Graph assembly conflicts)...' Info

    $shell = if ($PSVersionTable.PSEdition -eq 'Core') {
        (Get-Process -Id $PID).Path
    }
    else {
        Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    }

    $childArgs = @(
        '-NoProfile',
        '-NoLogo',
        '-ExecutionPolicy', 'Bypass',
        '-File', $ScriptPath,
        '-CleanChildProcess',
        '-TenantName', $TenantName
    )

    if ($UserPrincipalName) {
        $childArgs += '-UserPrincipalName', $UserPrincipalName
    }
    if ($AllCopilotLicensedUsers) {
        $childArgs += '-AllCopilotLicensedUsers'
    }
    if ($BaselineCsvPath) {
        $childArgs += '-BaselineCsvPath', $BaselineCsvPath
    }
    if ($OutputPath) {
        $childArgs += '-OutputPath', $OutputPath
    }
    if ($IncludeSharePointSiteScan) {
        $childArgs += '-IncludeSharePointSiteScan'
    }
    if ($IncludeSharePointBroadSharingScan) {
        $childArgs += '-IncludeSharePointBroadSharingScan'
    }
    if (-not $IncludeBroadSharingScan) {
        $childArgs += '-IncludeBroadSharingScan:$false'
    }
    if ($BroadSharingMaxItems -ne 500) {
        $childArgs += '-BroadSharingMaxItems', $BroadSharingMaxItems
    }
    if ($BroadSharingMaxDepth -ne 8) {
        $childArgs += '-BroadSharingMaxDepth', $BroadSharingMaxDepth
    }
    # Pattern arrays contain spaces (e.g. "Everyone except external users") and cannot be
    # forwarded safely on the command line; the child uses script defaults unless overridden
    # via environment variables when the caller explicitly passed custom patterns.
    if ($PSBoundParameters.ContainsKey('BroadGroupNamePatterns')) {
        $env:COPILOT_AUDIT_BROAD_PATTERNS = $BroadGroupNamePatterns -join [char]0x1F
    }
    if ($PSBoundParameters.ContainsKey('PnPClientId') -and $PnPClientId) {
        $env:COPILOT_AUDIT_PNP_CLIENT_ID = $PnPClientId
    }

    & $shell @childArgs
    exit $LASTEXITCODE
}

function Install-RequiredModules {
    Write-AuditLog 'Checking required modules...'

    try {
        if (-not (Get-Module -ListAvailable -Name 'Microsoft.Graph')) {
            Write-AuditLog 'Installing Microsoft.Graph bundle (keeps submodules on the same version)...' Warn
            Install-Module -Name 'Microsoft.Graph' -Scope CurrentUser -Force -AllowClobber -Repository PSGallery
        }

        Import-AlignedGraphModules

        if (-not (Get-Module -ListAvailable -Name 'ExchangeOnlineManagement')) {
            Write-AuditLog 'Installing ExchangeOnlineManagement...' Warn
            Install-Module -Name ExchangeOnlineManagement -Scope CurrentUser -Force -AllowClobber -Repository PSGallery
        }
        Import-Module ExchangeOnlineManagement -ErrorAction Stop

        if ($IncludeSharePointSiteScan -or $IncludeSharePointBroadSharingScan) {
            if (-not (Get-Module -ListAvailable -Name 'PnP.PowerShell')) {
                Write-AuditLog 'Installing PnP.PowerShell...' Warn
                Install-Module -Name PnP.PowerShell -Scope CurrentUser -Force -AllowClobber -Repository PSGallery
            }
            Import-Module PnP.PowerShell -ErrorAction Stop
        }

        return $true
    }
    catch {
        Write-AuditLog "Module setup failed: $($_.Exception.Message)" Err
        Write-AuditLog 'Try: Install-Module Microsoft.Graph -Scope CurrentUser -Force -AllowClobber' Warn
        Write-AuditLog 'If multiple Graph versions exist, remove old ones from the same PowerShell edition, then reinstall.' Warn
        return $false
    }
}

function Get-PnPClientId {
    if ($PnPClientId) {
        return $PnPClientId
    }

    $graphContext = Get-MgContext -ErrorAction SilentlyContinue
    if ($graphContext -and $graphContext.ClientId) {
        return [string]$graphContext.ClientId
    }

    return $Script:DefaultPnPClientId
}

function Get-SharePointAccessToken {
    param([string]$Url)

    if (-not (Get-Command Get-MgAccessToken -ErrorAction SilentlyContinue)) {
        return $null
    }

    $uri = [uri]$Url
    $resourceCandidates = @(
        "https://$($uri.Host)",
        $Url,
        "https://$TenantName.sharepoint.com",
        "https://$TenantName-admin.sharepoint.com"
    ) | Select-Object -Unique

    foreach ($resource in $resourceCandidates) {
        try {
            return Get-MgAccessToken -Resource $resource -ErrorAction Stop
        }
        catch {
            Write-AuditLog "Could not get SharePoint token for $resource : $($_.Exception.Message)" Warn
        }
    }

    return $null
}

function Connect-PnPSharePointOnline {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Url,
        [switch]$EstablishSession
    )

    if (-not $EstablishSession -and $Script:PnPConnection) {
        Connect-PnPOnline -Url $Url -Connection $Script:PnPConnection -ErrorAction Stop
        return
    }

    $token = Get-SharePointAccessToken -Url $Url
    if ($token) {
        try {
            $Script:PnPConnection = Connect-PnPOnline -Url $Url -AccessToken $token -ReturnConnection -ErrorAction Stop
            Write-AuditLog "SharePoint connected via Microsoft Graph token." Ok
            return
        }
        catch {
            Write-AuditLog "Graph token not accepted by PnP: $($_.Exception.Message)" Warn
        }
    }

    $clientId = Get-PnPClientId
    $baseParams = @{
        Url              = $Url
        ClientId         = $clientId
        ReturnConnection = $true
    }

    Write-AuditLog "Signing in to SharePoint at $Url (Entra app $clientId)..." Info
    try {
        $Script:PnPConnection = Connect-PnPOnline @baseParams -Interactive -ErrorAction Stop
    }
    catch {
        Write-AuditLog 'Interactive PnP sign-in failed in this host; using device login code...' Warn
        $Script:PnPConnection = Connect-PnPOnline @baseParams -DeviceLogin -ErrorAction Stop
    }
}

function Test-PnPSharePointConnectionActive {
    try {
        return $null -ne (Get-PnPConnection -ErrorAction Stop)
    }
    catch {
        return $false
    }
}

function Initialize-PnPSharePointConnection {
    param([switch]$Required)

    if (-not ($IncludeSharePointSiteScan -or $IncludeSharePointBroadSharingScan)) {
        return
    }

    if ($Script:PnPAvailable) {
        return
    }

    $adminUrl = "https://$TenantName-admin.sharepoint.com"
    Write-AuditLog "Connecting to SharePoint admin (PnP): $adminUrl"

    try {
        Connect-PnPSharePointOnline -Url $adminUrl -EstablishSession
        if (-not (Test-PnPSharePointConnectionActive)) {
            throw 'PnP connect returned without an active session.'
        }
        $Script:PnPAvailable = $true
    }
    catch {
        $Script:PnPAvailable = $false
        $Script:PnPConnection = $null
        $message = $_.Exception.Message
        if ($Required) {
            throw "SharePoint admin connection required but failed: $message"
        }
        Write-AuditLog "PnP admin connection unavailable: $message" Warn
        Write-AuditLog 'SharePoint broad-sharing will use Microsoft Graph only (team/group sites the user can access).' Warn
        Write-AuditLog 'For full tenant SharePoint scan, register an Entra app with SharePoint permissions and pass -PnPClientId.' Info
    }
}

function Connect-AuditServices {
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

    if (-not (Get-MgContext)) {
        Connect-MgGraph -Scopes $graphScopes -NoWelcome
    }

    Write-AuditLog 'Connecting to Exchange Online...'
    Connect-ExchangeOnline -ShowBanner:$false
    $Script:ExchangeConnected = $true

    # PnP admin is optional when only broad-sharing is enabled (Graph fallback exists).
    if ($IncludeSharePointSiteScan -or $IncludeSharePointBroadSharingScan) {
        Initialize-PnPSharePointConnection -Required:$IncludeSharePointSiteScan
    }
}
#endregion

#region Tenant name
function Resolve-SharePointTenantName {
    param([string]$Name)

    $normalized = $Name.Trim().TrimEnd('.')
    if ($normalized -match '^([^.]+)\.onmicrosoft\.com$') {
        return $Matches[1]
    }
    if ($normalized -match '^([^.]+)\.sharepoint\.com$') {
        return $Matches[1]
    }
    if ($normalized -match '\.') {
        $prefix = $normalized.Split('.')[0]
        Write-AuditLog "TenantName '$normalized' looks like a DNS domain; using SharePoint prefix '$prefix'." Warn
        Write-AuditLog 'If admin login fails, pass the prefix from https://<prefix>-admin.sharepoint.com' Info
        return $prefix
    }
    return $normalized
}
#endregion

#region Data helpers
function New-Finding {
    param(
        [string]$UserPrincipalName,
        [string]$DisplayName,
        [ValidateSet('Entra', 'Exchange', 'SharePoint', 'OneDrive', 'Teams', 'Baseline')]
        [string]$Workload,
        [string]$Resource,
        [string]$Permission,
        [ValidateSet('High', 'Medium', 'Low')]
        [string]$Risk,
        [ValidateSet('Heuristic', 'BaselineDelta', 'BaselineMissing', 'BroadSharing')]
        [string]$FindingType,
        [string]$CopilotImpact,
        [string]$Recommendation
    )

    [PSCustomObject]@{
        Timestamp         = (Get-Date).ToString('s')
        UserPrincipalName = $UserPrincipalName
        DisplayName       = $DisplayName
        Workload          = $Workload
        Resource          = $Resource
        Permission        = $Permission
        Risk              = $Risk
        FindingType       = $FindingType
        CopilotImpact     = $CopilotImpact
        Recommendation    = $Recommendation
    }
}

function Import-AccessBaseline {
    param([string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path)) {
        return @()
    }
    if (-not (Test-Path -LiteralPath $Path)) {
        throw "Baseline CSV not found: $Path"
    }

    Import-Csv -LiteralPath $Path | ForEach-Object {
        [PSCustomObject]@{
            UserPrincipalName = $_.UserPrincipalName.Trim()
            ResourceType      = $_.ResourceType.Trim()
            ResourceId          = $_.ResourceId.Trim()
            ExpectedRole        = $_.ExpectedRole.Trim()
        }
    }
}

function Get-CopilotLicensedUsers {
    $skus = Get-MgSubscribedSku -All
    $copilotSkuIds = @(
        $skus | Where-Object { $_.SkuPartNumber -match 'COPILOT' } | Select-Object -ExpandProperty SkuId
    )

    if ($copilotSkuIds.Count -eq 0) {
        Write-AuditLog 'No Copilot SKUs detected via SkuPartNumber *COPILOT*; falling back to all enabled users.' Warn
        return Get-MgUser -All -Property 'id,userPrincipalName,displayName,assignedLicenses,accountEnabled' |
            Where-Object { $_.AccountEnabled }
    }

    $users = Get-MgUser -All -Property 'id,userPrincipalName,displayName,assignedLicenses,accountEnabled'
    $users | Where-Object {
        $_.AccountEnabled -and
        ($_.AssignedLicenses.SkuId | Where-Object { $_ -in $copilotSkuIds })
    }
}

function Get-UserGroupMembershipIndex {
    param([string]$UserId)

    $groups = Get-MgUserTransitiveMemberOf -UserId $UserId -All |
        Where-Object { $_.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.group' }

    $index = @{}
    foreach ($g in $groups) {
        $index[$g.Id] = [PSCustomObject]@{
            Id          = $g.Id
            DisplayName = $g.AdditionalProperties.displayName
        }
    }
    return $index
}

function Test-ResourceMatchesBaseline {
    param(
        [object]$BaselineRow,
        [string]$ResourceId,
        [string]$ResourceName
    )

    $id = $BaselineRow.ResourceId
    return (
        $ResourceId -eq $id -or
        $ResourceName -eq $id -or
        ($ResourceName -and $ResourceName -like "*$id*") -or
        ($ResourceId -and $ResourceId -like "*$id*")
    )
}
#endregion

#region Entra / baseline
function Add-EntraHeuristicFindings {
    param(
        $User,
        [hashtable]$GroupIndex,
        [System.Collections.Generic.List[object]]$Findings
    )

    $roleMemberships = Get-MgUserMemberOf -UserId $User.Id -All |
        Where-Object { $_.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.directoryRole' }

    foreach ($roleRef in $roleMemberships) {
        $role = Get-MgDirectoryRole -DirectoryRoleId $roleRef.Id
        if ($Script:PrivilegedEntraRoles -contains $role.DisplayName) {
            $Findings.Add((New-Finding `
                -UserPrincipalName $User.UserPrincipalName `
                -DisplayName $User.DisplayName `
                -Workload Entra `
                -Resource $role.DisplayName `
                -Permission 'Directory role assignment' `
                -Risk High `
                -FindingType Heuristic `
                -CopilotImpact 'Elevated admin roles broaden tenant and content visibility surfaces' `
                -Recommendation 'Use PIM eligible assignments or remove standing admin role'))
        }
    }

    foreach ($group in $GroupIndex.Values) {
        if ($group.DisplayName -match $Script:SensitivePatternRegex) {
            $Findings.Add((New-Finding `
                -UserPrincipalName $User.UserPrincipalName `
                -DisplayName $User.DisplayName `
                -Workload Entra `
                -Resource "Group: $($group.DisplayName)" `
                -Permission 'Transitive member' `
                -Risk Medium `
                -FindingType Heuristic `
                -CopilotImpact 'Group may grant SharePoint, Teams, or mail access Copilot can index' `
                -Recommendation 'Validate membership against job function'))
        }
    }

    $ownedObjects = Get-MgUserOwnedObject -UserId $User.Id -All -ErrorAction SilentlyContinue |
        Where-Object { $_.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.group' }

    foreach ($owned in $ownedObjects) {
        $name = $owned.AdditionalProperties.displayName
        $Findings.Add((New-Finding `
            -UserPrincipalName $User.UserPrincipalName `
            -DisplayName $User.DisplayName `
            -Workload Entra `
            -Resource "Group owner: $name" `
            -Permission 'Owner' `
            -Risk Medium `
            -FindingType Heuristic `
            -CopilotImpact 'Group ownership often implies edit/manage on linked Teams and sites' `
            -Recommendation 'Confirm ownership is required for this user'))
    }
}

function Add-BaselineFindings {
    param(
        $User,
        [object[]]$Baseline,
        [hashtable]$GroupIndex,
        [System.Collections.Generic.List[object]]$Findings
    )

    if (-not $Baseline -or $Baseline.Count -eq 0) {
        return
    }

    $userBaseline = @($Baseline | Where-Object { $_.UserPrincipalName -eq $User.UserPrincipalName })
    if ($userBaseline.Count -eq 0) {
        return
    }

    foreach ($row in $userBaseline) {
        $matched = $false
        switch ($row.ResourceType) {
            'Group' {
                foreach ($group in $GroupIndex.Values) {
                    if (Test-ResourceMatchesBaseline -BaselineRow $row -ResourceId $group.Id -ResourceName $group.DisplayName) {
                        $matched = $true
                        break
                    }
                }
            }
            'Team' {
                $teams = Get-MgUserJoinedTeam -UserId $User.Id -All -ErrorAction SilentlyContinue
                foreach ($team in $teams) {
                    if (Test-ResourceMatchesBaseline -BaselineRow $row -ResourceId $team.Id -ResourceName $team.DisplayName) {
                        $matched = $true
                        break
                    }
                }
            }
            'Site' {
                # Site URL baseline rows require -IncludeSharePointSiteScan for validation.
                if (-not $IncludeSharePointSiteScan) {
                    $matched = $true
                }
            }
            default {
                Write-AuditLog "Unknown baseline ResourceType '$($row.ResourceType)' for $($User.UserPrincipalName)" Warn
            }
        }

        if (-not $matched) {
            $Findings.Add((New-Finding `
                -UserPrincipalName $User.UserPrincipalName `
                -DisplayName $User.DisplayName `
                -Workload Baseline `
                -Resource "$($row.ResourceType): $($row.ResourceId)" `
                -Permission "Expected: $($row.ExpectedRole)" `
                -Risk Low `
                -FindingType BaselineMissing `
                -CopilotImpact 'Expected access not found; may indicate provisioning gap (under-permissioned)' `
                -Recommendation 'Confirm user should have this access and remediate if required'))
        }
    }

    foreach ($group in $GroupIndex.Values) {
        if ($group.DisplayName -notmatch $Script:SensitivePatternRegex) {
            continue
        }

        $listed = $userBaseline | Where-Object {
            $_.ResourceType -eq 'Group' -and
            (Test-ResourceMatchesBaseline -BaselineRow $_ -ResourceId $group.Id -ResourceName $group.DisplayName)
        }

        if (-not $listed) {
            $Findings.Add((New-Finding `
                -UserPrincipalName $User.UserPrincipalName `
                -DisplayName $User.DisplayName `
                -Workload Baseline `
                -Resource "Group: $($group.DisplayName)" `
                -Permission 'Member (not in baseline)' `
                -Risk Medium `
                -FindingType BaselineDelta `
                -CopilotImpact 'Sensitive group access not listed in approved baseline' `
                -Recommendation 'Remove access or add to baseline with approval'))
        }
    }
}
#endregion

#region Teams
function Add-TeamsFindings {
    param(
        $User,
        [System.Collections.Generic.List[object]]$Findings
    )

    $teams = Get-MgUserJoinedTeam -UserId $User.Id -All -ErrorAction SilentlyContinue
    foreach ($team in $teams) {
        $members = Get-MgTeamMember -TeamId $team.Id -All
        $membership = $members | Where-Object {
            $_.UserId -eq $User.Id -or
            ($_.AdditionalProperties.email -eq $User.UserPrincipalName)
        } | Select-Object -First 1

        if ($membership -and ($membership.Roles -contains 'owner')) {
            $risk = if ($team.DisplayName -match $Script:SensitivePatternRegex) { 'High' } else { 'Medium' }
            $Findings.Add((New-Finding `
                -UserPrincipalName $User.UserPrincipalName `
                -DisplayName $User.DisplayName `
                -Workload Teams `
                -Resource $team.DisplayName `
                -Permission 'Team owner' `
                -Risk $risk `
                -FindingType Heuristic `
                -CopilotImpact 'Owners can access team files, chats, and channel content Copilot may surface' `
                -Recommendation 'Demote to member if ownership is not required'))
        }
    }
}
#endregion

#region Broad sharing detection
function Get-GraphObjectProperty {
    param(
        $Object,
        [string]$PropertyName
    )

    if ($null -eq $Object) {
        return $null
    }

    $property = $Object.PSObject.Properties |
        Where-Object { $_.Name -ieq $PropertyName } |
        Select-Object -First 1

    if ($property) {
        return $property.Value
    }

    return $null
}

function Test-IsBroadGroupName {
    param([string]$Name)

    if ([string]::IsNullOrWhiteSpace($Name)) {
        return $false
    }
    return $Name -match $Script:BroadGroupPatternRegex
}

function Test-IsBroadShareLoginName {
    param([string]$LoginName)

    if ([string]::IsNullOrWhiteSpace($LoginName)) {
        return $false
    }

    foreach ($pattern in $Script:BroadShareLoginPatterns) {
        if ($LoginName -match $pattern) {
            return $true
        }
    }
    return $false
}

function Get-GraphPermissionBroadSharingGrants {
    param($Permission)

    $grants = [System.Collections.Generic.List[object]]::new()
    if ($null -eq $Permission) {
        return $grants
    }

    $link = Get-GraphObjectProperty -Object $Permission -PropertyName 'link'
    $linkScope = Get-GraphObjectProperty -Object $link -PropertyName 'scope'

    if ($linkScope -and ($linkScope -in @('organization', 'anonymous'))) {
        $roles = @(Get-GraphObjectProperty -Object $Permission -PropertyName 'roles')
        $grants.Add([PSCustomObject]@{
            GrantType   = 'SharingLink'
            Grantee     = $linkScope
            Detail      = "Sharing link scope: $linkScope"
            Roles       = ($roles | Where-Object { $_ } | Select-Object -Unique) -join ','
            Risk        = if ($linkScope -eq 'anonymous') { 'High' } else { 'Medium' }
        })
    }

    $identitySets = [System.Collections.Generic.List[object]]::new()
    foreach ($propName in @('grantedToIdentitiesV2', 'grantedToIdentities', 'grantedToV2', 'grantedTo')) {
        $collection = Get-GraphObjectProperty -Object $Permission -PropertyName $propName
        if ($collection) {
            foreach ($entry in @($collection)) {
                $identitySets.Add($entry)
            }
        }
    }

    $permissionRoles = @(Get-GraphObjectProperty -Object $Permission -PropertyName 'roles')
    $permissionRolesText = ($permissionRoles | Where-Object { $_ } | Select-Object -Unique) -join ','

    foreach ($identitySet in $identitySets) {
        foreach ($entityType in @('siteGroup', 'group', 'user')) {
            $entity = Get-GraphObjectProperty -Object $identitySet -PropertyName $entityType
            if (-not $entity) {
                continue
            }

            $displayName = Get-GraphObjectProperty -Object $entity -PropertyName 'displayName'
            $loginName = Get-GraphObjectProperty -Object $entity -PropertyName 'loginName'
            $entityId = Get-GraphObjectProperty -Object $entity -PropertyName 'id'

            if (Test-IsBroadGroupName -Name $displayName) {
                $grants.Add([PSCustomObject]@{
                    GrantType = 'BroadGroup'
                    Grantee   = $displayName
                    Detail    = "Direct grant to group/site group: $displayName"
                    Roles     = $permissionRolesText
                    Risk      = 'High'
                })
            }
            elseif (Test-IsBroadShareLoginName -LoginName $loginName) {
                $grants.Add([PSCustomObject]@{
                    GrantType = 'BroadPrincipal'
                    Grantee   = $(if ($displayName) { $displayName } else { $loginName })
                    Detail    = "Broad SharePoint principal: $loginName"
                    Roles     = $permissionRolesText
                    Risk      = 'High'
                })
            }
            elseif ($entityType -eq 'group' -and $entityId) {
                try {
                    $group = Get-MgGroup -GroupId $entityId -Property 'displayName,mailEnabled,securityEnabled' -ErrorAction SilentlyContinue
                    if ($group -and (Test-IsBroadGroupName -Name $group.DisplayName)) {
                        $grants.Add([PSCustomObject]@{
                            GrantType = 'BroadGroup'
                            Grantee   = $group.DisplayName
                            Detail    = "Direct grant to Entra group: $($group.DisplayName)"
                            Roles     = $permissionRolesText
                            Risk      = 'High'
                        })
                    }
                }
                catch {
                    # Group lookup is best-effort only.
                }
            }
        }
    }

    return $grants
}

function Add-BroadSharingFindingFromGrant {
    param(
        $User,
        [ValidateSet('OneDrive', 'SharePoint')]
        [string]$Workload,
        [string]$ItemPath,
        [string]$ItemUrl,
        $Grant,
        [System.Collections.Generic.List[object]]$Findings
    )

    $Findings.Add((New-Finding `
        -UserPrincipalName $User.UserPrincipalName `
        -DisplayName $User.DisplayName `
        -Workload $Workload `
        -Resource "$ItemPath | $ItemUrl" `
        -Permission "$($Grant.GrantType): $($Grant.Grantee) [$($Grant.Detail)] Roles=$($Grant.Roles)" `
        -Risk $Grant.Risk `
        -FindingType BroadSharing `
        -CopilotImpact 'Content shared with a large audience is discoverable via search and Copilot' `
        -Recommendation 'Remove Everyone/All Users/org-wide sharing; share with specific people or security groups'))
}

function Resolve-GraphDriveRootItemId {
    param(
        [string]$DriveId,
        [string]$UserId,
        [ValidateSet('OneDrive', 'SharePoint')]
        [string]$Workload
    )

    if ($Workload -eq 'OneDrive' -and $UserId) {
        if (-not $DriveId) {
            $DriveId = (Get-MgUserDrive -UserId $UserId -ErrorAction Stop).Id
        }
        return (Get-MgUserDriveRoot -UserId $UserId -DriveId $DriveId -ErrorAction Stop).Id
    }

    return (Get-MgDriveRoot -DriveId $DriveId -ErrorAction Stop).Id
}

function Get-GraphDriveItemChildren {
    param(
        [string]$DriveId,
        [string]$ItemId,
        [string]$UserId,
        [ValidateSet('OneDrive', 'SharePoint')]
        [string]$Workload
    )

    $propertySet = 'id,name,folder,file,webUrl'
    if ($Workload -eq 'OneDrive' -and $UserId) {
        return Get-MgUserDriveItemChild `
            -UserId $UserId `
            -DriveId $DriveId `
            -DriveItemId $ItemId `
            -All `
            -Property $propertySet `
            -ErrorAction Stop
    }

    return Get-MgDriveItemChild `
        -DriveId $DriveId `
        -DriveItemId $ItemId `
        -All `
        -Property $propertySet `
        -ErrorAction Stop
}

function Get-GraphDriveItemPermissions {
    param(
        [string]$DriveId,
        [string]$ItemId,
        [string]$UserId,
        [ValidateSet('OneDrive', 'SharePoint')]
        [string]$Workload
    )

    if ($Workload -eq 'OneDrive' -and $UserId) {
        return Get-MgUserDriveItemPermission `
            -UserId $UserId `
            -DriveId $DriveId `
            -DriveItemId $ItemId `
            -ErrorAction SilentlyContinue
    }

    return Get-MgDriveItemPermission `
        -DriveId $DriveId `
        -DriveItemId $ItemId `
        -ErrorAction SilentlyContinue
}

function Get-UserOneDriveDriveContext {
    param($User)

    try {
        $drive = Get-MgUserDrive -UserId $User.Id -ErrorAction Stop
        if ($drive -and $drive.Id) {
            return [PSCustomObject]@{
                DriveId     = $drive.Id
                Method      = 'UserDrive'
                StorageUsed = $drive.Quota.Used
            }
        }
    }
    catch {
        Write-AuditLog "  Get-MgUserDrive: $($_.Exception.Message)" Warn
    }

    try {
        $driveUri = "https://graph.microsoft.com/v1.0/users/$($User.Id)/drive"
        $drive = Invoke-MgGraphRequest -Method GET -Uri $driveUri -ErrorAction Stop
        $driveId = Get-GraphObjectProperty -Object $drive -PropertyName 'id'
        if ($driveId) {
            $quota = Get-GraphObjectProperty -Object $drive -PropertyName 'quota'
            return [PSCustomObject]@{
                DriveId     = $driveId
                Method      = 'UserDriveRest'
                StorageUsed = Get-GraphObjectProperty -Object $quota -PropertyName 'used'
            }
        }
    }
    catch {
        Write-AuditLog "  User /drive endpoint: $($_.Exception.Message)" Warn
    }

    try {
        $fullUser = Get-MgUser -UserId $User.Id -Property 'mySite' -ErrorAction Stop
        if (-not $fullUser.MySite) {
            return $null
        }

        $siteUri = [uri]$fullUser.MySite
        $siteId = "$($siteUri.Host):$($siteUri.AbsolutePath.TrimEnd('/'))"
        $graphSite = Get-MgSite -SiteId $siteId -ErrorAction Stop
        $drive = Get-MgSiteDrive -SiteId $graphSite.Id -ErrorAction Stop
        if ($drive -and $drive.Id) {
            return [PSCustomObject]@{
                DriveId     = $drive.Id
                Method      = 'PersonalSite'
                StorageUsed = $drive.Quota.Used
            }
        }
    }
    catch {
        Write-AuditLog "  Personal site drive: $($_.Exception.Message)" Warn
    }

    return $null
}

function Get-GraphDriveChildrenByDriveId {
    param(
        [string]$DriveId,
        [string]$ItemId = 'root'
    )

    if ($ItemId -eq 'root') {
        $uri = "https://graph.microsoft.com/v1.0/drives/$DriveId/root/children"
    }
    else {
        $uri = "https://graph.microsoft.com/v1.0/drives/$DriveId/items/$ItemId/children"
    }

    $children = [System.Collections.Generic.List[object]]::new()
    while ($uri) {
        $response = Invoke-MgGraphRequest -Method GET -Uri $uri -ErrorAction Stop
        $pageItems = Get-GraphObjectProperty -Object $response -PropertyName 'value'
        if ($pageItems) {
            foreach ($item in @($pageItems)) {
                $children.Add($item)
            }
        }
        $uri = Get-GraphObjectProperty -Object $response -PropertyName '@odata.nextLink'
    }

    return $children
}

function Get-GraphDriveItemPermissionsByDriveId {
    param(
        [string]$DriveId,
        [string]$ItemId = 'root'
    )

    if ($ItemId -eq 'root') {
        $uri = "https://graph.microsoft.com/v1.0/drives/$DriveId/root/permissions"
    }
    else {
        $uri = "https://graph.microsoft.com/v1.0/drives/$DriveId/items/$ItemId/permissions"
    }

    try {
        $response = Invoke-MgGraphRequest -Method GET -Uri $uri -ErrorAction Stop
        $permissions = Get-GraphObjectProperty -Object $response -PropertyName 'value'
        if ($permissions) {
            return @($permissions)
        }
        return @()
    }
    catch {
        return @()
    }
}

function Get-GraphUserDriveChildren {
    param(
        $User,
        [string]$ItemId = 'root'
    )

    $userKey = [uri]::EscapeDataString($User.Id)
    if ($ItemId -eq 'root') {
        $uri = "https://graph.microsoft.com/v1.0/users/$userKey/drive/root/children"
    }
    else {
        $uri = "https://graph.microsoft.com/v1.0/users/$userKey/drive/items/$ItemId/children"
    }

    $children = [System.Collections.Generic.List[object]]::new()
    while ($uri) {
        $response = Invoke-MgGraphRequest -Method GET -Uri $uri -ErrorAction Stop
        $pageItems = Get-GraphObjectProperty -Object $response -PropertyName 'value'
        if ($pageItems) {
            foreach ($item in @($pageItems)) {
                $children.Add($item)
            }
        }
        $uri = Get-GraphObjectProperty -Object $response -PropertyName '@odata.nextLink'
    }

    return $children
}

function Get-GraphUserDriveItemPermissions {
    param(
        $User,
        [string]$ItemId = 'root'
    )

    $userKey = [uri]::EscapeDataString($User.Id)
    if ($ItemId -eq 'root') {
        $uri = "https://graph.microsoft.com/v1.0/users/$userKey/drive/root/permissions"
    }
    else {
        $uri = "https://graph.microsoft.com/v1.0/users/$userKey/drive/items/$ItemId/permissions"
    }

    try {
        $response = Invoke-MgGraphRequest -Method GET -Uri $uri -ErrorAction Stop
        $permissions = Get-GraphObjectProperty -Object $response -PropertyName 'value'
        if ($permissions) {
            return @($permissions)
        }
        return @()
    }
    catch {
        return @()
    }
}

function Search-OneDriveBroadSharingGraph {
    param(
        $User,
        [Parameter(Mandatory)]
        [string]$DriveId,
        [string]$ItemId = 'root',
        [string]$ItemPath = '\',
        [int]$Depth = 0,
        [int]$MaxItems,
        [ref]$ItemsScanned,
        [System.Collections.Generic.List[object]]$Findings
    )

    if (-not $PSBoundParameters.ContainsKey('MaxItems')) {
        $MaxItems = $BroadSharingMaxItems
    }

    if ($ItemsScanned.Value -ge $MaxItems -or $Depth -gt $BroadSharingMaxDepth) {
        return
    }

    foreach ($permission in (Get-GraphUserDriveItemPermissions -User $User -ItemId $ItemId)) {
        try {
            foreach ($grant in (Get-GraphPermissionBroadSharingGrants -Permission $permission)) {
                Add-BroadSharingFindingFromGrant `
                    -User $User `
                    -Workload OneDrive `
                    -ItemPath $ItemPath `
                    -ItemUrl "onedrive:$ItemId" `
                    -Grant $grant `
                    -Findings $Findings
            }
        }
        catch {
            Write-AuditLog "Skipped permission on '$ItemPath': $($_.Exception.Message)" Warn
        }
    }

    try {
        $children = Get-GraphUserDriveChildren -User $User -ItemId $ItemId
    }
    catch {
        Write-AuditLog "OneDrive crawl stopped at '$ItemPath': $($_.Exception.Message)" Warn
        return
    }

    if ($ItemId -eq 'root' -and $children.Count -eq 0) {
        try {
            $children = Get-GraphDriveChildrenByDriveId -DriveId $DriveId -ItemId $ItemId
            if ($children.Count -gt 0) {
                Write-AuditLog '  Listed root via /drives/{id} fallback (user-scoped path returned empty).' Info
            }
        }
        catch {
            Write-AuditLog "  Drive-scoped root listing fallback failed: $($_.Exception.Message)" Warn
        }
    }

    foreach ($child in $children) {
        if ($ItemsScanned.Value -ge $MaxItems) {
            return
        }

        $ItemsScanned.Value++
        $childName = Get-GraphObjectProperty -Object $child -PropertyName 'name'
        $childPath = if ($ItemPath -eq '\') { $childName } else { Join-Path $ItemPath $childName }
        $childId = Get-GraphObjectProperty -Object $child -PropertyName 'id'
        $childWebUrl = Get-GraphObjectProperty -Object $child -PropertyName 'webUrl'

        foreach ($permission in (Get-GraphUserDriveItemPermissions -User $User -ItemId $childId)) {
            try {
                foreach ($grant in (Get-GraphPermissionBroadSharingGrants -Permission $permission)) {
                    Add-BroadSharingFindingFromGrant `
                        -User $User `
                        -Workload OneDrive `
                        -ItemPath $childPath `
                        -ItemUrl $(if ($childWebUrl) { $childWebUrl } else { "onedrive:$childId" }) `
                        -Grant $grant `
                        -Findings $Findings
                }
            }
            catch {
                Write-AuditLog "Skipped permission on '$childPath': $($_.Exception.Message)" Warn
            }
        }

        if (Get-GraphObjectProperty -Object $child -PropertyName 'folder') {
            Search-OneDriveBroadSharingGraph `
                -User $User `
                -DriveId $DriveId `
                -ItemId $childId `
                -ItemPath $childPath `
                -Depth ($Depth + 1) `
                -MaxItems $MaxItems `
                -ItemsScanned $ItemsScanned `
                -Findings $Findings
        }
    }
}

function Search-GraphDriveBroadSharing {
    param(
        $User,
        [string]$DriveId,
        [ValidateSet('OneDrive', 'SharePoint')]
        [string]$Workload,
        [string]$ItemId = 'root',
        [string]$ItemPath = '\',
        [int]$Depth = 0,
        [int]$MaxItems,
        [ref]$ItemsScanned,
        [System.Collections.Generic.List[object]]$Findings
    )

    if (-not $PSBoundParameters.ContainsKey('MaxItems')) {
        $MaxItems = $BroadSharingMaxItems
    }

    if ($ItemsScanned.Value -ge $MaxItems) {
        return
    }
    if ($Depth -gt $BroadSharingMaxDepth) {
        return
    }

    if ($ItemId -eq 'root') {
        try {
            $ItemId = Resolve-GraphDriveRootItemId -DriveId $DriveId -UserId $User.Id -Workload $Workload
        }
        catch {
            Write-AuditLog "Could not resolve drive root for $Workload at '$ItemPath': $($_.Exception.Message)" Warn
            return
        }
    }

    try {
        $permissions = Get-GraphDriveItemPermissions `
            -DriveId $DriveId `
            -ItemId $ItemId `
            -UserId $User.Id `
            -Workload $Workload
        foreach ($permission in $permissions) {
            foreach ($grant in (Get-GraphPermissionBroadSharingGrants -Permission $permission)) {
                Add-BroadSharingFindingFromGrant `
                    -User $User `
                    -Workload $Workload `
                    -ItemPath $ItemPath `
                    -ItemUrl "(drive item $ItemId)" `
                    -Grant $grant `
                    -Findings $Findings
            }
        }
    }
    catch {
        # Item may not expose permissions to the caller.
    }

    try {
        $children = Get-GraphDriveItemChildren `
            -DriveId $DriveId `
            -ItemId $ItemId `
            -UserId $User.Id `
            -Workload $Workload

        foreach ($child in $children) {
            if ($ItemsScanned.Value -ge $MaxItems) {
                return
            }

            $ItemsScanned.Value++
            $childPath = Join-Path $ItemPath $child.Name

            try {
                $childPermissions = Get-GraphDriveItemPermissions `
                    -DriveId $DriveId `
                    -ItemId $child.Id `
                    -UserId $User.Id `
                    -Workload $Workload
                foreach ($permission in $childPermissions) {
                    foreach ($grant in (Get-GraphPermissionBroadSharingGrants -Permission $permission)) {
                        Add-BroadSharingFindingFromGrant `
                            -User $User `
                            -Workload $Workload `
                            -ItemPath $childPath `
                            -ItemUrl $child.WebUrl `
                            -Grant $grant `
                            -Findings $Findings
                    }
                }
            }
            catch {
                # Continue scanning siblings.
            }

            if ($child.Folder) {
                Search-GraphDriveBroadSharing `
                    -User $User `
                    -DriveId $DriveId `
                    -Workload $Workload `
                    -ItemId $child.Id `
                    -ItemPath $childPath `
                    -Depth ($Depth + 1) `
                    -ItemsScanned $ItemsScanned `
                    -Findings $Findings
            }
        }
    }
    catch {
        Write-AuditLog "Drive crawl stopped at '$ItemPath': $($_.Exception.Message)" Warn
    }
}

function Add-OneDriveBroadSharingFindings {
    param(
        $User,
        [System.Collections.Generic.List[object]]$Findings
    )

    Write-AuditLog "Broad-sharing scan: OneDrive for $($User.UserPrincipalName) (max $BroadSharingMaxItems items, depth $BroadSharingMaxDepth)..." Info

    try {
        $driveContext = Get-UserOneDriveDriveContext -User $User
        if (-not $driveContext) {
            Write-AuditLog "  OneDrive not provisioned or not accessible for $($User.UserPrincipalName)." Warn
            return
        }

        $usedMb = if ($driveContext.StorageUsed) { [math]::Round($driveContext.StorageUsed / 1MB, 2) } else { 0 }
        Write-AuditLog "  OneDrive resolved via $($driveContext.Method); drive $($driveContext.DriveId); ~${usedMb} MB used" Info

        try {
            $rootProbe = @(Get-MgUserDriveRootChild -UserId $User.Id -DriveId $driveContext.DriveId -Top 5 -ErrorAction Stop)
            Write-AuditLog "  Root probe (SDK): $($rootProbe.Count) item(s) on first page" Info
        }
        catch {
            Write-AuditLog "  Root probe (SDK) failed: $($_.Exception.Message)" Warn
        }

        $itemsScanned = [ref]0
        Search-OneDriveBroadSharingGraph `
            -User $User `
            -DriveId $driveContext.DriveId `
            -ItemsScanned $itemsScanned `
            -Findings $Findings

        Write-AuditLog "  OneDrive items inspected: $($itemsScanned.Value)" Info

        if ($itemsScanned.Value -eq 0 -and $driveContext.StorageUsed -gt 0) {
            Write-AuditLog '  Drive reports stored content but no items were listed. Confirm Graph Sites.Read.All / Files.Read.All for the signed-in admin.' Warn
        }
        elseif ($itemsScanned.Value -eq 0) {
            Write-AuditLog '  OneDrive root appears empty (no child items to scan).' Info
        }
    }
    catch {
        Write-AuditLog "OneDrive broad-sharing scan skipped for $($User.UserPrincipalName): $($_.Exception.Message)" Warn
    }
}

function Get-UserAccessibleSharePointSitesGraph {
    param($User)

    $sitesById = @{}

    $teams = @(Get-MgUserJoinedTeam -UserId $User.Id -All -ErrorAction SilentlyContinue)
    foreach ($team in $teams) {
        try {
            $site = Get-MgGroupSite -GroupId $team.Id -ErrorAction Stop
            if ($site) {
                $sitesById[$site.Id] = [PSCustomObject]@{
                    GraphSite = $site
                    Title     = $team.DisplayName
                    Source    = 'Team'
                }
            }
        }
        catch {
            Write-AuditLog "Could not resolve SharePoint site for team $($team.DisplayName): $($_.Exception.Message)" Warn
        }
    }

    $groups = Get-MgUserTransitiveMemberOf -UserId $User.Id -All -ErrorAction SilentlyContinue |
        Where-Object { $_.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.group' }

    foreach ($groupRef in $groups) {
        try {
            $site = Get-MgGroupSite -GroupId $groupRef.Id -ErrorAction Stop
            if ($site -and -not $sitesById.ContainsKey($site.Id)) {
                $sitesById[$site.Id] = [PSCustomObject]@{
                    GraphSite = $site
                    Title     = $groupRef.AdditionalProperties.displayName
                    Source    = 'Group'
                }
            }
        }
        catch {
            # Not every group has a SharePoint site.
        }
    }

    if ($sitesById.Count -eq 0) {
        return @()
    }

    return @($sitesById.Values)
}

function Add-SharePointBroadSharingFindingsGraph {
    param(
        $User,
        [System.Collections.Generic.List[object]]$Findings
    )

    Write-AuditLog "Broad-sharing scan (Graph): team/group sites for $($User.UserPrincipalName)..." Info

    $sites = @(Get-UserAccessibleSharePointSitesGraph -User $User)
    if ($sites.Count -eq 0) {
        Write-AuditLog '  No team/group SharePoint sites found via Graph.' Info
        return
    }

    $itemsScanned = 0
    foreach ($siteEntry in $sites) {
        if ($itemsScanned -ge $BroadSharingMaxItems) {
            break
        }

        try {
            $drive = Get-MgSiteDrive -SiteId $siteEntry.GraphSite.Id -ErrorAction Stop
            if (-not $drive) {
                continue
            }

            $remaining = $BroadSharingMaxItems - $itemsScanned
            $localScanned = [ref]0
            Search-GraphDriveBroadSharing `
                -User $User `
                -DriveId $drive.Id `
                -Workload SharePoint `
                -ItemPath "$($siteEntry.Title)\Documents ($($siteEntry.Source))" `
                -MaxItems $remaining `
                -ItemsScanned $localScanned `
                -Findings $Findings
            $itemsScanned += $localScanned.Value
        }
        catch {
            Write-AuditLog "Graph drive scan skipped for $($siteEntry.Title): $($_.Exception.Message)" Warn
        }
    }

    Write-AuditLog "  SharePoint items inspected via Graph: $itemsScanned" Info
}

function Add-SharePointBroadSharingFindingsPnP {
    param(
        $User,
        [System.Collections.Generic.List[object]]$Findings
    )

    if (-not (Test-PnPSharePointConnectionActive)) {
        Write-AuditLog 'PnP session not active; skipping tenant SharePoint scan.' Warn
        $Script:PnPAvailable = $false
        return
    }

    Write-AuditLog "Broad-sharing scan (PnP tenant): libraries on sites $($User.UserPrincipalName) can access..." Info

    try {
        $sites = @(Get-PnPTenantSite | Where-Object { $_.Template -notmatch 'RedirectSite|PERSONAL' })
    }
    catch {
        Write-AuditLog "PnP tenant site enumeration failed: $($_.Exception.Message)" Warn
        $Script:PnPAvailable = $false
        return
    }

    $itemsScanned = 0

    foreach ($site in $sites) {
        if ($itemsScanned -ge $BroadSharingMaxItems) {
            break
        }

        try {
            Connect-PnPSharePointOnline -Url $site.Url -ErrorAction Stop
            $pnpUser = Get-PnPUser -Identity $User.UserPrincipalName -ErrorAction SilentlyContinue
            if (-not $pnpUser) {
                continue
            }

            $uri = [uri]$site.Url
            $graphSiteId = "$($uri.Host):$($uri.AbsolutePath.TrimEnd('/'))"
            $graphSite = Get-MgSite -SiteId $graphSiteId -ErrorAction SilentlyContinue

            if ($graphSite) {
                $drive = Get-MgSiteDrive -SiteId $graphSite.Id -ErrorAction SilentlyContinue
                if ($drive) {
                    $remaining = $BroadSharingMaxItems - $itemsScanned
                    $localScanned = [ref]0
                    Search-GraphDriveBroadSharing `
                        -User $User `
                        -DriveId $drive.Id `
                        -Workload SharePoint `
                        -ItemPath "$($site.Title)\Documents" `
                        -MaxItems $remaining `
                        -ItemsScanned $localScanned `
                        -Findings $Findings
                    $itemsScanned += $localScanned.Value
                }
            }

            $lists = Get-PnPList -ErrorAction SilentlyContinue |
                Where-Object { -not $_.Hidden -and $_.BaseTemplate -eq 101 }

            foreach ($list in $lists) {
                if ($itemsScanned -ge $BroadSharingMaxItems) {
                    break
                }

                $listItems = Get-PnPListItem -List $list -PageSize 100 -ErrorAction SilentlyContinue |
                    Select-Object -First ([Math]::Max(1, $BroadSharingMaxItems - $itemsScanned))

                foreach ($listItem in $listItems) {
                    if ($itemsScanned -ge $BroadSharingMaxItems) {
                        break
                    }
                    $itemsScanned++

                    $fileName = $listItem.FieldValues.FileLeafRef
                    if (-not $fileName) {
                        continue
                    }

                    $fileRef = $listItem.FieldValues.FileRef
                    $roleAssignments = Get-PnPProperty -ClientObject $listItem -Property RoleAssignments -ErrorAction SilentlyContinue
                    if (-not $roleAssignments) {
                        continue
                    }

                    foreach ($assignment in $roleAssignments) {
                        $member = Get-PnPProperty -ClientObject $assignment -Property Member -ErrorAction SilentlyContinue
                        $roleBindings = Get-PnPProperty -ClientObject $assignment -Property RoleDefinitionBindings -ErrorAction SilentlyContinue
                        if (-not $member) {
                            continue
                        }

                        $memberTitle = $member.Title
                        $memberLogin = $member.LoginName
                        $rights = @($roleBindings | ForEach-Object { $_.Name }) -join ','

                        $isBroad = (Test-IsBroadGroupName -Name $memberTitle) -or
                            (Test-IsBroadShareLoginName -LoginName $memberLogin)

                        if (-not $isBroad) {
                            continue
                        }

                        $grant = [PSCustomObject]@{
                            GrantType = 'SharePointRoleAssignment'
                            Grantee   = $(if ($memberTitle) { $memberTitle } else { $memberLogin })
                            Detail    = "Unique permission on list item via $memberLogin"
                            Roles     = $rights
                            Risk      = 'High'
                        }

                        Add-BroadSharingFindingFromGrant `
                            -User $User `
                            -Workload SharePoint `
                            -ItemPath "$($site.Title)\$($list.Title)\$fileName" `
                            -ItemUrl "$($site.Url)$fileRef" `
                            -Grant $grant `
                            -Findings $Findings
                    }
                }
            }
        }
        catch {
            Write-AuditLog "Broad-sharing scan skipped for site $($site.Url): $($_.Exception.Message)" Warn
        }
    }

    Write-AuditLog "  SharePoint items inspected for broad sharing (PnP): $itemsScanned" Info
}

function Add-SharePointBroadSharingFindings {
    param(
        $User,
        [System.Collections.Generic.List[object]]$Findings
    )

    Add-SharePointBroadSharingFindingsGraph -User $User -Findings $Findings

    if ($Script:PnPAvailable -and (Test-PnPSharePointConnectionActive)) {
        try {
            Add-SharePointBroadSharingFindingsPnP -User $User -Findings $Findings
        }
        catch {
            Write-AuditLog "PnP SharePoint broad-sharing scan failed: $($_.Exception.Message)" Warn
        }
    }
}
#endregion

#region OneDrive
function Add-OneDriveFindings {
    param(
        $User,
        [System.Collections.Generic.List[object]]$Findings
    )

    if ($IncludeBroadSharingScan) {
        Add-OneDriveBroadSharingFindings -User $User -Findings $Findings
        return
    }

    try {
        $drive = Get-MgUserDrive -UserId $User.Id -ErrorAction Stop
        $items = Get-MgUserDriveRootChild -UserId $User.Id -DriveId $drive.Id -All -Property 'id,name,webUrl' -ErrorAction Stop |
            Select-Object -First 100

        foreach ($item in $items) {
            $permissions = Get-MgUserDriveItemPermission `
                -UserId $User.Id `
                -DriveId $drive.Id `
                -DriveItemId $item.Id `
                -ErrorAction SilentlyContinue

            foreach ($permission in $permissions) {
                foreach ($grant in (Get-GraphPermissionBroadSharingGrants -Permission $permission)) {
                    Add-BroadSharingFindingFromGrant `
                        -User $User `
                        -Workload OneDrive `
                        -ItemPath $item.Name `
                        -ItemUrl $item.WebUrl `
                        -Grant $grant `
                        -Findings $Findings
                }
            }
        }
    }
    catch {
        Write-AuditLog "OneDrive scan skipped for $($User.UserPrincipalName): $($_.Exception.Message)" Warn
    }
}
#endregion

#region Exchange
function Add-ExchangeFindings {
    param(
        $User,
        [System.Collections.Generic.List[object]]$Findings
    )

    $upn = $User.UserPrincipalName
    $userSidPattern = [regex]::Escape($upn)

    Write-AuditLog "Checking Exchange delegations for $upn..." Info

    $mailboxes = Get-EXOMailbox -ResultSize Unlimited -Properties PrimarySmtpAddress, DisplayName
    foreach ($mailbox in $mailboxes) {
        if ($mailbox.PrimarySmtpAddress -eq $upn) {
            continue
        }

        $permissions = Get-MailboxPermission -Identity $mailbox.PrimarySmtpAddress -ErrorAction SilentlyContinue |
            Where-Object {
                $_.User -match $userSidPattern -and
                ($_.AccessRights -contains 'FullAccess') -and
                (-not $_.IsInherited)
            }

        foreach ($perm in $permissions) {
            $Findings.Add((New-Finding `
                -UserPrincipalName $upn `
                -DisplayName $User.DisplayName `
                -Workload Exchange `
                -Resource $mailbox.PrimarySmtpAddress `
                -Permission 'FullAccess (delegated mailbox)' `
                -Risk High `
                -FindingType Heuristic `
                -CopilotImpact 'Copilot can surface content from delegated mailboxes' `
                -Recommendation 'Remove FullAccess unless required; prefer shared mailbox with auditing'))
        }

        $sendAs = Get-RecipientPermission -Identity $mailbox.PrimarySmtpAddress -ErrorAction SilentlyContinue |
            Where-Object {
                $_.Trustee -match $userSidPattern -and
                $_.AccessControlType -eq 'Allow'
            }

        foreach ($sa in $sendAs) {
            $Findings.Add((New-Finding `
                -UserPrincipalName $upn `
                -DisplayName $User.DisplayName `
                -Workload Exchange `
                -Resource $mailbox.PrimarySmtpAddress `
                -Permission 'Send As' `
                -Risk Medium `
                -FindingType Heuristic `
                -CopilotImpact 'Send As may indicate elevated mailbox trust; review with data owner' `
                -Recommendation 'Validate Send As assignment against policy'))
        }
    }
}
#endregion

#region SharePoint (PnP)
function Add-SharePointFindings {
    param(
        $User,
        [object[]]$Baseline,
        [System.Collections.Generic.List[object]]$Findings
    )

    if (-not $IncludeSharePointSiteScan) {
        return
    }

    Write-AuditLog 'Starting SharePoint site permission scan (this may take a while)...' Warn
    $sites = Get-PnPTenantSite | Where-Object { $_.Template -notmatch 'RedirectSite|PERSONAL' }
    $userBaseline = @()
    if ($Baseline) {
        $userBaseline = @($Baseline | Where-Object {
            $_.UserPrincipalName -eq $User.UserPrincipalName -and $_.ResourceType -eq 'Site'
        })
    }

    foreach ($site in $sites) {
        try {
            Connect-PnPSharePointOnline -Url $site.Url -ErrorAction Stop
            $pnpUser = Get-PnPUser -Identity $User.UserPrincipalName -ErrorAction SilentlyContinue
            if (-not $pnpUser) {
                continue
            }

            $siteRole = $null
            foreach ($groupName in @('Owners', 'Members', 'Visitors')) {
                $members = @(Get-PnPGroupMember -Identity $groupName -ErrorAction SilentlyContinue)
                $isMember = $members | Where-Object {
                    $_.Email -eq $User.UserPrincipalName -or $_.LoginName -match [regex]::Escape($User.UserPrincipalName)
                }
                if (-not $isMember) {
                    continue
                }

                $siteRole = switch ($groupName) {
                    'Owners'   { 'Owner' }
                    'Members'  { 'Edit' }
                    'Visitors' { 'Read' }
                }

                $isHigh = ($groupName -eq 'Owners') -or ($Script:HighSharePointPermissionNames -contains $siteRole)
                if ($isHigh) {
                    $risk = if ($site.Title -match $Script:SensitivePatternRegex) { 'High' } else { 'Medium' }
                    $Findings.Add((New-Finding `
                        -UserPrincipalName $User.UserPrincipalName `
                        -DisplayName $User.DisplayName `
                        -Workload SharePoint `
                        -Resource "$($site.Title) | $($site.Url)" `
                        -Permission $siteRole `
                        -Risk $risk `
                        -FindingType Heuristic `
                        -CopilotImpact 'Site content is in Copilot retrieval scope for this user' `
                        -Recommendation 'Reduce to Read/Visitors or remove access if not required'))
                }
                break
            }

            if ($userBaseline.Count -gt 0) {
                $listed = $userBaseline | Where-Object {
                    Test-ResourceMatchesBaseline -BaselineRow $_ -ResourceId $site.Url -ResourceName $site.Title
                }

                if ($siteRole -and -not $listed) {
                    $Findings.Add((New-Finding `
                        -UserPrincipalName $User.UserPrincipalName `
                        -DisplayName $User.DisplayName `
                        -Workload Baseline `
                        -Resource "$($site.Title) | $($site.Url)" `
                        -Permission "$siteRole (not in baseline)" `
                        -Risk Medium `
                        -FindingType BaselineDelta `
                        -CopilotImpact 'Site access not listed in approved baseline CSV' `
                        -Recommendation 'Remove access or update baseline with approval'))
                }
            }
        }
        catch {
            Write-AuditLog "Skipped site $($site.Url): $($_.Exception.Message)" Warn
        }
    }

    foreach ($row in $userBaseline) {
        try {
            Connect-PnPSharePointOnline -Url $row.ResourceId -ErrorAction Stop
            $pnpUser = Get-PnPUser -Identity $User.UserPrincipalName -ErrorAction SilentlyContinue
            if (-not $pnpUser) {
                $Findings.Add((New-Finding `
                    -UserPrincipalName $User.UserPrincipalName `
                    -DisplayName $User.DisplayName `
                    -Workload Baseline `
                    -Resource "Site: $($row.ResourceId)" `
                    -Permission "Expected: $($row.ExpectedRole)" `
                    -Risk Low `
                    -FindingType BaselineMissing `
                    -CopilotImpact 'Expected site access not found (under-provisioned)' `
                    -Recommendation 'Grant approved access or remove row from baseline'))
            }
        }
        catch {
            Write-AuditLog "Could not verify baseline site $($row.ResourceId): $($_.Exception.Message)" Warn
        }
    }
}
#endregion

#region Main
if (-not $CleanChildProcess -and -not $NoCleanRelaunch) {
    Start-CopilotAuditCleanProcess -ScriptPath $PSCommandPath
}

try {
    Write-AuditLog '========================================'
    Write-AuditLog 'Copilot Over-Permission Audit'
    Write-AuditLog 'Mode: Heuristics + Baseline CSV + Broad sharing scan'
    if ($IncludeBroadSharingScan) {
        Write-AuditLog "Broad sharing (OneDrive): max $BroadSharingMaxItems items, depth $BroadSharingMaxDepth per drive" Info
    }
    if ($IncludeSharePointBroadSharingScan) {
        Write-AuditLog 'Broad sharing (SharePoint): enabled — expect longer run times' Warn
    }
    Write-AuditLog '========================================'

    $TenantName = Resolve-SharePointTenantName -Name $TenantName

    if (-not (Install-RequiredModules)) {
        throw 'Required modules could not be installed.'
    }

    $baseline = @(Import-AccessBaseline -Path $BaselineCsvPath)
    if ($baseline.Count -gt 0) {
        Write-AuditLog "Loaded $($baseline.Count) baseline row(s) from $BaselineCsvPath" Ok
    }
    else {
        Write-AuditLog 'No baseline CSV supplied; running heuristics only.' Warn
    }

    New-Item -ItemType Directory -Force -Path $OutputPath | Out-Null
    Connect-AuditServices

    $targets = @()
    if ($PSCmdlet.ParameterSetName -eq 'Single') {
        if ([string]::IsNullOrWhiteSpace($UserPrincipalName)) {
            throw 'Specify -UserPrincipalName or use -AllCopilotLicensedUsers.'
        }
        $targets = @(Get-MgUser -UserId $UserPrincipalName -Property 'id,userPrincipalName,displayName,accountEnabled')
    }
    else {
        $targets = @(Get-CopilotLicensedUsers)
        Write-AuditLog "Auditing $($targets.Count) Copilot-licensed user(s)." Info
    }

    if ($targets.Count -eq 0) {
        throw 'No users matched the audit criteria.'
    }

    $findings = [System.Collections.Generic.List[object]]::new()

    foreach ($user in $targets) {
        if (-not $user.AccountEnabled) {
            Write-AuditLog "Skipping disabled account: $($user.UserPrincipalName)" Warn
            continue
        }

        Write-AuditLog "Auditing $($user.UserPrincipalName)..." Info
        $groupIndex = Get-UserGroupMembershipIndex -UserId $user.Id

        Add-EntraHeuristicFindings -User $user -GroupIndex $groupIndex -Findings $findings
        Add-BaselineFindings -User $user -Baseline $baseline -GroupIndex $groupIndex -Findings $findings
        Add-TeamsFindings -User $user -Findings $findings
        Add-OneDriveFindings -User $user -Findings $findings
        Add-ExchangeFindings -User $user -Findings $findings
        Add-SharePointFindings -User $user -Baseline $baseline -Findings $findings
        if ($IncludeBroadSharingScan -and $IncludeSharePointBroadSharingScan) {
            Add-SharePointBroadSharingFindings -User $user -Findings $findings
        }
    }

    $timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $findingsPath = Join-Path $OutputPath "Copilot-OverPermission-$timestamp.csv"
    $findings | Export-Csv -LiteralPath $findingsPath -NoTypeInformation -Encoding UTF8

    Write-AuditLog "Exported $($findings.Count) finding(s) to:" Ok
    Write-AuditLog "  $findingsPath" Ok

    $findings |
        Group-Object Risk, FindingType |
        Sort-Object Name |
        ForEach-Object {
            Write-AuditLog "  $($_.Name): $($_.Count)" Info
        }
}
catch {
    Write-AuditLog $_.Exception.Message Err
    throw
}
finally {
    if (Get-Command Disconnect-MgGraph -ErrorAction SilentlyContinue) {
        Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
    }
    if ($Script:ExchangeConnected -and (Get-Command Disconnect-ExchangeOnline -ErrorAction SilentlyContinue)) {
        Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
    }
    if (Get-Command Disconnect-PnPOnline -ErrorAction SilentlyContinue) {
        Disconnect-PnPOnline -ErrorAction SilentlyContinue | Out-Null
    }
}
#endregion
