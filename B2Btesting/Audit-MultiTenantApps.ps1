#Requires -Version 5.1
<#
.SYNOPSIS
    Audit multi-tenant / cross-tenant (B2B-style) applications in an Entra tenant.

.DESCRIPTION
    Inventories two populations that matter for cross-tenant app risk:

      1) Outbound — App registrations owned by this tenant with multi-tenant
         signInAudience (AzureADMultipleOrgs or AzureADandPersonalMicrosoftAccount).
         These apps can be consented into other tenants.

      2) Inbound — Enterprise applications (service principals) whose home
         directory (appOwnerOrganizationId) is not this tenant. Includes
         third-party multi-tenant apps and many Microsoft first-party apps.

    Emits CSV detail plus an HTML summary with security concern flags
    (privileged Graph permissions, credentials, redirect URIs, owners, etc.).

.PARAMETER TenantId
    Target tenant ID (GUID) or domain. Required for sign-in pinning.

.PARAMETER OutputPath
    Base folder for the timestamped report directory (default: .\MultiTenantAppAuditOutput).

.PARAMETER IncludeMicrosoftFirstParty
    Include inbound service principals owned by Microsoft tenants (noisy; default off).

.PARAMETER AppOnly
    Use app-only Graph from B2B_GR_* or COPILOT_GRAPH_* env / certificate params.

.PARAMETER GraphAppId
    Optional app-only client ID (overrides env).

.PARAMETER GraphCertificateThumbprint
    Optional cert thumbprint for app-only.

.PARAMETER DeviceCode
    Use device-code Graph sign-in instead of interactive browser (recommended in Cursor /
    VS Code terminals where InteractiveBrowserCredential / WAM often fails).
    You have about 2 minutes after the code appears — use an external browser tab.

.PARAMETER ForceReconnect
    Ignore any existing Connect-MgGraph session and sign in again.

.PARAMETER IncludeExchange
    Also probe Exchange Online RBAC-for-Applications and Application Access Policies
    (requires the ExchangeOnlineManagement module; connects if not already connected).

.PARAMETER ExchangeConnectTimeoutSeconds
    Auto-skip the Exchange Online connect if sign-in does not complete within this many
    seconds (default 90). Prevents a swallowed interactive prompt from hanging the audit.
    Pre-connecting with Connect-ExchangeOnline avoids the timed connect entirely.

.PARAMETER SkipSignInActivity
    Skip per-app sign-in evidence collection (auditLogs/signIns requires Entra ID P1).

.PARAMETER SignInLookbackDays
    Days of service-principal sign-in activity to summarize per app (default 30).

.NOTES
    For each inbound external service principal the audit collects application
    permissions, delegated grants (admin vs user consent), active and PIM-eligible
    directory roles, security-group memberships, owned objects, owners, assigned
    users/groups, credentials, sign-in evidence, and (optionally) Exchange app RBAC.
    Azure RBAC (ARM) role assignments are NOT covered here — enumerate those with
    Get-AzRoleAssignment / ARM, since they are not exposed via Microsoft Graph.

.EXAMPLE
    # Prefer: sign in once in an external PowerShell window, then run the audit (reuses session)
    Connect-MgGraph -TenantId contoso.com -Scopes Application.Read.All,Directory.Read.All,DelegatedPermissionGrant.Read.All -UseDeviceCode
    .\Audit-MultiTenantApps.ps1 -TenantId contoso.com

.EXAMPLE
    .\Audit-MultiTenantApps.ps1 -TenantId contoso.com -DeviceCode

.EXAMPLE
    # Include Exchange app RBAC and a 90-day sign-in window
    .\Audit-MultiTenantApps.ps1 -TenantId contoso.com -IncludeExchange -SignInLookbackDays 90

.EXAMPLE
    . .\.b2b-global-reader.local.ps1
    .\Audit-MultiTenantApps.ps1 -TenantId '<BB-TENANT-ID>' -AppOnly
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$TenantId,

    [string]$OutputPath = (Join-Path $PSScriptRoot 'MultiTenantAppAuditOutput'),

    [switch]$IncludeMicrosoftFirstParty,

    [switch]$AppOnly,

    [string]$GraphAppId,

    [string]$GraphCertificateThumbprint,

    [switch]$DeviceCode,

    [switch]$ForceReconnect,

    # Also probe Exchange Online RBAC-for-Applications + Application Access Policies
    # (requires the ExchangeOnlineManagement module; connects if not already connected).
    [switch]$IncludeExchange,

    # Auto-skip the Exchange Online connect if a sign-in does not complete in this many
    # seconds (prevents an interactive prompt from hanging the whole audit).
    [int]$ExchangeConnectTimeoutSeconds = 90,

    # Skip sign-in log evidence collection (auditLogs/signIns needs Entra ID P1).
    [switch]$SkipSignInActivity,

    # Skip the source-IP intelligence pass (RDAP + reverse DNS) over sign-in IPs.
    [switch]$SkipIpIntelligence,

    # How many days of sign-in activity to summarize per service principal.
    [int]$SignInLookbackDays = 30,

    # Internal: set when relaunched into an external console from Cursor/VS Code.
    [switch]$SkipExternalRelaunch
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Ensures the sign-in log failure warning is emitted at most once per run.
$Script:SignInErrorReported = $false

# Flat list of per-sign-in detail records (across all SPs) for the report's sign-in section.
$Script:SignInDetailRecords = [System.Collections.Generic.List[object]]::new()

# Cache of applicationTemplateId -> gallery template display name (avoids repeat Graph calls).
$Script:AppTemplateNameCache = @{}

# Subnet-keyed RDAP cache: each entry has Start/End (BigInteger) covering the network
# allocation returned by RDAP, plus the parsed result. Any IP that falls inside an already
# resolved range reuses that result without another RDAP call.
$Script:RdapSubnetCache = [System.Collections.Generic.List[object]]::new()

# Well-known "non-gallery application" template id (used by "create your own application").
$Script:NonGalleryTemplateId = '8adf8e6e-67b2-4cf2-a259-e3dc5476c621'

# Well-known Microsoft "home" tenant IDs commonly seen as appOwnerOrganizationId for 1P apps.
$Script:MicrosoftTenantIds = @(
    'f8cdef31-a31e-4b4a-93e4-5f571e91255a', # Microsoft Services
    '72f988bf-86f1-41af-91ab-2d7cd011db47', # Microsoft
    '33e01921-4d64-4f8c-a055-5bdaffd5e33d',
    'cdc5aeea-15c5-4db6-b079-fcadd2505dc2'
)

$Script:HighRiskPermissionPatterns = @(
    '(?i)^Directory\.(ReadWrite|AccessAsUser)',
    '(?i)^RoleManagement\.(ReadWrite|ReadWrite\.Directory)',
    '(?i)^AppRoleAssignment\.ReadWrite',
    '(?i)^Application\.ReadWrite',
    '(?i)^Policy\.ReadWrite',
    '(?i)^User\.ReadWrite',
    '(?i)^Group\.(ReadWrite|Create)',
    '(?i)^Files\.ReadWrite',
    '(?i)^Sites\.(FullControl|ReadWrite)',
    '(?i)^Mail\.(ReadWrite|Send)',
    '(?i)^Calendars\.ReadWrite',
    '(?i)^Exchange\.ManageAsApp',
    '(?i)^AppRoleAssignment\.ReadWrite\.All',
    '(?i)^Domain\.ReadWrite',
    '(?i)^DeviceManagement',
    '(?i)^EntitlementManagement',
    '(?i)^IdentityRisky',
    '(?i)^UserAuthenticationMethod',
    '(?i)^PrivilegedAccess',
    '(?i)^AuditLog\.Read\.All'
)

function Write-AuditMsg {
    param([string]$Message, [ValidateSet('Info', 'Warn', 'Ok')][string]$Level = 'Info')
    $color = switch ($Level) {
        'Warn' { 'Yellow' }
        'Ok'   { 'Green' }
        default { 'Cyan' }
    }
    Write-Host $Message -ForegroundColor $color
}

function Get-ObjectCount {
    # StrictMode-safe count: empty function returns become $null; single objects have no .Count.
    # Note: @($null).Count is 1 in PowerShell — treat null as zero.
    # Do NOT use ICollection: Hashtable/IDictionary.Count is key count, not "one row".
    param($Object)
    if ($null -eq $Object) { return 0 }
    if ($Object -is [string]) { return 1 }
    if ($Object -is [System.Array]) { return [int]$Object.Length }
    if ($Object -is [System.Collections.IList]) { return [int]$Object.Count }
    return 1
}

function ConvertTo-ObjectArray {
    # Preserve empty arrays. Do NOT use @($x) on an empty Object[] — that nests it as 1 element.
    param($Object)
    if ($null -eq $Object) { return , @() }
    if ($Object -is [System.Array]) { return , $Object }
    if ($Object -is [System.Collections.ICollection] -and -not ($Object -is [string])) {
        $tmp = [System.Collections.Generic.List[object]]::new()
        foreach ($i in $Object) { [void]$tmp.Add($i) }
        return , $tmp.ToArray()
    }
    return , @($Object)
}

function Get-GraphProp {
    param($Object, [string]$Name)
    if ($null -eq $Object) { return $null }
    if ($Object -is [string] -or $Object -is [ValueType]) { return $null }

    if ($Object -is [hashtable] -or $Object -is [System.Collections.IDictionary]) {
        if ($Object.ContainsKey($Name)) { return $Object[$Name] }
        foreach ($k in $Object.Keys) {
            if ([string]::Equals([string]$k, $Name, [StringComparison]::OrdinalIgnoreCase)) {
                return $Object[$k]
            }
        }
        return $null
    }

    $p = $Object.PSObject.Properties[$Name]
    if ($p) { return $p.Value }
    foreach ($prop in $Object.PSObject.Properties) {
        if ([string]::Equals([string]$prop.Name, $Name, [StringComparison]::OrdinalIgnoreCase)) {
            return $prop.Value
        }
    }
    return $null
}

function Test-IsGraphRowObject {
    param($Object)
    if ($null -eq $Object) { return $false }
    if ($Object -is [string] -or $Object -is [ValueType]) { return $false }
    return ($Object -is [hashtable] -or $Object -is [System.Collections.IDictionary] -or $null -ne $Object.PSObject)
}

function Invoke-GraphRequestWithRetry {
    <#
        Wraps Invoke-MgGraphRequest with retry/backoff for throttling (429) and
        transient 5xx errors so a single hiccup does not abort a whole collector.
    #>
    param(
        [Parameter(Mandatory)][string]$Uri,
        [string]$Method = 'GET',
        [int]$MaxAttempts = 5
    )

    $attempt = 0
    while ($true) {
        $attempt++
        try {
            return Invoke-MgGraphRequest -Method $Method -Uri $Uri -ErrorAction Stop
        }
        catch {
            $status = $null
            try { $status = [int]$_.Exception.Response.StatusCode } catch { }
            $isTransient = ($status -eq 429 -or ($status -ge 500 -and $status -le 599))
            if (-not $isTransient -or $attempt -ge $MaxAttempts) { throw }

            $delay = [Math]::Min(30, [Math]::Pow(2, $attempt))
            try {
                $retryAfter = $_.Exception.Response.Headers.RetryAfter.Delta.TotalSeconds
                if ($retryAfter -and $retryAfter -gt 0) { $delay = [Math]::Min(60, $retryAfter) }
            }
            catch { }
            Write-AuditMsg ("  Graph {0} throttled/transient (HTTP {1}); retry {2}/{3} in {4}s..." -f $Method, $status, $attempt, $MaxAttempts, $delay) Warn
            Start-Sleep -Seconds ([int]$delay)
        }
    }
}

function Get-GraphPaged {
    param([Parameter(Mandatory)][string]$Uri, [int]$MaxPages = 200)

    $items = [System.Collections.Generic.List[object]]::new()
    $next = $Uri
    $page = 0
    while ($next -and $page -lt $MaxPages) {
        $page++
        $response = Invoke-GraphRequestWithRetry -Method GET -Uri $next
        foreach ($v in @((Get-GraphProp -Object $response -Name 'value'))) {
            if ($v) { $items.Add($v) }
        }
        $next = [string](Get-GraphProp -Object $response -Name '@odata.nextLink')
    }
    # Comma prevents PowerShell from unwrapping a single-element array (breaks .Count under StrictMode).
    return , @($items.ToArray())
}

function Test-IsMicrosoftTenantId {
    param([string]$OrgId)
    if ([string]::IsNullOrWhiteSpace($OrgId)) { return $false }
    return ($Script:MicrosoftTenantIds -contains $OrgId.Trim().ToLowerInvariant())
}

function Test-IsHighRiskPermission {
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $false }
    foreach ($pat in $Script:HighRiskPermissionPatterns) {
        if ($Value -match $pat) { return $true }
    }
    return $false
}

function Test-GraphContextMatchesTenant {
    param([Parameter(Mandatory)][string]$TargetTenant)

    $ctx = Get-MgContext -ErrorAction SilentlyContinue
    if (-not $ctx -or [string]::IsNullOrWhiteSpace([string]$ctx.TenantId)) { return $false }

    $ctxTenant = [string]$ctx.TenantId
    if ([string]::Equals($ctxTenant, $TargetTenant, [StringComparison]::OrdinalIgnoreCase)) { return $true }

    # Allow match when caller passed a domain and context has the GUID (or vice versa) via org read later.
    # Here only exact / GUID equality; domain vs GUID is resolved after connect.
    if ($TargetTenant -notmatch '^[0-9a-fA-F-]{36}$' -and $ctx.Account) {
        # Domain pin: accept existing session; Get-CurrentOrganization will confirm.
        return $true
    }
    return $false
}

function Test-GraphTokenValid {
    # Cheap probe to confirm the current session token actually works (user-provided
    # tokens expire after ~1h and are not refreshed, so a matching context can still be dead).
    try {
        $null = Invoke-MgGraphRequest -Method GET -Uri 'https://graph.microsoft.com/v1.0/organization?$select=id&$top=1' -ErrorAction Stop
        return $true
    }
    catch {
        return $false
    }
}

function Test-IsCursorOrVsCodeTerminal {
    if ($env:CURSOR_TRACE_ID) { return $true }
    if ($env:TERM_PROGRAM -match '(?i)vscode|cursor') { return $true }
    if ($env:VSCODE_PID -or $env:VSCODE_INJECTION) { return $true }
    return $false
}

function Get-GraphAuthDependencyPath {
    param([Parameter(Mandatory)][string]$FileName)

    $mod = Get-Module Microsoft.Graph.Authentication -ErrorAction Stop
    $depsRoot = Join-Path $mod.ModuleBase 'Dependencies'
    $direct = Join-Path $depsRoot $FileName
    if (Test-Path -LiteralPath $direct) { return $direct }

    # Graph 2.x lays out Azure.Core under Dependencies\Core (PowerShell 7) or Dependencies\Desktop (Windows PowerShell 5.1).
    # Use built-in $IsCoreCLR — do not assign $isCoreClr (case-insensitive clash with that read-only variable).
    $preferredSubdir = if ($IsCoreCLR) { 'Core' } else { 'Desktop' }
    $preferred = Join-Path (Join-Path $depsRoot $preferredSubdir) $FileName
    if (Test-Path -LiteralPath $preferred) { return $preferred }

    $matches = @(Get-ChildItem -Path $depsRoot -Recurse -Filter $FileName -File -ErrorAction SilentlyContinue)
    if ($matches.Count -eq 0) {
        throw "Missing Graph dependency '$FileName' under $depsRoot"
    }

    $preferredMatch = @($matches | Where-Object { $_.DirectoryName -match [regex]::Escape($preferredSubdir) } | Select-Object -First 1)
    if ($preferredMatch) { return $preferredMatch.FullName }
    return $matches[0].FullName
}

function Connect-MgGraphWithVisibleDeviceCode {
    param(
        [Parameter(Mandatory)][string]$TargetTenant,
        [Parameter(Mandatory)][string[]]$Scopes
    )

    # Connect-MgGraph -UseDeviceCode / Azure.Identity callbacks run on a background thread.
    # PowerShell scriptblocks fail there ("no Runspace"), and Console.WriteLine is swallowed in Cursor.
    # Do the OAuth device-code flow on this thread and print with Write-Host.
    $publicClientId = '14d82eec-204b-4c2f-b7e8-296a70dab67e' # Microsoft Graph PowerShell
    $scopeList = [System.Collections.Generic.List[string]]::new()
    foreach ($s in $Scopes) {
        if ($s -match '^https://') { [void]$scopeList.Add($s) }
        else { [void]$scopeList.Add(('https://graph.microsoft.com/{0}' -f $s)) }
    }
    foreach ($oidc in @('openid', 'profile', 'offline_access')) {
        if (-not ($scopeList -contains $oidc)) { [void]$scopeList.Add($oidc) }
    }
    $scopeString = ($scopeList -join ' ')

    $tenantSegment = if ([string]::IsNullOrWhiteSpace($TargetTenant)) { 'organizations' } else { $TargetTenant.Trim() }
    $deviceCodeUrl = "https://login.microsoftonline.com/$tenantSegment/oauth2/v2.0/devicecode"
    $tokenUrl = "https://login.microsoftonline.com/$tenantSegment/oauth2/v2.0/token"

    Write-AuditMsg '  Requesting device code (code message should appear below)...' Info
    $dcBody = @{
        client_id = $publicClientId
        scope     = $scopeString
    }
    try {
        $dc = Invoke-RestMethod -Method Post -Uri $deviceCodeUrl -Body $dcBody -ContentType 'application/x-www-form-urlencoded' -ErrorAction Stop
    }
    catch {
        throw ("Device-code request failed: {0}" -f $_.Exception.Message)
    }

    $message = [string]$dc.message
    if ([string]::IsNullOrWhiteSpace($message)) {
        $message = "To sign in, open {0} and enter code {1}" -f $dc.verification_uri, $dc.user_code
    }
    Write-Host ''
    Write-Host $message -ForegroundColor Yellow
    Write-Host ("  user_code = {0}" -f $dc.user_code) -ForegroundColor Yellow
    Write-Host ("  verification_uri = {0}" -f $dc.verification_uri) -ForegroundColor Yellow
    Write-Host ''
    try {
        $verifyUri = if ($dc.verification_uri) { [string]$dc.verification_uri } else { 'https://microsoft.com/devicelogin' }
        Start-Process $verifyUri -ErrorAction SilentlyContinue
    }
    catch { }

    $intervalSec = 5
    if ($dc.interval -and [int]$dc.interval -gt 0) { $intervalSec = [int]$dc.interval }
    $expiresIn = 900
    if ($dc.expires_in -and [int]$dc.expires_in -gt 0) { $expiresIn = [int]$dc.expires_in }
    $deadline = [datetime]::UtcNow.AddSeconds($expiresIn)
    $accessToken = $null

    Write-AuditMsg ("  Waiting for browser/device login (timeout ~{0}s)..." -f $expiresIn) Warn
    while ([datetime]::UtcNow -lt $deadline) {
        Start-Sleep -Seconds $intervalSec
        $tokenBody = @{
            grant_type  = 'urn:ietf:params:oauth:grant-type:device_code'
            client_id   = $publicClientId
            device_code = [string]$dc.device_code
        }
        try {
            $tokenResponse = Invoke-RestMethod -Method Post -Uri $tokenUrl -Body $tokenBody -ContentType 'application/x-www-form-urlencoded' -ErrorAction Stop
            if ($tokenResponse.access_token) {
                $accessToken = [string]$tokenResponse.access_token
                break
            }
        }
        catch {
            $errText = $_.ErrorDetails.Message
            if ([string]::IsNullOrWhiteSpace($errText) -and $_.Exception.Response) {
                try {
                    $reader = [System.IO.StreamReader]::new($_.Exception.Response.GetResponseStream())
                    $errText = $reader.ReadToEnd()
                    $reader.Dispose()
                }
                catch { }
            }
            if ([string]::IsNullOrWhiteSpace($errText)) { $errText = $_.Exception.Message }

            $errCode = $null
            try {
                $errObj = $errText | ConvertFrom-Json -ErrorAction Stop
                $errCode = [string]$errObj.error
            }
            catch { }

            if ($errCode -eq 'authorization_pending') { continue }
            if ($errCode -eq 'slow_down') {
                $intervalSec += 5
                continue
            }
            if ($errCode -eq 'expired_token') {
                throw 'Device-code sign-in timed out (code expired). Re-run the script and complete login faster.'
            }
            if ($errCode -eq 'authorization_declined') {
                throw 'Device-code sign-in was declined in the browser.'
            }
            throw ("Device-code token poll failed: {0}" -f $errText)
        }
    }

    if ([string]::IsNullOrWhiteSpace($accessToken)) {
        throw 'Device-code sign-in timed out waiting for approval.'
    }

    $secure = ConvertTo-SecureString -String $accessToken -AsPlainText -Force
    Connect-MgGraph -AccessToken $secure -NoWelcome -ErrorAction Stop
}

function Start-AuditInExternalConsole {
    param([Parameter(Mandatory)][string]$TargetTenant)

    $pwshCmd = Get-Command pwsh -ErrorAction SilentlyContinue
    $pwsh = if ($pwshCmd) { [string]$pwshCmd.Source } else { '' }
    if (-not $pwsh) {
        $pwsh = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    }

    # Do not use $args — it is an automatic variable and breaks Start-Process ArgumentList.
    $launchArgs = [System.Collections.Generic.List[string]]::new()
    [void]$launchArgs.AddRange([string[]]@(
            '-NoExit',
            '-ExecutionPolicy', 'Bypass',
            '-File', $PSCommandPath,
            '-TenantId', $TargetTenant,
            '-DeviceCode',
            '-SkipExternalRelaunch'
        ))
    if ($IncludeMicrosoftFirstParty) { [void]$launchArgs.Add('-IncludeMicrosoftFirstParty') }
    if ($IncludeExchange) { [void]$launchArgs.Add('-IncludeExchange') }
    if ($SkipSignInActivity) { [void]$launchArgs.Add('-SkipSignInActivity') }
    if ($PSBoundParameters.ContainsKey('SignInLookbackDays')) {
        [void]$launchArgs.Add('-SignInLookbackDays')
        [void]$launchArgs.Add([string]$SignInLookbackDays)
    }
    if ($OutputPath) {
        [void]$launchArgs.Add('-OutputPath')
        [void]$launchArgs.Add([string]$OutputPath)
    }

    Write-AuditMsg 'Cursor/VS Code cannot show Graph device codes (Console.WriteLine is swallowed).' Warn
    Write-AuditMsg 'Opening an external PowerShell window — complete device login THERE; the audit will continue in that window.' Warn
    Start-Process -FilePath $pwsh -WorkingDirectory $PSScriptRoot -ArgumentList @($launchArgs.ToArray())
}

function Connect-AuditGraph {
    param(
        [Parameter(Mandatory)][string]$TargetTenant,
        [switch]$UseAppOnly
    )

    if (-not (Get-Module -ListAvailable -Name 'Microsoft.Graph.Authentication')) {
        throw 'Install Microsoft.Graph.Authentication: Install-Module Microsoft.Graph.Authentication -Scope CurrentUser'
    }
    Import-Module Microsoft.Graph.Authentication -ErrorAction Stop

    $appId = $GraphAppId
    if ([string]::IsNullOrWhiteSpace($appId)) {
        $appId = [Environment]::GetEnvironmentVariable('B2B_GR_APP_ID')
    }
    if ([string]::IsNullOrWhiteSpace($appId)) {
        $appId = [Environment]::GetEnvironmentVariable('COPILOT_GRAPH_APP_ID')
    }

    $thumb = $GraphCertificateThumbprint
    if ([string]::IsNullOrWhiteSpace($thumb)) {
        $thumb = [Environment]::GetEnvironmentVariable('B2B_GR_CERT_THUMBPRINT')
    }
    if ([string]::IsNullOrWhiteSpace($thumb)) {
        $thumb = [Environment]::GetEnvironmentVariable('COPILOT_GRAPH_CERT_THUMBPRINT')
    }

    if (-not $ForceReconnect -and -not $UseAppOnly -and (Test-GraphContextMatchesTenant -TargetTenant $TargetTenant)) {
        $existing = Get-MgContext
        if (Test-GraphTokenValid) {
            Write-AuditMsg ("Reusing existing Graph session (AuthType={0}; TenantId={1}). Use -ForceReconnect to sign in again." -f $existing.AuthType, $existing.TenantId) Ok
            return [string]$existing.TenantId
        }
        Write-AuditMsg 'Existing Graph session token is expired/invalid; signing in again...' Warn
    }

    if ($UseAppOnly) {
        if ([string]::IsNullOrWhiteSpace($appId) -or [string]::IsNullOrWhiteSpace($thumb)) {
            throw 'AppOnly requires GraphAppId/B2B_GR_APP_ID and GraphCertificateThumbprint/B2B_GR_CERT_THUMBPRINT.'
        }
        Write-AuditMsg "Connecting app-only Graph (TenantId=$TargetTenant; AppId=$appId)..."
        Connect-MgGraph -TenantId $TargetTenant -ClientId $appId -CertificateThumbprint $thumb -NoWelcome
    }
    else {
        # AppRoleAssignment.Read.All is not a real Graph scope (AADSTS650053).
        # Application.Read.All / Directory.Read.All cover appRoleAssignments, group
        # memberships, and owned objects; DelegatedPermissionGrant.Read.All covers
        # oauth2PermissionGrants; RoleManagement.Read.Directory covers active/eligible
        # role assignments; AuditLog.Read.All covers sign-in activity evidence.
        $scopes = @(
            'Application.Read.All',
            'Directory.Read.All',
            'DelegatedPermissionGrant.Read.All',
            'RoleManagement.Read.Directory',
            'AuditLog.Read.All'
        )
        $connectParams = @{
            TenantId  = $TargetTenant
            Scopes    = $scopes
            NoWelcome = $true
        }
        $paramNames = @((Get-Command Connect-MgGraph -ErrorAction Stop).Parameters.Keys)
        $supportsDeviceCode = ($paramNames -contains 'UseDeviceCode')

        # Cursor / VS Code: interactive browser / WAM often fails; prefer device code.
        $preferDeviceCode = [bool]$DeviceCode
        if (-not $preferDeviceCode -and $env:TERM_PROGRAM -match '(?i)vscode|cursor') {
            $preferDeviceCode = $true
        }
        if (-not $preferDeviceCode -and $env:CURSOR_TRACE_ID) {
            $preferDeviceCode = $true
        }

        $invokeDeviceCodeConnect = {
            param([string]$Tenant, [string[]]$ScopeList)

            Write-AuditMsg '  Device-code sign-in (~2 minutes after the code prints).' Warn
            try {
                Connect-MgGraphWithVisibleDeviceCode -TargetTenant $Tenant -Scopes $ScopeList
                return 'OK'
            }
            catch {
                $msg = $_.Exception.Message
                Write-AuditMsg ("  Visible device-code helper failed: {0}" -f $msg) Warn
                if ((Test-IsCursorOrVsCodeTerminal) -and -not $SkipExternalRelaunch) {
                    Start-AuditInExternalConsole -TargetTenant $Tenant
                    return 'RELAUNCHED_EXTERNAL'
                }
                if ($supportsDeviceCode) {
                    Write-AuditMsg '  Falling back to Connect-MgGraph -UseDeviceCode (code may not show in Cursor)...' Warn
                    Connect-MgGraph -TenantId $Tenant -Scopes $ScopeList -UseDeviceCode -ErrorAction Stop
                    return 'OK'
                }
                throw
            }
        }

        if ($preferDeviceCode) {
            Write-AuditMsg "Connecting delegated Graph via device code (TenantId=$TargetTenant)..."
            try {
                $dcResult = & $invokeDeviceCodeConnect $TargetTenant $scopes
                if ($dcResult -eq 'RELAUNCHED_EXTERNAL') {
                    return 'RELAUNCHED_EXTERNAL'
                }
            }
            catch {
                $msg = $_.Exception.Message
                if ($msg -match '(?i)timed out|inactivity') {
                    throw @"
Graph device-code sign-in timed out (usually ~120 seconds).

Run the whole audit in an external PowerShell window (not Cursor):
  cd '$PSScriptRoot'
  .\Audit-MultiTenantApps.ps1 -TenantId '$TargetTenant' -DeviceCode -SkipExternalRelaunch

Original error: $msg
"@
                }
                throw
            }
        }
        else {
            Write-AuditMsg "Connecting delegated Graph (TenantId=$TargetTenant)..."
            try {
                Connect-MgGraph @connectParams
            }
            catch {
                $msg = $_.Exception.Message
                if ($msg -match '(?i)InteractiveBrowserCredential|browser|WAM|authentication failed') {
                    Write-AuditMsg '  Interactive browser sign-in failed. Retrying with device code...' Warn
                    $dcResult = & $invokeDeviceCodeConnect $TargetTenant $scopes
                    if ($dcResult -eq 'RELAUNCHED_EXTERNAL') {
                        return 'RELAUNCHED_EXTERNAL'
                    }
                }
                else {
                    throw
                }
            }
        }
    }

    $ctx = Get-MgContext
    if (-not $ctx) { throw 'Graph connection failed.' }
    Write-AuditMsg ("  Connected AuthType={0} TenantId={1}" -f $ctx.AuthType, $ctx.TenantId) Ok
    return [string]$ctx.TenantId
}

function Get-CurrentOrganization {
    $org = Invoke-MgGraphRequest -Method GET `
        -Uri 'https://graph.microsoft.com/v1.0/organization?$select=id,displayName,verifiedDomains' `
        -ErrorAction Stop
    $item = @((Get-GraphProp -Object $org -Name 'value')) | Select-Object -First 1
    return [PSCustomObject]@{
        Id          = [string](Get-GraphProp -Object $item -Name 'id')
        DisplayName = [string](Get-GraphProp -Object $item -Name 'displayName')
    }
}

function Get-GraphAppRoleValueMap {
    $uri = 'https://graph.microsoft.com/v1.0/servicePrincipals?$filter=appId eq ''00000003-0000-0000-c000-000000000000''&$select=id,appRoles,oauth2PermissionScopes'
    $response = Invoke-MgGraphRequest -Method GET -Uri $uri -ErrorAction Stop
    $sp = @((Get-GraphProp -Object $response -Name 'value')) | Select-Object -First 1
    $map = @{}
    foreach ($role in @((Get-GraphProp -Object $sp -Name 'appRoles'))) {
        $id = [string](Get-GraphProp -Object $role -Name 'id')
        $value = [string](Get-GraphProp -Object $role -Name 'value')
        if ($id -and $value) { $map[$id] = $value }
    }
    $delegatedById = @{}
    foreach ($scope in @((Get-GraphProp -Object $sp -Name 'oauth2PermissionScopes'))) {
        $id = [string](Get-GraphProp -Object $scope -Name 'id')
        $value = [string](Get-GraphProp -Object $scope -Name 'value')
        if ($id -and $value) { $delegatedById[$id] = $value }
    }
    return @{
        SpId          = [string](Get-GraphProp -Object $sp -Name 'id')
        RolesById     = $map
        DelegatedById = $delegatedById
        ResourceRoleCache = @{}
    }
}

function Get-ResourceAppRoleLabel {
    param(
        [string]$ResourceId,
        [string]$AppRoleId,
        [string]$ResourceDisplayName,
        $GraphRoleMap
    )

    if ([string]::IsNullOrWhiteSpace($AppRoleId)) { return 'unknown' }

    if ($GraphRoleMap -and $GraphRoleMap.RolesById -and $GraphRoleMap.RolesById.ContainsKey($AppRoleId)) {
        return [string]$GraphRoleMap.RolesById[$AppRoleId]
    }

    if ([string]::IsNullOrWhiteSpace($ResourceId) -or -not $GraphRoleMap) {
        return $AppRoleId
    }

    if (-not $GraphRoleMap.ContainsKey('ResourceRoleCache')) {
        $GraphRoleMap['ResourceRoleCache'] = @{}
    }
    $cache = $GraphRoleMap.ResourceRoleCache
    if (-not $cache.ContainsKey($ResourceId)) {
        $roleMap = @{}
        try {
            $res = Invoke-MgGraphRequest -Method GET `
                -Uri ("https://graph.microsoft.com/v1.0/servicePrincipals/{0}?`$select=id,displayName,appRoles" -f $ResourceId) `
                -ErrorAction Stop
            foreach ($role in @((Get-GraphProp -Object $res -Name 'appRoles'))) {
                $rid = [string](Get-GraphProp -Object $role -Name 'id')
                $val = [string](Get-GraphProp -Object $role -Name 'value')
                if (-not $val) { $val = [string](Get-GraphProp -Object $role -Name 'displayName') }
                if ($rid) { $roleMap[$rid] = $(if ($val) { $val } else { $rid }) }
            }
        }
        catch {
            $roleMap = @{}
        }
        $cache[$ResourceId] = $roleMap
    }

    $resolved = $cache[$ResourceId]
    if ($resolved -and $resolved.ContainsKey($AppRoleId)) {
        return [string]$resolved[$AppRoleId]
    }
    return $AppRoleId
}

function Format-CredentialSummary {
    param($KeyCredentials, $PasswordCredentials)

    $now = [DateTime]::UtcNow
    $keys = @($KeyCredentials)
    $secrets = @($PasswordCredentials)
    $expiring = [System.Collections.Generic.List[string]]::new()
    $expired = [System.Collections.Generic.List[string]]::new()

    foreach ($c in @($keys + $secrets)) {
        if (-not $c) { continue }
        $end = Get-GraphProp -Object $c -Name 'endDateTime'
        $display = [string](Get-GraphProp -Object $c -Name 'displayName')
        if (-not $display) { $display = [string](Get-GraphProp -Object $c -Name 'keyId') }
        if (-not $end) { continue }
        try {
            $dt = [DateTime]::Parse([string]$end).ToUniversalTime()
        }
        catch { continue }
        $label = if ($display) { $display } else { $dt.ToString('yyyy-MM-dd') }
        if ($dt -lt $now) {
            [void]$expired.Add($label)
        }
        elseif ($dt -lt $now.AddDays(30)) {
            [void]$expiring.Add(('{0} ({1:yyyy-MM-dd})' -f $label, $dt))
        }
    }

    return [PSCustomObject]@{
        CertCount       = $keys.Count
        SecretCount     = $secrets.Count
        ExpiredCount    = $expired.Count
        Expiring30Count = $expiring.Count
        ExpiredNames    = ($expired -join '; ')
        ExpiringNames   = ($expiring -join '; ')
    }
}

function Get-RedirectRiskFlags {
    param($Web, $PublicClient, $Spa)

    $flags = [System.Collections.Generic.List[string]]::new()
    $uris = [System.Collections.Generic.List[string]]::new()
    foreach ($bucket in @(
            (Get-GraphProp -Object $Web -Name 'redirectUris'),
            (Get-GraphProp -Object $PublicClient -Name 'redirectUris'),
            (Get-GraphProp -Object $Spa -Name 'redirectUris')
        )) {
        foreach ($u in @($bucket)) {
            if ($u) { [void]$uris.Add([string]$u) }
        }
    }

    foreach ($u in $uris) {
        if ($u -match '(?i)^http:') { [void]$flags.Add('HttpRedirectUri') }
        if ($u -match '(?i)\*') { [void]$flags.Add('WildcardRedirectUri') }
        if ($u -match '(?i)localhost|127\.0\.0\.1') { [void]$flags.Add('LocalhostRedirectUri') }
    }

    $uniqueFlags = @($flags | Select-Object -Unique)
    return [PSCustomObject]@{
        RedirectUriCount = $uris.Count
        RedirectUris     = ($uris -join '; ')
        Flags            = ($uniqueFlags -join ',')
    }
}

function Resolve-RequiredResourceAccess {
    param(
        $RequiredResourceAccess,
        $GraphRoleMap
    )

    $perms = [System.Collections.Generic.List[string]]::new()
    $high = [System.Collections.Generic.List[string]]::new()
    $appRoleCount = 0
    $delegatedCount = 0

    foreach ($res in @($RequiredResourceAccess)) {
        $resAppId = [string](Get-GraphProp -Object $res -Name 'resourceAppId')
        foreach ($access in @((Get-GraphProp -Object $res -Name 'resourceAccess'))) {
            $id = [string](Get-GraphProp -Object $access -Name 'id')
            $type = [string](Get-GraphProp -Object $access -Name 'type')
            $label = $id
            if ($resAppId -eq '00000003-0000-0000-c000-000000000000' -and $GraphRoleMap.RolesById.ContainsKey($id)) {
                $label = [string]$GraphRoleMap.RolesById[$id]
            }
            else {
                $label = '{0}:{1}' -f $resAppId, $id
            }
            if ($type -eq 'Role') {
                $appRoleCount++
                $entry = 'App/' + $label
            }
            else {
                $delegatedCount++
                $entry = 'Delegated/' + $label
            }
            [void]$perms.Add($entry)
            if (Test-IsHighRiskPermission -Value $label) {
                [void]$high.Add($entry)
            }
        }
    }

    return [PSCustomObject]@{
        PermissionCount     = $perms.Count
        ApplicationRoleCount = $appRoleCount
        DelegatedScopeCount = $delegatedCount
        Permissions         = ($perms -join '; ')
        HighRiskPermissions = ($high -join '; ')
        HighRiskCount       = $high.Count
    }
}

function Get-AppOwnerCount {
    param([Parameter(Mandatory)][string]$ApplicationObjectId)

    try {
        $owners = ConvertTo-ObjectArray (Get-GraphPaged -Uri ("https://graph.microsoft.com/v1.0/applications/{0}/owners?`$select=id,displayName" -f $ApplicationObjectId))
        return (Get-ObjectCount $owners)
    }
    catch {
        return -1
    }
}

function Get-AppFederatedCredentialSummary {
    param([Parameter(Mandatory)][string]$ApplicationObjectId)

    # Federated identity credentials = passwordless trust from external IdPs (GitHub Actions,
    # other clouds, workload identity federation). A secretless path to act as this app.
    $creds = [System.Collections.Generic.List[string]]::new()
    try {
        $rows = ConvertTo-ObjectArray (Get-GraphPaged -Uri ("https://graph.microsoft.com/v1.0/applications/{0}/federatedIdentityCredentials" -f $ApplicationObjectId))
    }
    catch {
        return [PSCustomObject]@{ CredentialCount = -1; Details = '' }
    }

    foreach ($c in $rows) {
        if (-not (Test-IsGraphRowObject $c)) { continue }
        $name = [string](Get-GraphProp -Object $c -Name 'name')
        $issuer = [string](Get-GraphProp -Object $c -Name 'issuer')
        $subject = [string](Get-GraphProp -Object $c -Name 'subject')
        [void]$creds.Add(('{0} (issuer={1}; subject={2})' -f $name, $issuer, $subject))
    }

    return [PSCustomObject]@{
        CredentialCount = $creds.Count
        Details         = ($creds -join '; ')
    }
}

function Collect-OutboundMultiTenantApps {
    param(
        [Parameter(Mandatory)][string]$TenantOrgId,
        $GraphRoleMap
    )

    Write-AuditMsg 'Collecting outbound multi-tenant app registrations...'
    # signInAudience cannot OR-filter reliably on all tenants; pull both audiences.
    $apps = [System.Collections.Generic.List[object]]::new()
    foreach ($audience in @('AzureADMultipleOrgs', 'AzureADandPersonalMicrosoftAccount')) {
        $filter = [uri]::EscapeDataString("signInAudience eq '$audience'")
        $uri = 'https://graph.microsoft.com/v1.0/applications?$filter={0}&$select=id,appId,displayName,createdDateTime,signInAudience,publisherDomain,verifiedPublisher,info,web,spa,publicClient,keyCredentials,passwordCredentials,requiredResourceAccess,api,isFallbackPublicClient,tags,notes' -f $filter
        try {
            foreach ($a in (ConvertTo-ObjectArray (Get-GraphPaged -Uri $uri))) { $apps.Add($a) }
        }
        catch {
            Write-AuditMsg ("  Filter for {0} failed: {1}" -f $audience, $_.Exception.Message) Warn
        }
    }

    # Dedupe by object id
    $byId = @{}
    foreach ($a in $apps) {
        $oid = [string](Get-GraphProp -Object $a -Name 'id')
        if ($oid) { $byId[$oid] = $a }
    }

    $rows = [System.Collections.Generic.List[object]]::new()
    $i = 0
    foreach ($app in @($byId.Values)) {
        $i++
        if ($i % 25 -eq 0) { Write-AuditMsg ("  Processed {0}/{1} outbound apps..." -f $i, $byId.Count) }

        $objectId = [string](Get-GraphProp -Object $app -Name 'id')
        $appId = [string](Get-GraphProp -Object $app -Name 'appId')
        $name = [string](Get-GraphProp -Object $app -Name 'displayName')
        $audience = [string](Get-GraphProp -Object $app -Name 'signInAudience')
        $publisherDomain = [string](Get-GraphProp -Object $app -Name 'publisherDomain')
        $verified = Get-GraphProp -Object $app -Name 'verifiedPublisher'
        $verifiedName = [string](Get-GraphProp -Object $verified -Name 'displayName')
        $creds = Format-CredentialSummary `
            -KeyCredentials (Get-GraphProp -Object $app -Name 'keyCredentials') `
            -PasswordCredentials (Get-GraphProp -Object $app -Name 'passwordCredentials')
        $redirects = Get-RedirectRiskFlags `
            -Web (Get-GraphProp -Object $app -Name 'web') `
            -PublicClient (Get-GraphProp -Object $app -Name 'publicClient') `
            -Spa (Get-GraphProp -Object $app -Name 'spa')
        $permInfo = Resolve-RequiredResourceAccess `
            -RequiredResourceAccess (Get-GraphProp -Object $app -Name 'requiredResourceAccess') `
            -GraphRoleMap $GraphRoleMap
        $ownerCount = Get-AppOwnerCount -ApplicationObjectId $objectId
        $ficSummary = Get-AppFederatedCredentialSummary -ApplicationObjectId $objectId
        $fallbackPublic = [bool](Get-GraphProp -Object $app -Name 'isFallbackPublicClient')
        $homepage = [string](Get-GraphProp -Object (Get-GraphProp -Object $app -Name 'info') -Name 'homepage')

        $risk = [System.Collections.Generic.List[string]]::new()
        if ($permInfo.HighRiskCount -gt 0) { [void]$risk.Add('HighRiskGraphPermissions') }
        if ($creds.SecretCount -gt 0) { [void]$risk.Add('ClientSecretsPresent') }
        if ($creds.ExpiredCount -gt 0) { [void]$risk.Add('ExpiredCredentials') }
        if ($creds.Expiring30Count -gt 0) { [void]$risk.Add('CredentialsExpiring30Days') }
        if ($creds.CertCount -eq 0 -and $creds.SecretCount -eq 0) { [void]$risk.Add('NoCredentialsConfigured') }
        if ($ficSummary.CredentialCount -gt 0) { [void]$risk.Add('FederatedIdentityCredentials') }
        if ($ownerCount -eq 0) { [void]$risk.Add('NoOwners') }
        if ([string]::IsNullOrWhiteSpace($verifiedName)) { [void]$risk.Add('UnverifiedPublisher') }
        if ($audience -eq 'AzureADandPersonalMicrosoftAccount') { [void]$risk.Add('AllowsPersonalMicrosoftAccounts') }
        if ($fallbackPublic) { [void]$risk.Add('FallbackPublicClient') }
        if ($redirects.Flags) {
            foreach ($f in @($redirects.Flags -split ',' | Where-Object { $_ })) { [void]$risk.Add($f) }
        }
        if ($permInfo.ApplicationRoleCount -gt 0) { [void]$risk.Add('RequestsApplicationPermissions') }

        $severity = 'Low'
        if ($risk -contains 'HighRiskGraphPermissions' -or $risk -contains 'AllowsPersonalMicrosoftAccounts') {
            $severity = 'High'
        }
        elseif ($risk.Count -ge 3 -or ($risk -contains 'ClientSecretsPresent') -or ($risk -contains 'NoOwners')) {
            $severity = 'Medium'
        }

        $rows.Add([PSCustomObject][ordered]@{
                Direction              = 'Outbound'
                ObjectType             = 'Application'
                AppId                  = $appId
                ObjectId               = $objectId
                DisplayName            = $name
                SignInAudience         = $audience
                HomeTenantId           = $TenantOrgId
                PublisherDomain        = $publisherDomain
                VerifiedPublisher      = $verifiedName
                Homepage               = $homepage
                CreatedDateTime        = [string](Get-GraphProp -Object $app -Name 'createdDateTime')
                OwnerCount              = $ownerCount
                Owners                  = ''
                AssignedPrincipals      = ''
                AssignedPrincipalCount  = ''
                CertCount               = $creds.CertCount
                SecretCount             = $creds.SecretCount
                ExpiredCredentialCount  = $creds.ExpiredCount
                Expiring30DayCount      = $creds.Expiring30Count
                RedirectUriCount        = $redirects.RedirectUriCount
                RedirectUris            = $redirects.RedirectUris
                PermissionCount         = $permInfo.PermissionCount
                ApplicationRoleCount    = $permInfo.ApplicationRoleCount
                DelegatedScopeCount     = $permInfo.DelegatedScopeCount
                HighRiskPermissionCount = $permInfo.HighRiskCount
                HighRiskPermissions     = $permInfo.HighRiskPermissions
                ApplicationPermissions           = ($(@($permInfo.Permissions -split ';' | ForEach-Object { $_.Trim() } | Where-Object { $_ -like 'App/*' })) -join '; ')
                DelegatedPermissions             = ($(@($permInfo.Permissions -split ';' | ForEach-Object { $_.Trim() } | Where-Object { $_ -like 'Delegated/*' })) -join '; ')
                AdminConsentPermissions          = ''
                UserConsentPermissions           = ''
                AdminConsentDelegatedPermissions = ''
                UserConsentDelegatedPermissions  = ''
                AdminConsentDelegatedScopes      = ''
                UserConsentDelegatedScopes       = ''
                AdminConsentGrantCount           = ''
                UserConsentGrantCount            = ''
                AdminConsentScopeCount           = ''
                UserConsentScopeCount            = ''
                DirectoryRoles                   = ''
                DirectoryRoleCount               = ''
                EligibleDirectoryRoles           = ''
                EligibleDirectoryRoleCount       = ''
                GroupMemberships                 = ''
                GroupMembershipCount             = ''
                OwnedObjects                     = ''
                OwnedObjectCount                 = ''
                ExchangeAppAccess                = ''
                SignInCount                      = ''
                InteractiveUserSignIns           = ''
                NonInteractiveUserSignIns        = ''
                ServicePrincipalSignIns          = ''
                ManagedIdentitySignIns           = ''
                LastSignIn                       = ''
                SignInResources                  = ''
                FederatedCredentials             = $ficSummary.Details
                FederatedCredentialCount         = $(if ($ficSummary.CredentialCount -ge 0) { $ficSummary.CredentialCount } else { '' })
                Permissions                      = $permInfo.Permissions
                AccountEnabled                   = ''
                AppRoleAssignmentCount           = ''
                Oauth2GrantCount                 = ''
                RiskFlags                        = ($risk -join ',')
                Severity                         = $severity
                SecurityNotes                    = (
                    @(
                        'Multi-tenant app registration owned by this tenant; other tenants can admin-consent it. Permissions listed are requested (requiredResourceAccess), not grants in other tenants.'
                        if ($permInfo.HighRiskCount -gt 0) { 'Requests privileged Graph permissions — review necessity and least privilege.' }
                        if ($creds.SecretCount -gt 0) { 'Client secrets are present; prefer certificates and rotate regularly.' }
                        if ($ficSummary.CredentialCount -gt 0) { 'Federated identity credentials configured — passwordless external trust; verify issuer/subject.' }
                        if ($ownerCount -eq 0) { 'No owners assigned — ownership/accountability gap.' }
                        if ($audience -eq 'AzureADandPersonalMicrosoftAccount') { 'Also allows personal Microsoft accounts — broader attack surface.' }
                    ) -join ' '
                )
            })
    }

    Write-AuditMsg ("  Outbound multi-tenant app registrations: {0}" -f $rows.Count) Ok
    # Leading comma keeps empty/single-element arrays from collapsing to $null / a scalar.
    return , $rows.ToArray()
}

function Get-SpAppRoleAssignmentSummary {
    param([Parameter(Mandatory)][string]$ServicePrincipalId, $GraphRoleMap)

    $high = [System.Collections.Generic.List[string]]::new()
    $details = [System.Collections.Generic.List[string]]::new()
    try {
        $assignments = ConvertTo-ObjectArray (Get-GraphPaged -Uri ("https://graph.microsoft.com/v1.0/servicePrincipals/{0}/appRoleAssignments" -f $ServicePrincipalId))
    }
    catch {
        return [PSCustomObject]@{ AssignmentCount = -1; HighRiskCount = 0; HighRisk = ''; Details = '' }
    }

    foreach ($a in $assignments) {
        if (-not (Test-IsGraphRowObject $a)) { continue }
        $roleId = [string](Get-GraphProp -Object $a -Name 'appRoleId')
        $resId = [string](Get-GraphProp -Object $a -Name 'resourceId')
        $resName = [string](Get-GraphProp -Object $a -Name 'resourceDisplayName')
        if ($roleId -eq '00000000-0000-0000-0000-000000000000') {
            $label = 'Default Access'
        }
        else {
            $label = Get-ResourceAppRoleLabel -ResourceId $resId -AppRoleId $roleId -ResourceDisplayName $resName -GraphRoleMap $GraphRoleMap
        }
        if ([string]::IsNullOrWhiteSpace($label)) { $label = $(if ($roleId) { $roleId } else { 'unknown' }) }
        $entry = '{0}: {1}' -f $(if ($resName) { $resName } else { 'resource' }), $label
        [void]$details.Add($entry)
        if (Test-IsHighRiskPermission -Value $label) { [void]$high.Add($entry) }
    }

    return [PSCustomObject]@{
        AssignmentCount = $details.Count
        HighRiskCount   = $high.Count
        HighRisk        = ($high -join '; ')
        Details         = ($details -join '; ')
    }
}

function Resolve-Oauth2ResourceDisplayName {
    param([string]$ResourceId, $GraphRoleMap)

    if ([string]::IsNullOrWhiteSpace($ResourceId)) { return 'resource' }
    if ($GraphRoleMap -and $GraphRoleMap.SpId -and [string]::Equals($ResourceId, [string]$GraphRoleMap.SpId, [StringComparison]::OrdinalIgnoreCase)) {
        return 'Microsoft Graph'
    }
    try {
        $res = Invoke-MgGraphRequest -Method GET `
            -Uri ("https://graph.microsoft.com/v1.0/servicePrincipals/{0}?`$select=displayName" -f $ResourceId) `
            -ErrorAction Stop
        $dn = [string](Get-GraphProp -Object $res -Name 'displayName')
        if ($dn) { return $dn }
    }
    catch { }
    return $ResourceId
}

function Resolve-ConsentPrincipalLabel {
    param([string]$PrincipalId)

    if ([string]::IsNullOrWhiteSpace($PrincipalId)) { return '' }
    try {
        $u = Invoke-MgGraphRequest -Method GET `
            -Uri ("https://graph.microsoft.com/v1.0/directoryObjects/{0}?`$select=displayName,userPrincipalName" -f $PrincipalId) `
            -ErrorAction Stop
        $dn = [string](Get-GraphProp -Object $u -Name 'displayName')
        $upn = [string](Get-GraphProp -Object $u -Name 'userPrincipalName')
        if ($dn -and $upn) { return '{0} <{1}>' -f $dn, $upn }
        if ($dn) { return $dn }
        if ($upn) { return $upn }
    }
    catch { }
    return $PrincipalId
}

function Get-SpOauth2GrantSummary {
    param([Parameter(Mandatory)][string]$ServicePrincipalId, $GraphRoleMap)

    # oauth2PermissionGrants:
    #   consentType=AllPrincipals => admin consent (tenant-wide)
    #   consentType=Principal     => user consent (specific user)
    $adminEntries = [System.Collections.Generic.List[string]]::new()
    $userEntries = [System.Collections.Generic.List[string]]::new()
    $adminScopes = [System.Collections.Generic.List[string]]::new()
    $userScopes = [System.Collections.Generic.List[string]]::new()
    $high = [System.Collections.Generic.List[string]]::new()

    try {
        $filter = [uri]::EscapeDataString("clientId eq '$ServicePrincipalId'")
        $grants = ConvertTo-ObjectArray (Get-GraphPaged -Uri ('https://graph.microsoft.com/v1.0/oauth2PermissionGrants?$filter={0}' -f $filter))
    }
    catch {
        return [PSCustomObject]@{
            GrantCount              = -1
            ScopeCount              = -1
            AdminGrantCount         = -1
            UserGrantCount          = -1
            AdminScopeCount         = -1
            UserScopeCount          = -1
            HighRiskCount           = 0
            HighRisk                = ''
            Details                 = ''
            AdminConsentDetails     = ''
            UserConsentDetails      = ''
            AdminConsentScopes      = ''
            UserConsentScopes       = ''
        }
    }

    foreach ($g in $grants) {
        if (-not (Test-IsGraphRowObject $g)) { continue }
        $consentType = [string](Get-GraphProp -Object $g -Name 'consentType')
        $resourceId = [string](Get-GraphProp -Object $g -Name 'resourceId')
        $principalId = [string](Get-GraphProp -Object $g -Name 'principalId')
        $scopeRaw = [string](Get-GraphProp -Object $g -Name 'scope')
        $scopes = @($scopeRaw -split '\s+' | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | ForEach-Object { $_.Trim() })
        $resourceLabel = Resolve-Oauth2ResourceDisplayName -ResourceId $resourceId -GraphRoleMap $GraphRoleMap
        $scopeText = if ((Get-ObjectCount $scopes) -gt 0) { ($scopes -join ', ') } else { '(no scopes returned)' }

        $isAdminConsent = [string]::Equals($consentType, 'AllPrincipals', [StringComparison]::OrdinalIgnoreCase)
        $isUserConsent = [string]::Equals($consentType, 'Principal', [StringComparison]::OrdinalIgnoreCase) -or (
            -not $isAdminConsent -and -not [string]::IsNullOrWhiteSpace($principalId)
        )

        if ($isAdminConsent) {
            foreach ($s in $scopes) {
                [void]$adminScopes.Add($s)
                if (Test-IsHighRiskPermission -Value $s) { [void]$high.Add("AdminConsent/$s") }
            }
            $entry = '{0} | AdminConsent(AllPrincipals) | {1}' -f $resourceLabel, $scopeText
            [void]$adminEntries.Add($entry)
        }
        elseif ($isUserConsent) {
            $userLabel = Resolve-ConsentPrincipalLabel -PrincipalId $principalId
            if (-not $userLabel) { $userLabel = 'user' }
            foreach ($s in $scopes) {
                [void]$userScopes.Add($s)
                if (Test-IsHighRiskPermission -Value $s) { [void]$high.Add("UserConsent/$s") }
            }
            $entry = '{0} | UserConsent({1}) | {2}' -f $resourceLabel, $userLabel, $scopeText
            [void]$userEntries.Add($entry)
        }
        else {
            # Unknown consentType — keep under admin bucket with raw type for visibility.
            foreach ($s in $scopes) {
                [void]$adminScopes.Add($s)
                if (Test-IsHighRiskPermission -Value $s) { [void]$high.Add($s) }
            }
            $entry = '{0} | ConsentType={1} | {2}' -f $resourceLabel, $(if ($consentType) { $consentType } else { 'unknown' }), $scopeText
            [void]$adminEntries.Add($entry)
        }
    }

    $allEntries = [System.Collections.Generic.List[string]]::new()
    foreach ($e in $adminEntries) { [void]$allEntries.Add($e) }
    foreach ($e in $userEntries) { [void]$allEntries.Add($e) }

    $uniqueAdminScopes = @($adminScopes | Select-Object -Unique)
    $uniqueUserScopes = @($userScopes | Select-Object -Unique)
    $uniqueAllScopes = @(@($uniqueAdminScopes) + @($uniqueUserScopes) | Select-Object -Unique)
    $uniqueHigh = @($high | Select-Object -Unique)

    return [PSCustomObject]@{
        GrantCount          = $allEntries.Count
        ScopeCount          = (Get-ObjectCount $uniqueAllScopes)
        AdminGrantCount     = $adminEntries.Count
        UserGrantCount      = $userEntries.Count
        AdminScopeCount     = (Get-ObjectCount $uniqueAdminScopes)
        UserScopeCount      = (Get-ObjectCount $uniqueUserScopes)
        HighRiskCount       = (Get-ObjectCount $uniqueHigh)
        HighRisk            = ($uniqueHigh -join '; ')
        Details             = ($allEntries -join ' || ')
        AdminConsentDetails = ($adminEntries -join ' || ')
        UserConsentDetails  = ($userEntries -join ' || ')
        AdminConsentScopes  = ($uniqueAdminScopes -join ', ')
        UserConsentScopes   = ($uniqueUserScopes -join ', ')
    }
}

function Get-SpDirectoryRoleSummary {
    param([Parameter(Mandatory)][string]$ServicePrincipalId)

    $roles = [System.Collections.Generic.List[string]]::new()

    # Cast to directoryRole so groups are excluded; do not $select away @odata.type.
    try {
        $members = ConvertTo-ObjectArray (Get-GraphPaged -Uri ("https://graph.microsoft.com/v1.0/servicePrincipals/{0}/memberOf/microsoft.graph.directoryRole" -f $ServicePrincipalId))
        foreach ($m in $members) {
            if (-not (Test-IsGraphRowObject $m)) { continue }
            $name = [string](Get-GraphProp -Object $m -Name 'displayName')
            if ($name -and -not ($roles -contains $name)) { [void]$roles.Add($name) }
        }
    }
    catch { }

    # Fallback: untyped memberOf, keep only directoryRole types.
    if ($roles.Count -eq 0) {
        try {
            $members = ConvertTo-ObjectArray (Get-GraphPaged -Uri ("https://graph.microsoft.com/v1.0/servicePrincipals/{0}/memberOf" -f $ServicePrincipalId))
            foreach ($m in $members) {
                if (-not (Test-IsGraphRowObject $m)) { continue }
                $odataType = [string](Get-GraphProp -Object $m -Name '@odata.type')
                $name = [string](Get-GraphProp -Object $m -Name 'displayName')
                if ($name -and $odataType -match 'directoryRole' -and -not ($roles -contains $name)) {
                    [void]$roles.Add($name)
                }
            }
        }
        catch { }
    }

    # Unified role assignments (directory roles assigned to the SP).
    try {
        $filter = [uri]::EscapeDataString("principalId eq '$ServicePrincipalId'")
        $assignments = ConvertTo-ObjectArray (Get-GraphPaged -Uri ('https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?$filter={0}' -f $filter))
        foreach ($ra in $assignments) {
            if (-not (Test-IsGraphRowObject $ra)) { continue }
            $roleDefId = [string](Get-GraphProp -Object $ra -Name 'roleDefinitionId')
            $rn = $null
            if ($roleDefId) {
                try {
                    $rd = Invoke-MgGraphRequest -Method GET `
                        -Uri ("https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions/{0}?`$select=displayName" -f $roleDefId) `
                        -ErrorAction Stop
                    $rn = [string](Get-GraphProp -Object $rd -Name 'displayName')
                }
                catch { }
            }
            if (-not $rn) { $rn = $roleDefId }
            if ($rn -and -not ($roles -contains $rn)) { [void]$roles.Add($rn) }
        }
    }
    catch { }

    return [PSCustomObject]@{
        RoleCount = $roles.Count
        Details   = ($roles -join '; ')
    }
}

function Get-SpOwnerSummary {
    param([Parameter(Mandatory)][string]$ServicePrincipalId)

    $owners = [System.Collections.Generic.List[string]]::new()
    try {
        $rows = ConvertTo-ObjectArray (Get-GraphPaged -Uri ("https://graph.microsoft.com/v1.0/servicePrincipals/{0}/owners?`$select=id,displayName,userPrincipalName" -f $ServicePrincipalId))
    }
    catch {
        return [PSCustomObject]@{ OwnerCount = -1; Details = '' }
    }

    foreach ($o in $rows) {
        if (-not (Test-IsGraphRowObject $o)) { continue }
        $dn = [string](Get-GraphProp -Object $o -Name 'displayName')
        $upn = [string](Get-GraphProp -Object $o -Name 'userPrincipalName')
        $id = [string](Get-GraphProp -Object $o -Name 'id')
        $label = if ($dn -and $upn) { '{0} <{1}>' -f $dn, $upn } elseif ($dn) { $dn } elseif ($upn) { $upn } else { $id }
        if ($label) { [void]$owners.Add($label) }
    }

    return [PSCustomObject]@{
        OwnerCount = $owners.Count
        Details    = ($owners -join '; ')
    }
}

function Get-SpAppRoleAssignedToSummary {
    param([Parameter(Mandatory)][string]$ServicePrincipalId, $GraphRoleMap)

    # Users/groups/SPs assigned to this enterprise app (Entra "Users and groups").
    $entries = [System.Collections.Generic.List[string]]::new()
    try {
        $rows = ConvertTo-ObjectArray (Get-GraphPaged -Uri ("https://graph.microsoft.com/v1.0/servicePrincipals/{0}/appRoleAssignedTo" -f $ServicePrincipalId))
    }
    catch {
        return [PSCustomObject]@{ AssignmentCount = -1; Details = '' }
    }

    foreach ($a in $rows) {
        if (-not (Test-IsGraphRowObject $a)) { continue }
        $principalName = [string](Get-GraphProp -Object $a -Name 'principalDisplayName')
        $principalType = [string](Get-GraphProp -Object $a -Name 'principalType')
        $principalId = [string](Get-GraphProp -Object $a -Name 'principalId')
        $roleId = [string](Get-GraphProp -Object $a -Name 'appRoleId')
        $roleLabel = if ($roleId -eq '00000000-0000-0000-0000-000000000000') {
            'Default Access'
        }
        else {
            Get-ResourceAppRoleLabel -ResourceId $ServicePrincipalId -AppRoleId $roleId -ResourceDisplayName '' -GraphRoleMap $GraphRoleMap
        }
        if ([string]::IsNullOrWhiteSpace($principalName)) { $principalName = $principalId }
        if ([string]::IsNullOrWhiteSpace($principalType)) { $principalType = 'Principal' }
        [void]$entries.Add(('{0} ({1}) -> {2}' -f $principalName, $principalType, $roleLabel))
    }

    return [PSCustomObject]@{
        AssignmentCount = $entries.Count
        Details         = ($entries -join '; ')
    }
}

function Get-SpGroupMembershipSummary {
    param([Parameter(Mandatory)][string]$ServicePrincipalId)

    # Security-group memberships can grant SharePoint/site access, app-role assignments,
    # or Conditional Access scoping indirectly — a common blind spot.
    $groups = [System.Collections.Generic.List[string]]::new()
    try {
        $rows = ConvertTo-ObjectArray (Get-GraphPaged -Uri ("https://graph.microsoft.com/v1.0/servicePrincipals/{0}/memberOf/microsoft.graph.group?`$select=id,displayName,securityEnabled,isAssignableToRole" -f $ServicePrincipalId))
    }
    catch {
        return [PSCustomObject]@{ GroupCount = -1; RoleAssignableCount = 0; Details = '' }
    }

    $roleAssignable = 0
    foreach ($g in $rows) {
        if (-not (Test-IsGraphRowObject $g)) { continue }
        $name = [string](Get-GraphProp -Object $g -Name 'displayName')
        if (-not $name) { continue }
        $isRoleAssignable = [bool](Get-GraphProp -Object $g -Name 'isAssignableToRole')
        if ($isRoleAssignable) {
            $roleAssignable++
            $name = "$name [role-assignable]"
        }
        if (-not ($groups -contains $name)) { [void]$groups.Add($name) }
    }

    return [PSCustomObject]@{
        GroupCount          = $groups.Count
        RoleAssignableCount = $roleAssignable
        Details             = ($groups -join '; ')
    }
}

function Get-SpOwnedObjectsSummary {
    param([Parameter(Mandatory)][string]$ServicePrincipalId)

    # Objects this SP owns (apps/groups/SPs) — indirect privilege (can add credentials, members).
    $owned = [System.Collections.Generic.List[string]]::new()
    try {
        $rows = ConvertTo-ObjectArray (Get-GraphPaged -Uri ("https://graph.microsoft.com/v1.0/servicePrincipals/{0}/ownedObjects?`$select=id,displayName" -f $ServicePrincipalId))
    }
    catch {
        return [PSCustomObject]@{ OwnedCount = -1; Details = '' }
    }

    foreach ($o in $rows) {
        if (-not (Test-IsGraphRowObject $o)) { continue }
        $odataType = [string](Get-GraphProp -Object $o -Name '@odata.type')
        $name = [string](Get-GraphProp -Object $o -Name 'displayName')
        $kind = ($odataType -replace '#microsoft.graph.', '')
        if (-not $name) { $name = [string](Get-GraphProp -Object $o -Name 'id') }
        $label = if ($kind) { '{0} ({1})' -f $name, $kind } else { $name }
        if ($label -and -not ($owned -contains $label)) { [void]$owned.Add($label) }
    }

    return [PSCustomObject]@{
        OwnedCount = $owned.Count
        Details    = ($owned -join '; ')
    }
}

function Get-SpEligibleRoleSummary {
    param([Parameter(Mandatory)][string]$ServicePrincipalId)

    # PIM-eligible directory roles (not yet active). Requires RoleManagement.Read.Directory
    # and Entra ID P2; skip gracefully when unavailable.
    $roles = [System.Collections.Generic.List[string]]::new()
    try {
        $filter = [uri]::EscapeDataString("principalId eq '$ServicePrincipalId'")
        $rows = ConvertTo-ObjectArray (Get-GraphPaged -Uri ('https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilityScheduleInstances?$filter={0}' -f $filter))
    }
    catch {
        return [PSCustomObject]@{ RoleCount = -1; Details = '' }
    }

    foreach ($r in $rows) {
        if (-not (Test-IsGraphRowObject $r)) { continue }
        $roleDefId = [string](Get-GraphProp -Object $r -Name 'roleDefinitionId')
        $rn = $null
        if ($roleDefId) {
            try {
                $rd = Invoke-GraphRequestWithRetry -Method GET `
                    -Uri ("https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions/{0}?`$select=displayName" -f $roleDefId)
                $rn = [string](Get-GraphProp -Object $rd -Name 'displayName')
            }
            catch { }
        }
        if (-not $rn) { $rn = $roleDefId }
        if ($rn -and -not ($roles -contains $rn)) { [void]$roles.Add($rn) }
    }

    return [PSCustomObject]@{
        RoleCount = $roles.Count
        Details   = ($roles -join '; ')
    }
}

function Get-SpSignInSummary {
    param(
        [Parameter(Mandatory)][string]$AppId,
        [int]$LookbackDays = 30
    )

    # Evidence of actual use for this appId across ALL sign-in categories:
    #   interactiveUser + nonInteractiveUser = users signing INTO the app (delegated)
    #   servicePrincipal                     = the app authenticating as itself (app-only)
    #   managedIdentity                      = managed-identity sign-ins
    # The signIns endpoint returns only interactive user sign-ins unless you filter on
    # signInEventTypes, so each category is queried explicitly.
    # Requires AuditLog.Read.All + Entra ID P1. Counts are -1 when unavailable.
    $unavailable = [PSCustomObject]@{
        SignInCount             = -1
        LastSignIn              = ''
        Details                 = ''
        InteractiveUserCount    = -1
        NonInteractiveUserCount = -1
        ServicePrincipalCount   = -1
        ManagedIdentityCount    = -1
        Records                 = @()
    }
    if ([string]::IsNullOrWhiteSpace($AppId)) { return $unavailable }

    $since = [DateTime]::UtcNow.AddDays(-[Math]::Abs($LookbackDays)).ToString('yyyy-MM-ddTHH:mm:ssZ')

    # Performance: the signIns reporting store is high-latency, so pull ALL four event types in a
    # SINGLE query per SP (one lambda OR'ing every type) and bucket rows client-side, rather than
    # firing one slow query per type. Rows are capped (top x MaxPages) to keep the summary fast.
    $allTypes = "signInEventTypes/any(t: t eq 'interactiveUser' or t eq 'nonInteractiveUser' or t eq 'servicePrincipal' or t eq 'managedIdentity')"
    # Match sign-ins where this app is the CLIENT (appId) OR the RESOURCE (resourceId). resourceId
    # is the resource's appId, so non-interactive/token flows where the SP is the resource are caught.
    $combined = [uri]::EscapeDataString("(appId eq '$AppId' or resourceId eq '$AppId') and createdDateTime ge $since and $allTypes")
    $clientOnly = [uri]::EscapeDataString("appId eq '$AppId' and createdDateTime ge $since and $allTypes")

    # NOTE: signInEventTypes is only a filterable property on the /beta endpoint. The /v1.0 signIns
    # endpoint returns interactive sign-ins only and rejects signInEventTypes filters, so /beta is required.
    $rows = $null
    $firstError = $null
    try {
        $rows = ConvertTo-ObjectArray (Get-GraphPaged -Uri ('https://graph.microsoft.com/beta/auditLogs/signIns?$filter={0}&$top=100' -f $combined) -MaxPages 3)
    }
    catch {
        $firstError = $_.Exception.Message
        # Fall back to client-only filter if the combined (appId OR resourceId) filter is rejected.
        try {
            $rows = ConvertTo-ObjectArray (Get-GraphPaged -Uri ('https://graph.microsoft.com/beta/auditLogs/signIns?$filter={0}&$top=100' -f $clientOnly) -MaxPages 3)
        }
        catch {
            if (-not $firstError) { $firstError = $_.Exception.Message }
            if ($firstError -and -not $Script:SignInErrorReported) {
                $Script:SignInErrorReported = $true
                $hint = ''
                if ($firstError -match '403|Forbidden|Authorization_RequestDenied|insufficient') {
                    $hint = ' (missing AuditLog.Read.All consent or no Entra ID P1 license; re-run with -ForceReconnect to grant the scope)'
                }
                elseif ($firstError -match '401|expired|InvalidAuthenticationToken') {
                    $hint = ' (token expired; re-run with -ForceReconnect)'
                }
                Write-AuditMsg ("  WARNING: sign-in log queries failed - reporting n/a. First error: {0}{1}" -f $firstError, $hint) Warn
            }
            return $unavailable
        }
    }

    $overallLast = $null
    $resources = [System.Collections.Generic.List[string]]::new()
    $records = [System.Collections.Generic.List[object]]::new()
    $ic = 0; $ni = 0; $sp = 0; $mi = 0
    $total = 0
    foreach ($s in $rows) {
        if (-not (Test-IsGraphRowObject $s)) { continue }
        $total++
        $created = [string](Get-GraphProp -Object $s -Name 'createdDateTime')
        $createdUtc = ''
        if ($created) {
            try {
                $dt = [DateTime]::Parse($created).ToUniversalTime()
                $createdUtc = $dt.ToString('u')
                if (-not $overallLast -or $dt -gt $overallLast) { $overallLast = $dt }
            }
            catch { $createdUtc = $created }
        }
        $resName = [string](Get-GraphProp -Object $s -Name 'resourceDisplayName')
        if ($resName -and -not ($resources -contains $resName)) { [void]$resources.Add($resName) }

        $typeList = [System.Collections.Generic.List[string]]::new()
        $types = Get-GraphProp -Object $s -Name 'signInEventTypes'
        foreach ($t in (ConvertTo-ObjectArray $types)) {
            [void]$typeList.Add([string]$t)
            switch ([string]$t) {
                'interactiveUser' { $ic++ }
                'nonInteractiveUser' { $ni++ }
                'servicePrincipal' { $sp++ }
                'managedIdentity' { $mi++ }
            }
        }

        # Identity: user principal name for user sign-ins, else the calling app/SP name.
        $identity = [string](Get-GraphProp -Object $s -Name 'userPrincipalName')
        if ([string]::IsNullOrWhiteSpace($identity)) { $identity = [string](Get-GraphProp -Object $s -Name 'userDisplayName') }
        if ([string]::IsNullOrWhiteSpace($identity)) { $identity = [string](Get-GraphProp -Object $s -Name 'appDisplayName') }
        if ([string]::IsNullOrWhiteSpace($identity)) { $identity = [string](Get-GraphProp -Object $s -Name 'servicePrincipalName') }

        # Status: errorCode 0 = success; otherwise surface the failure reason/code.
        $statusText = 'Success'
        $statusOk = $true
        $status = Get-GraphProp -Object $s -Name 'status'
        if ($status) {
            $errCode = [string](Get-GraphProp -Object $status -Name 'errorCode')
            $failReason = [string](Get-GraphProp -Object $status -Name 'failureReason')
            if ($errCode -and $errCode -ne '0') {
                $statusOk = $false
                $statusText = if ($failReason -and $failReason -ne 'Other.') { "Failure ($errCode): $failReason" } else { "Failure ($errCode)" }
            }
        }

        # Location: "City, Country".
        $locText = ''
        $loc = Get-GraphProp -Object $s -Name 'location'
        if ($loc) {
            $city = [string](Get-GraphProp -Object $loc -Name 'city')
            $country = [string](Get-GraphProp -Object $loc -Name 'countryOrRegion')
            $locText = (@($city, $country) | Where-Object { $_ }) -join ', '
        }

        [void]$records.Add([PSCustomObject][ordered]@{
                Time      = $createdUtc
                Identity  = $identity
                EventType = ($typeList -join ', ')
                IpAddress = [string](Get-GraphProp -Object $s -Name 'ipAddress')
                Location  = $locText
                Status    = $statusText
                StatusOk  = $statusOk
                Resource  = $resName
                ClientApp = [string](Get-GraphProp -Object $s -Name 'clientAppUsed')
            })
    }

    return [PSCustomObject]@{
        SignInCount             = $total
        LastSignIn              = $(if ($overallLast) { $overallLast.ToString('u') } else { '' })
        Details                 = ($resources -join '; ')
        InteractiveUserCount    = $ic
        NonInteractiveUserCount = $ni
        ServicePrincipalCount   = $sp
        ManagedIdentityCount    = $mi
        Records                 = $records.ToArray()
    }
}

#region IP intelligence (RDAP + reverse DNS)
function Test-IsPrivateOrReservedIp {
    param([string]$Ip)
    if ([string]::IsNullOrWhiteSpace($Ip)) { return $true }
    $parsed = $null
    if (-not [System.Net.IPAddress]::TryParse($Ip, [ref]$parsed)) { return $true }

    if ($parsed.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6) {
        $s = $Ip.ToLowerInvariant()
        # loopback ::1, link-local fe80::/10, unique-local fc00::/7
        if ($s -eq '::1' -or $s.StartsWith('fe8') -or $s.StartsWith('fe9') -or $s.StartsWith('fea') -or $s.StartsWith('feb') -or $s.StartsWith('fc') -or $s.StartsWith('fd')) { return $true }
        return $false
    }

    $b = $parsed.GetAddressBytes()
    switch ($b[0]) {
        10 { return $true }                                   # 10.0.0.0/8
        127 { return $true }                                  # loopback
        169 { if ($b[1] -eq 254) { return $true } }           # link-local 169.254/16
        172 { if ($b[1] -ge 16 -and $b[1] -le 31) { return $true } } # 172.16/12
        192 { if ($b[1] -eq 168) { return $true } }           # 192.168/16
        0 { return $true }
        255 { return $true }
    }
    return $false
}

function Get-RdapVcardFn {
    # Return the 'fn' (formatted name / org) value from a single RDAP entity's vcardArray.
    param($Entity)
    if ($null -eq $Entity) { return '' }
    if (-not $Entity.PSObject.Properties['vcardArray']) { return '' }
    $va = @($Entity.vcardArray)
    if ($va.Count -lt 2) { return '' }
    foreach ($item in @($va[1])) {
        $parts = @($item)
        if ($parts.Count -ge 4 -and [string]$parts[0] -eq 'fn') { return [string]$parts[3] }
    }
    return ''
}

function Test-RdapEntityHasRole {
    param($Entity, [string]$Role)
    if ($null -eq $Entity -or -not $Entity.PSObject.Properties['roles']) { return $false }
    foreach ($r in @($Entity.roles)) { if ([string]$r -eq $Role) { return $true } }
    return $false
}

function Get-RdapRegistrant {
    # Prefer the org name of entities with the 'registrant' role; fall back to top-level entity names.
    # Avoids recursing into nested contact entities (abuse/admin/technical) which add noise.
    param($Resp)
    $preferred = [System.Collections.Generic.List[string]]::new()
    $fallback = [System.Collections.Generic.List[string]]::new()
    if ($null -eq $Resp -or -not $Resp.PSObject.Properties['entities']) { return '' }
    foreach ($e in @($Resp.entities)) {
        $fn = Get-RdapVcardFn $e
        if (-not $fn) { continue }
        if (Test-RdapEntityHasRole -Entity $e -Role 'registrant') { [void]$preferred.Add($fn) }
        else { [void]$fallback.Add($fn) }
    }
    $chosen = if ($preferred.Count -gt 0) { $preferred } else { $fallback }
    return ((@($chosen) | Select-Object -Unique) -join '; ')
}

function ConvertTo-IpNumber {
    # Convert an IPv4/IPv6 string to a comparable non-negative BigInteger (network byte order).
    param([string]$Ip)
    $addr = $null
    if (-not [System.Net.IPAddress]::TryParse($Ip, [ref]$addr)) { return $null }
    $bytes = $addr.GetAddressBytes()
    [array]::Reverse($bytes)            # BigInteger wants little-endian
    $bytes = $bytes + [byte]0           # append 0x00 so the value stays positive
    return [System.Numerics.BigInteger]::new($bytes)
}

function Get-RdapRegistryFromLinks {
    # Identify the responsible RIR from the RDAP 'links' (mirrors the Network Diagnostic Tool).
    param($Resp)
    if ($null -eq $Resp -or -not $Resp.PSObject.Properties['links']) { return '' }
    $map = @{ 'arin.net' = 'ARIN'; 'ripe.net' = 'RIPE'; 'apnic.net' = 'APNIC'; 'lacnic.net' = 'LACNIC'; 'afrinic.net' = 'AFRINIC' }
    foreach ($link in @($Resp.links)) {
        $href = if ($link.PSObject.Properties['href']) { [string]$link.href } else { '' }
        foreach ($k in $map.Keys) { if ($href -match [regex]::Escape($k)) { return $map[$k] } }
    }
    return ''
}

function Get-IpAddressIntelligence {
    <#
        Enriches a single IP with a reverse-DNS (PTR) lookup and RDAP registration data
        (registrant/org, network name, CIDR, country). The RDAP response describes the whole
        network allocation, so the parsed result is cached by that subnet range: subsequent IPs
        inside an already-resolved block reuse it with no extra RDAP call. Reverse DNS is always
        per-IP. Private/reserved IPs are flagged and never sent to RDAP.
    #>
    param([Parameter(Mandatory)][string]$Ip)

    $result = [PSCustomObject][ordered]@{
        IpAddress   = $Ip
        ReverseDns  = ''
        Registrant  = ''
        NetworkName = ''
        Cidr        = ''
        Country     = ''
        Source      = ''
    }

    try { $result.ReverseDns = [System.Net.Dns]::GetHostEntry($Ip).HostName } catch { $result.ReverseDns = '' }

    if (Test-IsPrivateOrReservedIp -Ip $Ip) {
        $result.Registrant = 'Private / reserved (non-routable)'
        $result.Source = 'n/a'
        return $result
    }

    # Subnet cache hit: reuse the network's RDAP data (only reverse DNS differs per IP).
    $ipNum = ConvertTo-IpNumber -Ip $Ip
    if ($null -ne $ipNum) {
        foreach ($entry in $Script:RdapSubnetCache) {
            if ($ipNum -ge $entry.Start -and $ipNum -le $entry.End) {
                $result.Registrant = $entry.Registrant
                $result.NetworkName = $entry.NetworkName
                $result.Cidr = $entry.Cidr
                $result.Country = $entry.Country
                $result.Source = ('{0} (cached subnet {1})' -f $entry.Source, $entry.Cidr)
                return $result
            }
        }
    }

    try {
        $resp = Invoke-RestMethod -Uri ('https://rdap.org/ip/{0}' -f $Ip) -Headers @{ Accept = 'application/rdap+json, application/json' } -TimeoutSec 20 -ErrorAction Stop
        if ($resp.PSObject.Properties['name']) { $result.NetworkName = [string]$resp.name }
        if ($resp.PSObject.Properties['country']) { $result.Country = [string]$resp.country }

        if ($resp.PSObject.Properties['cidr0_cidrs'] -and $resp.cidr0_cidrs) {
            $cidrs = foreach ($c in @($resp.cidr0_cidrs)) {
                $prefix = if ($c.PSObject.Properties['v4prefix']) { [string]$c.v4prefix } elseif ($c.PSObject.Properties['v6prefix']) { [string]$c.v6prefix } else { '' }
                $len = if ($c.PSObject.Properties['length']) { [string]$c.length } else { '' }
                if ($prefix) { "$prefix/$len" }
            }
            $result.Cidr = (@($cidrs) -join ', ')
        }
        if (-not $result.Cidr -and $resp.PSObject.Properties['startAddress'] -and $resp.startAddress) {
            $end = if ($resp.PSObject.Properties['endAddress']) { [string]$resp.endAddress } else { '' }
            $result.Cidr = ("{0} - {1}" -f [string]$resp.startAddress, $end)
        }

        $result.Registrant = Get-RdapRegistrant -Resp $resp
        if (-not $result.Registrant -and $result.NetworkName) { $result.Registrant = $result.NetworkName }
        $rir = Get-RdapRegistryFromLinks -Resp $resp
        $result.Source = if ($rir) { "RDAP ($rir)" } else { 'RDAP' }

        # Cache by the network allocation range so other IPs in this subnet skip the RDAP call.
        $startStr = if ($resp.PSObject.Properties['startAddress']) { [string]$resp.startAddress } else { '' }
        $endStr = if ($resp.PSObject.Properties['endAddress']) { [string]$resp.endAddress } else { '' }
        $startNum = if ($startStr) { ConvertTo-IpNumber -Ip $startStr } else { $null }
        $endNum = if ($endStr) { ConvertTo-IpNumber -Ip $endStr } else { $null }
        if ($null -ne $startNum -and $null -ne $endNum -and $endNum -ge $startNum) {
            [void]$Script:RdapSubnetCache.Add([PSCustomObject]@{
                    Start       = $startNum
                    End         = $endNum
                    Registrant  = $result.Registrant
                    NetworkName = $result.NetworkName
                    Cidr        = $result.Cidr
                    Country     = $result.Country
                    Source      = $result.Source
                })
        }
    }
    catch {
        $result.Source = ("RDAP lookup failed: {0}" -f $_.Exception.Message)
    }

    return $result
}

function Get-SignInIpIntelligence {
    <#
        Builds per-IP intelligence for every unique source IP seen across the sign-in records:
        event count, which applications used it, reverse DNS, and RDAP registrant/network/country.
    #>
    param([AllowEmptyCollection()][object[]]$SignInRecords)

    $records = [System.Collections.Generic.List[object]]::new()
    $ipGroups = @($SignInRecords | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_.IpAddress) } | Group-Object -Property IpAddress)
    if ($ipGroups.Count -eq 0) { return , $records.ToArray() }

    Write-AuditMsg ("Enriching {0} unique sign-in IP(s) via RDAP + reverse DNS (subnet-cached)..." -f $ipGroups.Count)
    $n = 0
    foreach ($g in $ipGroups) {
        $n++
        $ip = [string]$g.Name
        $apps = @($g.Group | ForEach-Object { [string]$_.ServicePrincipal } | Where-Object { $_ } | Select-Object -Unique)
        $lastSeen = ''
        $times = @($g.Group | ForEach-Object { [string]$_.Time } | Where-Object { $_ } | Sort-Object -Descending)
        if ($times.Count -gt 0) { $lastSeen = $times[0] }

        $intel = Get-IpAddressIntelligence -Ip $ip
        $cacheTag = if ([string]$intel.Source -match 'cached') { ' (cached)' } else { '' }
        Write-AuditMsg ("  [{0}/{1}] {2}{3}" -f $n, $ipGroups.Count, $ip, $cacheTag)
        [void]$records.Add([PSCustomObject][ordered]@{
                IpAddress    = $ip
                Events       = $g.Count
                Applications = (@($apps) -join '; ')
                ReverseDns   = $intel.ReverseDns
                Registrant   = $intel.Registrant
                NetworkName  = $intel.NetworkName
                Cidr         = $intel.Cidr
                Country      = $intel.Country
                LastSeen     = $lastSeen
                Source       = $intel.Source
            })
    }
    return , $records.ToArray()
}
#endregion

#region Entra App Gallery
function Get-AppTemplateName {
    # Resolve an application template's display name from the Entra App Gallery catalog (cached).
    param([Parameter(Mandatory)][string]$TemplateId)
    if ($Script:AppTemplateNameCache.ContainsKey($TemplateId)) { return $Script:AppTemplateNameCache[$TemplateId] }
    $name = ''
    try {
        $uri = 'https://graph.microsoft.com/v1.0/applicationTemplates/{0}?$select=id,displayName,publisher' -f $TemplateId
        $t = Invoke-GraphRequestWithRetry -Uri $uri
        $name = [string](Get-GraphProp -Object $t -Name 'displayName')
    }
    catch { $name = '' }
    $Script:AppTemplateNameCache[$TemplateId] = $name
    return $name
}

function Get-AppGalleryStatus {
    <#
        Determines whether an enterprise application is listed in the Microsoft Entra App Gallery.
        Gallery apps are instantiated from an application template, so servicePrincipal.applicationTemplateId
        is populated with a real template id. The special id 8adf8e6e-... means "non-gallery / custom".
    #>
    param([string]$TemplateId)

    if ([string]::IsNullOrWhiteSpace($TemplateId)) {
        return [PSCustomObject]@{ InGallery = $false; Status = 'Custom (no template)'; TemplateId = ''; TemplateName = '' }
    }
    if ($TemplateId -eq $Script:NonGalleryTemplateId) {
        return [PSCustomObject]@{ InGallery = $false; Status = 'Non-gallery (custom)'; TemplateId = $TemplateId; TemplateName = 'Non-gallery application' }
    }
    $name = Get-AppTemplateName -TemplateId $TemplateId
    return [PSCustomObject]@{ InGallery = $true; Status = 'Gallery'; TemplateId = $TemplateId; TemplateName = $name }
}
#endregion

function Collect-InboundExternalServicePrincipals {
    param(
        [Parameter(Mandatory)][string]$TenantOrgId,
        $GraphRoleMap,
        [switch]$IncludeMicrosoft,
        [switch]$CollectSignIns,
        [int]$SignInLookbackDays = 30,
        $ExchangeMap
    )

    Write-AuditMsg 'Collecting inbound enterprise apps (service principals from other tenants)...'
    $select = 'id,appId,displayName,appOwnerOrganizationId,accountEnabled,createdDateTime,servicePrincipalType,preferredSingleSignOnMode,homepage,replyUrls,keyCredentials,passwordCredentials,verifiedPublisher,publisherName,tags,notes,info,applicationTemplateId'
    $sps = ConvertTo-ObjectArray (Get-GraphPaged -Uri ('https://graph.microsoft.com/v1.0/servicePrincipals?$select={0}' -f $select))
    Write-AuditMsg ("  Fetched {0} service principals; scanning for external ones..." -f (Get-ObjectCount $sps))
    if ((Get-ObjectCount $sps) -le 1) {
        Write-AuditMsg '  WARNING: only <=1 service principal returned. Every tenant has many first-party SPs, so this usually means the Graph token is stale/expired or lacks Directory.Read.All. Re-run with -ForceReconnect to get a fresh sign-in.' Warn
    }

    $rows = [System.Collections.Generic.List[object]]::new()
    $i = 0
    foreach ($sp in $sps) {
        $homeTenantId = [string](Get-GraphProp -Object $sp -Name 'appOwnerOrganizationId')
        if ([string]::IsNullOrWhiteSpace($homeTenantId)) { continue }
        if ([string]::Equals($homeTenantId, $TenantOrgId, [StringComparison]::OrdinalIgnoreCase)) { continue }

        $isMs = Test-IsMicrosoftTenantId -OrgId $homeTenantId
        if ($isMs -and -not $IncludeMicrosoft) { continue }

        $i++

        $spId = [string](Get-GraphProp -Object $sp -Name 'id')
        $appId = [string](Get-GraphProp -Object $sp -Name 'appId')
        $name = [string](Get-GraphProp -Object $sp -Name 'displayName')
        Write-AuditMsg ("  [{0}] {1} - collecting permissions, roles, memberships..." -f $i, $name)
        $enabled = Get-GraphProp -Object $sp -Name 'accountEnabled'
        $verified = Get-GraphProp -Object $sp -Name 'verifiedPublisher'
        $verifiedName = [string](Get-GraphProp -Object $verified -Name 'displayName')
        if (-not $verifiedName) { $verifiedName = [string](Get-GraphProp -Object $sp -Name 'publisherName') }

        $creds = Format-CredentialSummary `
            -KeyCredentials (Get-GraphProp -Object $sp -Name 'keyCredentials') `
            -PasswordCredentials (Get-GraphProp -Object $sp -Name 'passwordCredentials')

        $roleSummary = Get-SpAppRoleAssignmentSummary -ServicePrincipalId $spId -GraphRoleMap $GraphRoleMap
        $grantSummary = Get-SpOauth2GrantSummary -ServicePrincipalId $spId -GraphRoleMap $GraphRoleMap
        $dirRoles = Get-SpDirectoryRoleSummary -ServicePrincipalId $spId
        $eligibleRoles = Get-SpEligibleRoleSummary -ServicePrincipalId $spId
        $ownerSummary = Get-SpOwnerSummary -ServicePrincipalId $spId
        $assignedToSummary = Get-SpAppRoleAssignedToSummary -ServicePrincipalId $spId -GraphRoleMap $GraphRoleMap
        $groupSummary = Get-SpGroupMembershipSummary -ServicePrincipalId $spId
        $ownedSummary = Get-SpOwnedObjectsSummary -ServicePrincipalId $spId
        $signInSummary = if ($CollectSignIns) {
            Write-AuditMsg ("      querying sign-in logs ({0}d; interactive/non-interactive/SP/MI)..." -f $SignInLookbackDays)
            Get-SpSignInSummary -AppId $appId -LookbackDays $SignInLookbackDays
        }
        else {
            [PSCustomObject]@{
                SignInCount = -1; LastSignIn = ''; Details = ''
                InteractiveUserCount = -1; NonInteractiveUserCount = -1
                ServicePrincipalCount = -1; ManagedIdentityCount = -1
                Records = @()
            }
        }
        # Accumulate per-sign-in detail records (tagged with this SP) for the report's sign-in section.
        if ($signInSummary.PSObject.Properties['Records']) {
            foreach ($rec in (ConvertTo-ObjectArray $signInSummary.Records)) {
                if (-not (Test-IsGraphRowObject $rec)) { continue }
                [void]$Script:SignInDetailRecords.Add([PSCustomObject][ordered]@{
                        ServicePrincipal = $name
                        AppId            = $appId
                        Time             = [string](Get-GraphProp -Object $rec -Name 'Time')
                        Identity         = [string](Get-GraphProp -Object $rec -Name 'Identity')
                        EventType        = [string](Get-GraphProp -Object $rec -Name 'EventType')
                        IpAddress        = [string](Get-GraphProp -Object $rec -Name 'IpAddress')
                        Location         = [string](Get-GraphProp -Object $rec -Name 'Location')
                        Status           = [string](Get-GraphProp -Object $rec -Name 'Status')
                        StatusOk         = [bool](Get-GraphProp -Object $rec -Name 'StatusOk')
                        Resource         = [string](Get-GraphProp -Object $rec -Name 'Resource')
                        ClientApp        = [string](Get-GraphProp -Object $rec -Name 'ClientApp')
                    })
            }
        }
        $exchangeAccess = ''
        if ($ExchangeMap -and $appId -and $ExchangeMap.ContainsKey($appId.ToLowerInvariant())) {
            $exchangeAccess = [string]$ExchangeMap[$appId.ToLowerInvariant()]
        }

        $templateId = [string](Get-GraphProp -Object $sp -Name 'applicationTemplateId')
        $gallery = Get-AppGalleryStatus -TemplateId $templateId

        $replyUrls = @((Get-GraphProp -Object $sp -Name 'replyUrls') | Where-Object { $_ })
        $redirectFlags = [System.Collections.Generic.List[string]]::new()
        foreach ($u in $replyUrls) {
            if ($u -match '(?i)^http:') { [void]$redirectFlags.Add('HttpRedirectUri') }
            if ($u -match '(?i)\*') { [void]$redirectFlags.Add('WildcardRedirectUri') }
        }

        $risk = [System.Collections.Generic.List[string]]::new()
        [void]$risk.Add('ExternalHomeTenant')
        if ($isMs) { [void]$risk.Add('MicrosoftFirstParty') } else { [void]$risk.Add('ThirdPartyPublisher') }
        $assignmentCount = [int]$roleSummary.AssignmentCount
        $grantCount = [int]$grantSummary.GrantCount
        $adminGrantCount = [int]$grantSummary.AdminGrantCount
        $userGrantCount = [int]$grantSummary.UserGrantCount
        $highRiskTotal = [int]$roleSummary.HighRiskCount + [int]$grantSummary.HighRiskCount
        if ($roleSummary.HighRiskCount -gt 0) { [void]$risk.Add('HighRiskAppRoleAssignments') }
        if ($grantSummary.HighRiskCount -gt 0) { [void]$risk.Add('HighRiskDelegatedScopes') }
        if ($assignmentCount -gt 0) { [void]$risk.Add('HasApplicationPermissions') }
        if ($grantCount -gt 0) { [void]$risk.Add('HasDelegatedGrants') }
        if ($adminGrantCount -gt 0) { [void]$risk.Add('HasAdminConsentDelegated') }
        if ($userGrantCount -gt 0) { [void]$risk.Add('HasUserConsentDelegated') }
        if ($dirRoles.RoleCount -gt 0) { [void]$risk.Add('HasDirectoryRoles') }
        if ($eligibleRoles.RoleCount -gt 0) { [void]$risk.Add('HasEligibleDirectoryRoles') }
        if ($ownerSummary.OwnerCount -eq 0) { [void]$risk.Add('NoOwners') }
        if ($assignedToSummary.AssignmentCount -gt 0) { [void]$risk.Add('HasUserGroupAssignments') }
        if ($groupSummary.GroupCount -gt 0) { [void]$risk.Add('MemberOfGroups') }
        if ($groupSummary.RoleAssignableCount -gt 0) { [void]$risk.Add('MemberOfRoleAssignableGroup') }
        if ($ownedSummary.OwnedCount -gt 0) { [void]$risk.Add('OwnsDirectoryObjects') }
        if ($exchangeAccess) { [void]$risk.Add('HasExchangeAppRbac') }
        if ($enabled -eq $false) { [void]$risk.Add('DisabledButPresent') }
        if ([string]::IsNullOrWhiteSpace($verifiedName) -and -not $isMs) { [void]$risk.Add('UnverifiedPublisher') }
        if ($creds.SecretCount -gt 0 -or $creds.CertCount -gt 0) { [void]$risk.Add('LocalCredentialsOnSp') }
        if (-not $isMs -and -not $gallery.InGallery) { [void]$risk.Add('NonGalleryApp') }
        foreach ($f in @($redirectFlags | Select-Object -Unique)) { [void]$risk.Add($f) }

        $severity = 'Low'
        if (-not $isMs -and ($highRiskTotal -gt 0 -or $dirRoles.RoleCount -gt 0 -or $eligibleRoles.RoleCount -gt 0 -or $groupSummary.RoleAssignableCount -gt 0)) {
            $severity = 'High'
        }
        elseif (-not $isMs -and ($assignmentCount -gt 0 -or $adminGrantCount -gt 0 -or $userGrantCount -gt 0 -or $ownedSummary.OwnedCount -gt 0 -or $exchangeAccess)) {
            $severity = 'Medium'
        }
        elseif ($isMs -and $highRiskTotal -gt 0) {
            $severity = 'Medium'
        }

        $highRiskCombined = @(
            @($roleSummary.HighRisk -split ';' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
            @($grantSummary.HighRisk -split ';' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
        ) | Select-Object -Unique

        # Application permissions (app roles) always require admin consent.
        $adminConsentPermissions = @(
            @($roleSummary.Details -split ';' | ForEach-Object { $_.Trim() } | Where-Object { $_ } | ForEach-Object { "Application(AdminConsent): $_" })
            @($grantSummary.AdminConsentDetails -split '\|\|' | ForEach-Object { $_.Trim() } | Where-Object { $_ } | ForEach-Object { "Delegated(AdminConsent): $_" })
        )
        $userConsentPermissions = @(
            @($grantSummary.UserConsentDetails -split '\|\|' | ForEach-Object { $_.Trim() } | Where-Object { $_ } | ForEach-Object { "Delegated(UserConsent): $_" })
        )
        $permissionsCombined = @($adminConsentPermissions + $userConsentPermissions)

        $rows.Add([PSCustomObject][ordered]@{
                Direction                      = 'Inbound'
                ObjectType                     = 'ServicePrincipal'
                AppId                          = $appId
                ObjectId                       = $spId
                DisplayName                    = $name
                SignInAudience                 = ''
                HomeTenantId                   = $homeTenantId
                PublisherDomain                = ''
                VerifiedPublisher              = $verifiedName
                Homepage                       = [string](Get-GraphProp -Object $sp -Name 'homepage')
                CreatedDateTime                = [string](Get-GraphProp -Object $sp -Name 'createdDateTime')
                OwnerCount                     = $(if ($ownerSummary.OwnerCount -ge 0) { $ownerSummary.OwnerCount } else { '' })
                Owners                         = $ownerSummary.Details
                AssignedPrincipals             = $assignedToSummary.Details
                AssignedPrincipalCount         = $(if ($assignedToSummary.AssignmentCount -ge 0) { $assignedToSummary.AssignmentCount } else { '' })
                CertCount                      = $creds.CertCount
                SecretCount                    = $creds.SecretCount
                ExpiredCredentialCount         = $creds.ExpiredCount
                Expiring30DayCount             = $creds.Expiring30Count
                RedirectUriCount               = (Get-ObjectCount $replyUrls)
                RedirectUris                   = ($replyUrls -join '; ')
                PermissionCount                = $(if ($assignmentCount -ge 0 -and $grantSummary.ScopeCount -ge 0) { $assignmentCount + $grantSummary.ScopeCount } elseif ($assignmentCount -ge 0) { $assignmentCount } else { '' })
                ApplicationRoleCount           = $(if ($assignmentCount -ge 0) { $assignmentCount } else { '' })
                DelegatedScopeCount            = $(if ($grantSummary.ScopeCount -ge 0) { $grantSummary.ScopeCount } else { '' })
                AdminConsentGrantCount         = $(if ($adminGrantCount -ge 0) { $adminGrantCount } else { '' })
                UserConsentGrantCount          = $(if ($userGrantCount -ge 0) { $userGrantCount } else { '' })
                AdminConsentScopeCount         = $(if ($grantSummary.AdminScopeCount -ge 0) { $grantSummary.AdminScopeCount } else { '' })
                UserConsentScopeCount          = $(if ($grantSummary.UserScopeCount -ge 0) { $grantSummary.UserScopeCount } else { '' })
                HighRiskPermissionCount        = $highRiskTotal
                HighRiskPermissions            = ($highRiskCombined -join '; ')
                ApplicationPermissions         = $roleSummary.Details
                DelegatedPermissions           = $grantSummary.Details
                AdminConsentPermissions        = ($adminConsentPermissions -join ' || ')
                UserConsentPermissions         = ($userConsentPermissions -join ' || ')
                AdminConsentDelegatedPermissions = $grantSummary.AdminConsentDetails
                UserConsentDelegatedPermissions  = $grantSummary.UserConsentDetails
                AdminConsentDelegatedScopes    = $grantSummary.AdminConsentScopes
                UserConsentDelegatedScopes     = $grantSummary.UserConsentScopes
                DirectoryRoles                 = $dirRoles.Details
                DirectoryRoleCount             = $(if ($dirRoles.RoleCount -ge 0) { $dirRoles.RoleCount } else { '' })
                EligibleDirectoryRoles         = $eligibleRoles.Details
                EligibleDirectoryRoleCount     = $(if ($eligibleRoles.RoleCount -ge 0) { $eligibleRoles.RoleCount } else { '' })
                GroupMemberships               = $groupSummary.Details
                GroupMembershipCount           = $(if ($groupSummary.GroupCount -ge 0) { $groupSummary.GroupCount } else { '' })
                OwnedObjects                   = $ownedSummary.Details
                OwnedObjectCount               = $(if ($ownedSummary.OwnedCount -ge 0) { $ownedSummary.OwnedCount } else { '' })
                AppGalleryListed               = $gallery.Status
                InAppGallery                   = $gallery.InGallery
                ApplicationTemplateId          = $gallery.TemplateId
                GalleryTemplateName            = $gallery.TemplateName
                ExchangeAppAccess              = $exchangeAccess
                SignInCount                    = $(if ($signInSummary.SignInCount -ge 0) { $signInSummary.SignInCount } else { '' })
                InteractiveUserSignIns         = $(if ($signInSummary.InteractiveUserCount -ge 0) { $signInSummary.InteractiveUserCount } else { '' })
                NonInteractiveUserSignIns      = $(if ($signInSummary.NonInteractiveUserCount -ge 0) { $signInSummary.NonInteractiveUserCount } else { '' })
                ServicePrincipalSignIns        = $(if ($signInSummary.ServicePrincipalCount -ge 0) { $signInSummary.ServicePrincipalCount } else { '' })
                ManagedIdentitySignIns         = $(if ($signInSummary.ManagedIdentityCount -ge 0) { $signInSummary.ManagedIdentityCount } else { '' })
                LastSignIn                     = $signInSummary.LastSignIn
                SignInResources                = $signInSummary.Details
                FederatedCredentials           = ''
                FederatedCredentialCount       = ''
                Permissions                    = ($permissionsCombined -join ' || ')
                AccountEnabled                 = $enabled
                AppRoleAssignmentCount         = $(if ($assignmentCount -ge 0) { $assignmentCount } else { '' })
                Oauth2GrantCount               = $(if ($grantCount -ge 0) { $grantCount } else { '' })
                RiskFlags                      = ($risk -join ',')
                Severity                       = $severity
                SecurityNotes                  = (
                    @(
                        'Service principal home tenant differs from this tenant (external / multi-tenant consent).'
                        if (-not $isMs -and $roleSummary.HighRiskCount -gt 0) { 'Third-party app holds privileged application permissions in THIS tenant — review and remove if unused.' }
                        if ($adminGrantCount -gt 0) { 'Has admin-consented delegated permissions (consentType=AllPrincipals) — see AdminConsentDelegatedPermissions.' }
                        if ($userGrantCount -gt 0) { 'Has user-consented delegated permissions (consentType=Principal) — see UserConsentDelegatedPermissions.' }
                        if ($assignmentCount -gt 0) { 'Has application permissions (admin-consent app roles) — see ApplicationPermissions / AdminConsentPermissions.' }
                        if ($dirRoles.RoleCount -gt 0) { 'Assigned Entra directory role(s) — see DirectoryRoles.' }
                        if ($eligibleRoles.RoleCount -gt 0) { 'PIM-eligible directory role(s) — can be activated on demand; see EligibleDirectoryRoles.' }
                        if ($groupSummary.RoleAssignableCount -gt 0) { 'Member of a role-assignable group — indirect path to privileged roles.' }
                        elseif ($groupSummary.GroupCount -gt 0) { 'Member of security group(s) — may inherit app/site access; see GroupMemberships.' }
                        if ($ownedSummary.OwnedCount -gt 0) { 'Owns directory object(s) — can modify/credential them; see OwnedObjects.' }
                        if ($exchangeAccess) { 'Has Exchange Online application RBAC/access policy — see ExchangeAppAccess.' }
                        if ($ownerSummary.OwnerCount -eq 0) { 'No owners on this enterprise app — assign an accountable admin.' }
                        if ($assignedToSummary.AssignmentCount -gt 0) { 'Users/groups are assigned to this app — see AssignedPrincipals.' }
                        if ($signInSummary.SignInCount -eq 0) { 'No app sign-ins in the lookback window — candidate for removal if unused.' }
                        if (-not $isMs -and -not $gallery.InGallery) { 'Not listed in the Microsoft Entra App Gallery (custom/non-gallery app) — verify it is expected and legitimate.' }
                        if ($enabled -eq $false) { 'Account disabled but object remains — confirm grants are revoked.' }
                        if ($isMs) { 'Microsoft first-party application (filtered in by -IncludeMicrosoftFirstParty).' }
                    ) -join ' '
                )
            })
    }

    Write-AuditMsg ("  Inbound external service principals: {0}" -f $rows.Count) Ok
    return , $rows.ToArray()
}

# Shared EXO query logic. Assumes a live Exchange Online connection in the current
# runspace. Emits a single hashtable (appId -> access description). Used both in the main
# runspace (pre-connected) and inside the timed background runspace (fresh connect).
$Script:ExchangeQueryScript = {
    $map = @{}
    $addTo = {
        param([string]$AppId, [string]$Text)
        if ([string]::IsNullOrWhiteSpace($AppId) -or [string]::IsNullOrWhiteSpace($Text)) { return }
        $key = $AppId.ToLowerInvariant()
        if ($map.ContainsKey($key)) { $map[$key] = ($map[$key] + '; ' + $Text) }
        else { $map[$key] = $Text }
    }

    try {
        $exoSps = @(Get-ServicePrincipal -ErrorAction Stop)
        foreach ($esp in $exoSps) {
            $appId = [string]$esp.AppId
            if (-not $appId) { continue }
            try {
                $assignments = @(Get-ManagementRoleAssignment -RoleAssignee $esp.Identity -ErrorAction Stop)
                $roles = @($assignments | ForEach-Object { [string]$_.Role } | Where-Object { $_ } | Select-Object -Unique)
                if ($roles.Count -gt 0) { & $addTo $appId ('EXO RBAC roles: ' + ($roles -join ', ')) }
            }
            catch { }
        }
    }
    catch { }

    try {
        $policies = @(Get-ApplicationAccessPolicy -ErrorAction Stop)
        foreach ($p in $policies) {
            & $addTo ([string]$p.AppId) ('AppAccessPolicy: {0} scope={1}' -f [string]$p.AccessRight, [string]$p.ScopeName)
        }
    }
    catch { }

    , $map
}

function Get-ExchangeAppAccessMap {
    <#
        Builds a map of appId -> Exchange Online application access description by combining
        RBAC-for-Applications management-role assignments and Application Access Policies.

        If no EXO session exists, the connect + queries run inside a background runspace with
        a hard timeout so an interactive sign-in that never surfaces (common in Cursor / VS
        Code terminals) cannot hang the whole audit. Returns an empty map on any failure.
    #>
    param(
        [Parameter(Mandatory)][string]$TargetTenant,
        [int]$ConnectTimeoutSeconds = 90
    )

    $map = @{}
    if (-not (Get-Module -ListAvailable -Name 'ExchangeOnlineManagement')) {
        Write-AuditMsg '  -IncludeExchange set but ExchangeOnlineManagement module is not installed; skipping EXO checks.' Warn
        return $map
    }

    try {
        Import-Module ExchangeOnlineManagement -ErrorAction Stop
    }
    catch {
        Write-AuditMsg ("  Could not import ExchangeOnlineManagement; skipping EXO checks: {0}" -f $_.Exception.Message) Warn
        return $map
    }

    $connected = $false
    try {
        if (Get-ConnectionInformation -ErrorAction SilentlyContinue) { $connected = $true }
    }
    catch { }

    # Fast path: an existing session (e.g. user ran Connect-ExchangeOnline first) — query here.
    if ($connected) {
        Write-AuditMsg '  Reusing existing Exchange Online connection.' Info
        try {
            $result = & $Script:ExchangeQueryScript
            if ($result -is [hashtable]) { $map = $result }
        }
        catch {
            Write-AuditMsg ("  EXO query failed: {0}" -f $_.Exception.Message) Warn
        }
        Write-AuditMsg ("  Exchange app-access entries mapped: {0}" -f $map.Count) Ok
        return $map
    }

    # No session: connect + query inside a background runspace we can abandon on timeout.
    # (EXO cmdlets register per-runspace, so the connect and queries must share one runspace.)
    $useDevice = [bool]$DeviceCode -or ($env:TERM_PROGRAM -match '(?i)vscode|cursor') -or [bool]$env:CURSOR_TRACE_ID
    Write-AuditMsg ("  Connecting to Exchange Online (auto-skips after {0}s{1})..." -f $ConnectTimeoutSeconds, $(if ($useDevice) { '; device code' } else { '' })) Info

    $worker = @'
param($TargetTenant, $UseDevice, $QueryText)
Import-Module ExchangeOnlineManagement -ErrorAction Stop
$p = @{ ShowBanner = $false; ErrorAction = 'Stop' }
if ($TargetTenant) { $p['Organization'] = $TargetTenant }
$keys = @((Get-Command Connect-ExchangeOnline -ErrorAction Stop).Parameters.Keys)
if ($UseDevice -and ($keys -contains 'Device')) { $p['Device'] = $true }
Connect-ExchangeOnline @p | Out-Null
$sb = [scriptblock]::Create($QueryText)
& $sb
try { Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue | Out-Null } catch { }
'@

    $ps = [PowerShell]::Create()
    [void]$ps.AddScript($worker).AddArgument($TargetTenant).AddArgument([bool]$useDevice).AddArgument($Script:ExchangeQueryScript.ToString())
    $async = $ps.BeginInvoke()
    $completed = $async.AsyncWaitHandle.WaitOne([TimeSpan]::FromSeconds([Math]::Max(10, $ConnectTimeoutSeconds)))

    if (-not $completed) {
        Write-AuditMsg ("  Exchange sign-in did not complete within {0}s; skipping EXO checks. Tip: run Connect-ExchangeOnline in an external window first, then re-run the audit (it reuses the session)." -f $ConnectTimeoutSeconds) Warn
        try { [void]$ps.Stop() } catch { }
        try { $ps.Dispose() } catch { }
        return $map
    }

    try {
        $out = $ps.EndInvoke($async)
        foreach ($o in @($out)) {
            if ($null -eq $o) { continue }
            # .psobject is an intrinsic member on every object, so this is StrictMode-safe
            # and unwraps PSObject-wrapped results back to the underlying hashtable.
            $candidate = $o.psobject.BaseObject
            if ($candidate -is [hashtable]) { $map = $candidate; break }
        }
        if ($ps.HadErrors -and $ps.Streams.Error.Count -gt 0) {
            Write-AuditMsg ("  Exchange checks reported: {0}" -f $ps.Streams.Error[0].ToString()) Warn
        }
    }
    catch {
        Write-AuditMsg ("  Exchange Online connection/query failed; skipping EXO checks: {0}" -f $_.Exception.Message) Warn
    }
    finally {
        try { $ps.Dispose() } catch { }
    }

    Write-AuditMsg ("  Exchange app-access entries mapped: {0}" -f $map.Count) Ok
    return $map
}

function Export-AuditCsv {
    param([object[]]$Rows, [string]$Path)
    if ((Get-ObjectCount $Rows) -eq 0) {
        [PSCustomObject]@{ Notice = 'No rows' } | Export-Csv -Path $Path -NoTypeInformation -Encoding UTF8
        return
    }
    @($Rows) | Export-Csv -Path $Path -NoTypeInformation -Encoding UTF8
}

function New-HtmlReport {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)]$Org,
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$AllRows,
        [Parameter(Mandatory)][string]$RunFolder,
        [hashtable]$Meta,
        [AllowEmptyCollection()][object[]]$SignInRecords = @(),
        [AllowEmptyCollection()][object[]]$IpIntel = @()
    )

    $outbound = @($AllRows | Where-Object { $_.Direction -eq 'Outbound' })
    $inbound = @($AllRows | Where-Object { $_.Direction -eq 'Inbound' })
    $high = @($AllRows | Where-Object { $_.Severity -eq 'High' })
    $medium = @($AllRows | Where-Object { $_.Severity -eq 'Medium' })
    $low = @($AllRows | Where-Object { $_.Severity -eq 'Low' })

    function Esc([string]$t) {
        if ($null -eq $t) { return '' }
        return [System.Net.WebUtility]::HtmlEncode($t)
    }

    # Render a possibly-long, delimited value as a collapsible list; '—' when empty.
    # Within an item, ' | ' field separators are rendered as line breaks for readability.
    function Format-CollapsibleCell {
        param([string]$Value, [string]$Delimiter = ';')
        if ([string]::IsNullOrWhiteSpace($Value)) { return '<span class="muted">&mdash;</span>' }
        $parts = @($Value -split [regex]::Escape($Delimiter) | ForEach-Object { $_.Trim() } | Where-Object { $_ })
        if ($parts.Count -le 1) { return ('<span>{0}</span>' -f ((Esc ($parts -join '')) -replace ' \| ', '<br/>')) }
        $items = ($parts | ForEach-Object { '<li>{0}</li>' -f ((Esc $_) -replace ' \| ', '<br/>') }) -join ''
        return ('<details><summary>{0} items</summary><ul class="cell-list">{1}</ul></details>' -f $parts.Count, $items)
    }

    function Format-RiskPills {
        param([string]$Flags)
        if ([string]::IsNullOrWhiteSpace($Flags)) { return '<span class="muted">&mdash;</span>' }
        $sb2 = [System.Text.StringBuilder]::new()
        foreach ($f in @($Flags -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })) {
            $hot = if ($f -match '(?i)HighRisk|RoleAssignable|DirectoryRoles|Eligible|OwnsDirectory|FederatedIdentity|NoOwners') { ' pill-hot' } else { '' }
            [void]$sb2.Append(('<span class="pill{0}">{1}</span>' -f $hot, (Esc $f)))
        }
        return $sb2.ToString()
    }

    function Get-SevBadge {
        param([string]$Severity)
        $cls = switch ($Severity) { 'High' { 'sev-high' } 'Medium' { 'sev-med' } default { 'sev-low' } }
        return ('<span class="badge {0}">{1}</span>' -f $cls, (Esc $Severity))
    }

    $css = @'
<style>
:root{--bg:#f5f6f8;--card:#fff;--ink:#1b1f24;--muted:#6b7280;--line:#e3e6ea;--brand:#2b579a;--high:#c62828;--med:#b26a00;--low:#2e7d32}
*{box-sizing:border-box}
body{font-family:'Segoe UI',Roboto,Arial,sans-serif;margin:0;background:var(--bg);color:var(--ink);font-size:14px;line-height:1.45}
.wrap{max-width:1500px;margin:0 auto;padding:24px}
header.top{background:linear-gradient(135deg,#2b579a,#1e3c6e);color:#fff;padding:24px 28px;border-radius:14px;box-shadow:0 6px 20px rgba(30,60,110,.25)}
header.top h1{margin:0 0 6px;font-size:22px}
header.top .meta{opacity:.9;font-size:13px}
header.top code{background:rgba(255,255,255,.18);padding:1px 6px;border-radius:5px;color:#fff}
.cards{display:flex;flex-wrap:wrap;gap:14px;margin:22px 0}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:16px 18px;min-width:150px;flex:1;box-shadow:0 1px 3px rgba(0,0,0,.05)}
.card .n{font-size:30px;font-weight:700;line-height:1}
.card .l{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.04em;margin-top:6px}
.card.high .n{color:var(--high)}.card.med .n{color:var(--med)}.card.low .n{color:var(--low)}
.legend{display:flex;gap:16px;flex-wrap:wrap;margin:0 0 14px;color:var(--muted);font-size:12px}
.badge{display:inline-block;padding:2px 9px;border-radius:20px;font-size:12px;font-weight:600;color:#fff}
.sev-high{background:var(--high)}.sev-med{background:var(--med)}.sev-low{background:var(--low)}
.controls{display:flex;gap:10px;flex-wrap:wrap;align-items:center;margin:16px 0}
.controls input,.controls select{padding:8px 10px;border:1px solid var(--line);border-radius:8px;font-size:13px;background:#fff}
.controls input[type=search]{min-width:280px}
section{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:6px 0;margin:18px 0;overflow:hidden}
section h2{font-size:16px;margin:14px 18px}
.tbl-scroll{overflow-x:auto}
table{border-collapse:collapse;width:100%;font-size:13px}
thead th{position:sticky;top:0;background:#eef1f5;text-align:left;padding:10px 12px;border-bottom:2px solid var(--line);cursor:pointer;white-space:nowrap;z-index:1}
thead th:hover{background:#e3e8ef}
tbody td{padding:9px 12px;border-bottom:1px solid var(--line);vertical-align:top}
tbody tr:hover{background:#f8fafc}
tr.row-high{box-shadow:inset 4px 0 0 var(--high)}
tr.row-med{box-shadow:inset 4px 0 0 var(--med)}
tr.row-low{box-shadow:inset 4px 0 0 var(--low)}
code{font-family:Consolas,Menlo,monospace;font-size:12px;background:#f1f3f5;padding:1px 5px;border-radius:4px}
.muted{color:var(--muted)}
.pill{display:inline-block;background:#eef1f5;color:#374151;border:1px solid var(--line);border-radius:20px;padding:1px 8px;margin:2px 3px 2px 0;font-size:11px;white-space:nowrap}
.pill-hot{background:#fdecec;color:#a01818;border-color:#f3c2c2}
details summary{cursor:pointer;color:var(--brand);font-size:12px}
ul.cell-list{margin:6px 0 0;padding-left:18px}
ul.cell-list li{margin:2px 0}
.notes{max-width:360px}
footer{color:var(--muted);font-size:12px;margin:24px 0 8px;text-align:center}
</style>
'@

    $js = @'
<script>
function auditFilter(sectionId){
  var sec=document.getElementById(sectionId);
  var searchEl=sec.querySelector('.f-search');
  var q=((searchEl&&searchEl.value)||'').toLowerCase();
  var sevEl=sec.querySelector('.f-sev');
  var sev=sevEl?sevEl.value:'';
  var rows=sec.querySelectorAll('tbody tr');
  var shown=0;
  rows.forEach(function(r){
    var okText=!q||r.innerText.toLowerCase().indexOf(q)>-1;
    var okSev=!sev||r.getAttribute('data-sev')===sev;
    var vis=okText&&okSev;r.style.display=vis?'':'none';if(vis)shown++;
  });
  var c=sec.querySelector('.f-count');if(c)c.textContent=shown+' shown';
}
function auditSort(th){
  var table=th.closest('table');var idx=Array.prototype.indexOf.call(th.parentNode.children,th);
  var tbody=table.querySelector('tbody');var rows=Array.prototype.slice.call(tbody.querySelectorAll('tr'));
  var asc=th.getAttribute('data-asc')!=='1';th.setAttribute('data-asc',asc?'1':'0');
  rows.sort(function(a,b){
    var x=(a.children[idx]?a.children[idx].innerText:'').trim().toLowerCase();
    var y=(b.children[idx]?b.children[idx].innerText:'').trim().toLowerCase();
    var nx=parseFloat(x),ny=parseFloat(y);
    if(!isNaN(nx)&&!isNaN(ny)){return asc?nx-ny:ny-nx;}
    return asc?x.localeCompare(y):y.localeCompare(x);
  });
  rows.forEach(function(r){tbody.appendChild(r);});
}
</script>
'@

    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.AppendLine('<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/><title>Multi-tenant application audit</title>')
    [void]$sb.AppendLine($css)
    [void]$sb.AppendLine('</head><body><div class="wrap">')

    $scopeNote = if ($Meta -and $Meta.ContainsKey('ScopeNote')) { [string]$Meta.ScopeNote } else { '' }
    $lookback = if ($Meta -and $Meta.ContainsKey('SignInLookbackDays')) { [string]$Meta.SignInLookbackDays } else { '30' }
    [void]$sb.AppendLine('<header class="top">')
    [void]$sb.AppendLine('<h1>Multi-tenant / cross-tenant application audit</h1>')
    [void]$sb.AppendLine(('<div class="meta">Tenant <strong>{0}</strong> &nbsp;|&nbsp; <code>{1}</code><br/>Generated {2:u} &nbsp;|&nbsp; Sign-in lookback: {3} days</div>' -f (Esc $Org.DisplayName), (Esc $Org.Id), [DateTime]::UtcNow, (Esc $lookback)))
    if ($scopeNote) { [void]$sb.AppendLine(('<div class="meta">{0}</div>' -f (Esc $scopeNote))) }
    [void]$sb.AppendLine('</header>')

    # Dashboard cards
    [void]$sb.AppendLine('<div class="cards">')
    [void]$sb.AppendLine(('<div class="card high"><div class="n">{0}</div><div class="l">High severity</div></div>' -f (Get-ObjectCount $high)))
    [void]$sb.AppendLine(('<div class="card med"><div class="n">{0}</div><div class="l">Medium severity</div></div>' -f (Get-ObjectCount $medium)))
    [void]$sb.AppendLine(('<div class="card low"><div class="n">{0}</div><div class="l">Low severity</div></div>' -f (Get-ObjectCount $low)))
    [void]$sb.AppendLine(('<div class="card"><div class="n">{0}</div><div class="l">Inbound enterprise apps</div></div>' -f (Get-ObjectCount $inbound)))
    [void]$sb.AppendLine(('<div class="card"><div class="n">{0}</div><div class="l">Outbound app registrations</div></div>' -f (Get-ObjectCount $outbound)))
    [void]$sb.AppendLine(('<div class="card"><div class="n">{0}</div><div class="l">Sign-in events captured</div></div>' -f (Get-ObjectCount $SignInRecords)))
    [void]$sb.AppendLine(('<div class="card"><div class="n">{0}</div><div class="l">Unique source IPs</div></div>' -f (Get-ObjectCount $IpIntel)))
    [void]$sb.AppendLine('</div>')

    [void]$sb.AppendLine('<div class="legend"><span><span class="badge sev-high">High</span> privileged app perms / directory roles</span><span><span class="badge sev-med">Medium</span> consented perms / owned objects</span><span><span class="badge sev-low">Low</span> presence only</span></div>')

    $sevOrder = { switch ($_.Severity) { 'High' { 0 } 'Medium' { 1 } default { 2 } } }

    # ---- Inbound section ----
    $inboundSorted = @($inbound | Sort-Object @{ Expression = $sevOrder }, DisplayName)
    [void]$sb.AppendLine('<section id="sec-inbound">')
    [void]$sb.AppendLine('<h2>Inbound service principals &mdash; permissions, roles &amp; administrators</h2>')
    [void]$sb.AppendLine('<div class="controls">')
    [void]$sb.AppendLine('<input type="search" class="f-search" placeholder="Search inbound apps, scopes, owners..." oninput="auditFilter(''sec-inbound'')"/>')
    [void]$sb.AppendLine('<select class="f-sev" onchange="auditFilter(''sec-inbound'')"><option value="">All severities</option><option>High</option><option>Medium</option><option>Low</option></select>')
    [void]$sb.AppendLine('<span class="f-count muted"></span>')
    [void]$sb.AppendLine('</div><div class="tbl-scroll"><table>')
    [void]$sb.AppendLine('<thead><tr><th onclick="auditSort(this)">Severity</th><th onclick="auditSort(this)">DisplayName</th><th onclick="auditSort(this)">AppId</th><th onclick="auditSort(this)">Homepage</th><th onclick="auditSort(this)">Home tenant</th><th onclick="auditSort(this)">Enabled</th><th onclick="auditSort(this)">App Gallery</th><th onclick="auditSort(this)">Risk flags</th><th onclick="auditSort(this)">Admin-consent permissions</th><th onclick="auditSort(this)">User-consent permissions</th><th onclick="auditSort(this)">Directory roles</th><th onclick="auditSort(this)">Eligible (PIM) roles</th><th onclick="auditSort(this)">Group memberships</th><th onclick="auditSort(this)">Owned objects</th><th onclick="auditSort(this)">Owners / admins</th><th onclick="auditSort(this)">Assigned users/groups</th><th onclick="auditSort(this)">Exchange access</th><th onclick="auditSort(this)">Sign-ins (total; int/non-int/SP/MI)</th><th onclick="auditSort(this)">Notes</th></tr></thead><tbody>')
    if ($inboundSorted.Count -eq 0) {
        [void]$sb.AppendLine('<tr><td colspan="19" class="muted">No inbound external service principals in this run.</td></tr>')
    }
    else {
        foreach ($r in $inboundSorted) {
            $rowcls = switch ($r.Severity) { 'High' { 'row-high' } 'Medium' { 'row-med' } default { 'row-low' } }
            $fmtT = { param($v) if ([string]::IsNullOrWhiteSpace([string]$v)) { '-' } else { [string]$v } }
            $breakdown = ('<span class="muted" style="font-size:11px">int {0} &middot; non-int {1} &middot; SP {2} &middot; MI {3}</span>' -f `
                (Esc (& $fmtT $r.InteractiveUserSignIns)), (Esc (& $fmtT $r.NonInteractiveUserSignIns)), (Esc (& $fmtT $r.ServicePrincipalSignIns)), (Esc (& $fmtT $r.ManagedIdentitySignIns)))
            $signInText = if ([string]::IsNullOrWhiteSpace([string]$r.SignInCount)) {
                '<span class="muted">n/a</span>'
            }
            elseif ([int]$r.SignInCount -eq 0) {
                '<span class="pill pill-hot">0</span><br/>' + $breakdown
            }
            else {
                ('<strong>{0}</strong><br/>{1}<br/><span class="muted">{2}</span>' -f (Esc $r.SignInCount), $breakdown, (Esc $r.LastSignIn))
            }
            $homepageCell = if ([string]::IsNullOrWhiteSpace([string]$r.Homepage)) {
                '<span class="muted">&mdash;</span>'
            }
            else {
                ('<a href="{0}" target="_blank" rel="noopener">{1}</a>' -f (Esc $r.Homepage), (Esc $r.Homepage))
            }
            $enabledCell = if ($r.AccountEnabled -eq $true) {
                '<span class="pill" style="background:#e6f4ea;color:#1e7e34;border-color:#bfe3c9">Enabled</span>'
            }
            elseif ($r.AccountEnabled -eq $false) {
                '<span class="pill pill-hot">Disabled</span>'
            }
            else {
                '<span class="muted">unknown</span>'
            }
            $galleryCell = if ($r.InAppGallery -eq $true) {
                $gname = if ([string]::IsNullOrWhiteSpace([string]$r.GalleryTemplateName)) { 'Gallery' } else { [string]$r.GalleryTemplateName }
                ('<span class="pill" style="background:#e8effb;color:#1f4e9c;border-color:#c4d6f5" title="{0}">Gallery</span>' -f (Esc $gname))
            }
            elseif ([string]$r.AppGalleryListed -match '(?i)custom|non-gallery') {
                ('<span class="pill" style="background:#fff4e5;color:#8a5300;border-color:#f3dcae">{0}</span>' -f (Esc $r.AppGalleryListed))
            }
            else {
                '<span class="muted">&mdash;</span>'
            }
            [void]$sb.AppendLine(('<tr class="{0}" data-sev="{1}"><td>{2}</td><td>{3}</td><td><code>{4}</code></td><td>{5}</td><td><code>{6}</code></td><td>{7}</td><td>{8}</td><td>{9}</td><td>{10}</td><td>{11}</td><td>{12}</td><td>{13}</td><td>{14}</td><td>{15}</td><td>{16}</td><td>{17}</td><td>{18}</td><td>{19}</td><td class="notes">{20}</td></tr>' -f `
                    $rowcls,
                    (Esc $r.Severity),
                    (Get-SevBadge $r.Severity),
                    (Esc $r.DisplayName),
                    (Esc $r.AppId),
                    $homepageCell,
                    (Esc $r.HomeTenantId),
                    $enabledCell,
                    $galleryCell,
                    (Format-RiskPills $r.RiskFlags),
                    (Format-CollapsibleCell $r.AdminConsentPermissions ' || '),
                    (Format-CollapsibleCell $r.UserConsentPermissions ' || '),
                    (Format-CollapsibleCell $r.DirectoryRoles ';'),
                    (Format-CollapsibleCell $r.EligibleDirectoryRoles ';'),
                    (Format-CollapsibleCell $r.GroupMemberships ';'),
                    (Format-CollapsibleCell $r.OwnedObjects ';'),
                    (Format-CollapsibleCell $r.Owners ';'),
                    (Format-CollapsibleCell $r.AssignedPrincipals ';'),
                    (Format-CollapsibleCell $r.ExchangeAppAccess ';'),
                    $signInText,
                    (Esc $r.SecurityNotes)))
        }
    }
    [void]$sb.AppendLine('</tbody></table></div>')
    [void]$sb.AppendLine('<p class="muted" style="margin:10px 18px">Admin consent = application permissions (appRoleAssignments) + delegated grants with consentType=AllPrincipals. User consent = delegated grants with consentType=Principal (per user). Sign-ins = app-only sign-ins in the lookback window (requires Entra ID P1).</p>')
    [void]$sb.AppendLine('</section>')

    # ---- Sign-in activity detail: one section per enterprise application ----
    [void]$sb.AppendLine('<h2 style="margin:26px 4px 4px">Sign-in activity by application</h2>')
    [void]$sb.AppendLine('<p class="muted" style="margin:0 4px 8px">Per-event sign-in logs for each inbound enterprise application (capped per app for performance). Includes interactive, non-interactive, service-principal, and managed-identity sign-ins. Full data is in multitenant-apps-signins.csv.</p>')

    if ((Get-ObjectCount $SignInRecords) -eq 0) {
        [void]$sb.AppendLine('<section id="sec-signins-empty"><p class="muted" style="margin:14px 18px">No sign-in events captured (sign-in collection skipped, unavailable, or no activity in the lookback window).</p></section>')
    }
    else {
        $signInGroups = @($SignInRecords | Group-Object -Property AppId | Sort-Object -Property @{ Expression = { $_.Count }; Descending = $true }, Name)
        $grpIdx = 0
        foreach ($g in $signInGroups) {
            $grpIdx++
            $secId = "sec-signins-$grpIdx"
            $first = $g.Group | Select-Object -First 1
            $appName = [string]$first.ServicePrincipal
            if ([string]::IsNullOrWhiteSpace($appName)) { $appName = '(unnamed application)' }
            $appId = [string]$g.Name

            [void]$sb.AppendLine(('<section id="{0}">' -f $secId))
            [void]$sb.AppendLine(('<h2>{0} &nbsp;<code>{1}</code> &nbsp;<span class="muted" style="font-size:13px;font-weight:400">{2} events</span></h2>' -f (Esc $appName), (Esc $appId), $g.Count))
            [void]$sb.AppendLine('<div class="controls">')
            [void]$sb.AppendLine(('<input type="search" class="f-search" placeholder="Search this app''s sign-ins (user, IP, status, resource)..." oninput="auditFilter(''{0}'')"/>' -f $secId))
            [void]$sb.AppendLine('<span class="f-count muted"></span>')
            [void]$sb.AppendLine('</div><div class="tbl-scroll"><table>')
            [void]$sb.AppendLine('<thead><tr><th onclick="auditSort(this)">Time (UTC)</th><th onclick="auditSort(this)">Identity</th><th onclick="auditSort(this)">Event type</th><th onclick="auditSort(this)">IP address</th><th onclick="auditSort(this)">Location</th><th onclick="auditSort(this)">Status</th><th onclick="auditSort(this)">Resource</th><th onclick="auditSort(this)">Client app</th></tr></thead><tbody>')

            $recordsSorted = @($g.Group | Sort-Object @{ Expression = { $_.Time }; Descending = $true })
            foreach ($r in $recordsSorted) {
                $okBool = $false
                try { $okBool = [bool]$r.StatusOk } catch { $okBool = $false }
                $statusHtml = if ($okBool) {
                    ('<span class="pill" style="background:#e6f4ea;color:#1e7e34;border-color:#bfe3c9">{0}</span>' -f (Esc $r.Status))
                }
                else {
                    ('<span class="pill pill-hot">{0}</span>' -f (Esc $r.Status))
                }
                [void]$sb.AppendLine(('<tr><td>{0}</td><td>{1}</td><td>{2}</td><td><code>{3}</code></td><td>{4}</td><td>{5}</td><td>{6}</td><td>{7}</td></tr>' -f `
                        (Esc $r.Time),
                        (Esc $r.Identity),
                        (Esc $r.EventType),
                        (Esc $r.IpAddress),
                        (Esc $r.Location),
                        $statusHtml,
                        (Esc $r.Resource),
                        (Esc $r.ClientApp)))
            }
            [void]$sb.AppendLine('</tbody></table></div>')
            [void]$sb.AppendLine('</section>')
        }
    }

    # ---- Sign-in source IP intelligence section ----
    $ipSorted = @($IpIntel | Sort-Object @{ Expression = { [int]$_.Events }; Descending = $true }, IpAddress)
    [void]$sb.AppendLine('<section id="sec-ipintel">')
    [void]$sb.AppendLine('<h2>Sign-in source IP intelligence &mdash; RDAP registrant &amp; reverse DNS</h2>')
    [void]$sb.AppendLine('<div class="controls">')
    [void]$sb.AppendLine('<input type="search" class="f-search" placeholder="Search by IP, registrant, host, network, country..." oninput="auditFilter(''sec-ipintel'')"/>')
    [void]$sb.AppendLine('<span class="f-count muted"></span>')
    [void]$sb.AppendLine('</div><div class="tbl-scroll"><table>')
    [void]$sb.AppendLine('<thead><tr><th onclick="auditSort(this)">IP address</th><th onclick="auditSort(this)">Events</th><th onclick="auditSort(this)">Applications</th><th onclick="auditSort(this)">Reverse DNS (PTR)</th><th onclick="auditSort(this)">Registrant / org</th><th onclick="auditSort(this)">Network</th><th onclick="auditSort(this)">CIDR</th><th onclick="auditSort(this)">Country</th><th onclick="auditSort(this)">Last seen (UTC)</th><th onclick="auditSort(this)">Source</th></tr></thead><tbody>')
    if ($ipSorted.Count -eq 0) {
        [void]$sb.AppendLine('<tr><td colspan="10" class="muted">No source IPs to enrich (sign-in collection skipped/unavailable, or IP intelligence skipped with -SkipIpIntelligence).</td></tr>')
    }
    else {
        foreach ($r in $ipSorted) {
            $rdns = if ([string]::IsNullOrWhiteSpace([string]$r.ReverseDns)) { '<span class="muted">&mdash;</span>' } else { (Esc $r.ReverseDns) }
            $reg = if ([string]::IsNullOrWhiteSpace([string]$r.Registrant)) { '<span class="muted">&mdash;</span>' } else { (Esc $r.Registrant) }
            [void]$sb.AppendLine(('<tr><td><code>{0}</code></td><td>{1}</td><td>{2}</td><td>{3}</td><td>{4}</td><td>{5}</td><td><code>{6}</code></td><td>{7}</td><td>{8}</td><td><span class="muted" style="font-size:11px">{9}</span></td></tr>' -f `
                    (Esc $r.IpAddress),
                    (Esc ([string]$r.Events)),
                    (Format-CollapsibleCell ([string]$r.Applications) ';'),
                    $rdns,
                    $reg,
                    (Esc $r.NetworkName),
                    (Esc $r.Cidr),
                    (Esc $r.Country),
                    (Esc $r.LastSeen),
                    (Esc $r.Source)))
        }
    }
    [void]$sb.AppendLine('</tbody></table></div>')
    [void]$sb.AppendLine('<p class="muted" style="margin:10px 18px">Registrant/network/CIDR/country come from RDAP (rdap.org, which routes to the responsible RIR). Reverse DNS is the PTR record for the IP. Private/reserved (non-routable) addresses are flagged and not sent to RDAP. This reflects who owns the IP block, not necessarily the end user.</p>')
    [void]$sb.AppendLine('</section>')

    # ---- Outbound section ----
    $outboundSorted = @($outbound | Sort-Object @{ Expression = $sevOrder }, DisplayName)
    [void]$sb.AppendLine('<section id="sec-outbound">')
    [void]$sb.AppendLine('<h2>Outbound multi-tenant app registrations (owned by this tenant)</h2>')
    [void]$sb.AppendLine('<div class="controls">')
    [void]$sb.AppendLine('<input type="search" class="f-search" placeholder="Search outbound apps..." oninput="auditFilter(''sec-outbound'')"/>')
    [void]$sb.AppendLine('<select class="f-sev" onchange="auditFilter(''sec-outbound'')"><option value="">All severities</option><option>High</option><option>Medium</option><option>Low</option></select>')
    [void]$sb.AppendLine('<span class="f-count muted"></span>')
    [void]$sb.AppendLine('</div><div class="tbl-scroll"><table>')
    [void]$sb.AppendLine('<thead><tr><th onclick="auditSort(this)">Severity</th><th onclick="auditSort(this)">DisplayName</th><th onclick="auditSort(this)">AppId</th><th onclick="auditSort(this)">Sign-in audience</th><th onclick="auditSort(this)">Risk flags</th><th onclick="auditSort(this)">Requested permissions</th><th onclick="auditSort(this)">Federated credentials</th><th onclick="auditSort(this)">Owners</th><th onclick="auditSort(this)">Notes</th></tr></thead><tbody>')
    if ($outboundSorted.Count -eq 0) {
        [void]$sb.AppendLine('<tr><td colspan="9" class="muted">No outbound multi-tenant app registrations in this run.</td></tr>')
    }
    else {
        foreach ($r in $outboundSorted) {
            $rowcls = switch ($r.Severity) { 'High' { 'row-high' } 'Medium' { 'row-med' } default { 'row-low' } }
            [void]$sb.AppendLine(('<tr class="{0}" data-sev="{1}"><td>{2}</td><td>{3}</td><td><code>{4}</code></td><td>{5}</td><td>{6}</td><td>{7}</td><td>{8}</td><td>{9}</td><td class="notes">{10}</td></tr>' -f `
                    $rowcls,
                    (Esc $r.Severity),
                    (Get-SevBadge $r.Severity),
                    (Esc $r.DisplayName),
                    (Esc $r.AppId),
                    (Esc $r.SignInAudience),
                    (Format-RiskPills $r.RiskFlags),
                    (Format-CollapsibleCell $r.Permissions ';'),
                    (Format-CollapsibleCell $r.FederatedCredentials ';'),
                    (Format-CollapsibleCell $r.Owners ';'),
                    (Esc $r.SecurityNotes)))
        }
    }
    [void]$sb.AppendLine('</tbody></table></div>')
    [void]$sb.AppendLine('<p class="muted" style="margin:10px 18px">Outbound permissions are requested (requiredResourceAccess) on the app registration, not grants in consenting tenants.</p>')
    [void]$sb.AppendLine('</section>')

    [void]$sb.AppendLine('<footer>Full inventories (all columns) are in the CSV files alongside this report. Generated by Audit-MultiTenantApps.ps1</footer>')
    [void]$sb.AppendLine('</div>')
    [void]$sb.AppendLine($js)
    [void]$sb.AppendLine('</body></html>')
    [System.IO.File]::WriteAllText($Path, $sb.ToString(), [System.Text.UTF8Encoding]::new($false))
}

#region Main
Write-Host '========================================' -ForegroundColor Cyan
Write-Host 'Multi-tenant / B2B application audit' -ForegroundColor Cyan
Write-Host '========================================' -ForegroundColor Cyan

$resolvedTenantId = Connect-AuditGraph -TargetTenant $TenantId -UseAppOnly:$AppOnly
if ($resolvedTenantId -eq 'RELAUNCHED_EXTERNAL') {
    Write-AuditMsg 'External PowerShell window launched for device login + audit. Continue there; this Cursor run is done.' Ok
    return
}
$org = Get-CurrentOrganization
if ($org.Id) { $resolvedTenantId = $org.Id }
Write-AuditMsg ("Organization: {0} ({1})" -f $org.DisplayName, $resolvedTenantId) Ok

$exchangeMap = $null
if ($IncludeExchange) {
    Write-AuditMsg 'Collecting Exchange Online application RBAC / access policies...'
    $exchangeMap = Get-ExchangeAppAccessMap -TargetTenant $resolvedTenantId -ConnectTimeoutSeconds $ExchangeConnectTimeoutSeconds
}

$collectSignIns = -not $SkipSignInActivity

$graphRoleMap = Get-GraphAppRoleValueMap
$outboundRows = ConvertTo-ObjectArray (Collect-OutboundMultiTenantApps -TenantOrgId $resolvedTenantId -GraphRoleMap $graphRoleMap)
$inboundRows = ConvertTo-ObjectArray (Collect-InboundExternalServicePrincipals -TenantOrgId $resolvedTenantId -GraphRoleMap $graphRoleMap `
        -IncludeMicrosoft:$IncludeMicrosoftFirstParty `
        -CollectSignIns:$collectSignIns -SignInLookbackDays $SignInLookbackDays -ExchangeMap $exchangeMap)

$allRowsList = [System.Collections.Generic.List[object]]::new()
foreach ($r in $outboundRows) { [void]$allRowsList.Add($r) }
foreach ($r in $inboundRows) { [void]$allRowsList.Add($r) }
$allRows = $allRowsList.ToArray()

$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$runFolder = Join-Path $OutputPath ("run-{0}" -f $stamp)
$null = New-Item -ItemType Directory -Path $runFolder -Force

$allCsv = Join-Path $runFolder 'multitenant-apps-all.csv'
$outCsv = Join-Path $runFolder 'multitenant-apps-outbound.csv'
$inCsv = Join-Path $runFolder 'multitenant-apps-inbound.csv'
$signInsCsv = Join-Path $runFolder 'multitenant-apps-signins.csv'
$ipIntelCsv = Join-Path $runFolder 'multitenant-apps-ip-intel.csv'
$html = Join-Path $runFolder 'multitenant-apps-report.html'

$signInRecords = ConvertTo-ObjectArray $Script:SignInDetailRecords

$ipIntel = @()
if (-not $SkipIpIntelligence -and (Get-ObjectCount $signInRecords) -gt 0) {
    $ipIntel = ConvertTo-ObjectArray (Get-SignInIpIntelligence -SignInRecords $signInRecords)
}

Export-AuditCsv -Rows $allRows -Path $allCsv
Export-AuditCsv -Rows $outboundRows -Path $outCsv
Export-AuditCsv -Rows $inboundRows -Path $inCsv
Export-AuditCsv -Rows $signInRecords -Path $signInsCsv
Export-AuditCsv -Rows $ipIntel -Path $ipIntelCsv

$reportMeta = @{
    ScopeNote          = 'Scopes: Application.Read.All, Directory.Read.All, DelegatedPermissionGrant.Read.All, RoleManagement.Read.Directory, AuditLog.Read.All' + $(if ($IncludeExchange) { ' + Exchange Online RBAC' } else { '' })
    SignInLookbackDays = $SignInLookbackDays
}
New-HtmlReport -Path $html -Org $org -AllRows $allRows -RunFolder $runFolder -Meta $reportMeta -SignInRecords $signInRecords -IpIntel $ipIntel

$summary = [PSCustomObject]@{
    TenantId                     = $resolvedTenantId
    TenantDisplayName            = $org.DisplayName
    OutboundMultiTenantAppCount  = (Get-ObjectCount $outboundRows)
    InboundExternalSpCount       = (Get-ObjectCount $inboundRows)
    HighSeverityCount            = (Get-ObjectCount @($allRows | Where-Object { $_.Severity -eq 'High' }))
    MediumSeverityCount          = (Get-ObjectCount @($allRows | Where-Object { $_.Severity -eq 'Medium' }))
    LowSeverityCount             = (Get-ObjectCount @($allRows | Where-Object { $_.Severity -eq 'Low' }))
    IncludeMicrosoftFirstParty   = [bool]$IncludeMicrosoftFirstParty
    IncludeExchange              = [bool]$IncludeExchange
    SignInActivityCollected      = [bool]$collectSignIns
    SignInLookbackDays           = $SignInLookbackDays
    SignInEventsCaptured         = (Get-ObjectCount $signInRecords)
    UniqueSourceIpCount          = (Get-ObjectCount $ipIntel)
    IpIntelligenceCollected      = [bool](-not $SkipIpIntelligence)
    GeneratedUtc                 = [DateTime]::UtcNow.ToString('o')
}
$summary | ConvertTo-Json | Set-Content -Path (Join-Path $runFolder 'summary.json') -Encoding UTF8

Write-Host ''
Write-AuditMsg 'Exported:' Ok
Write-Host "  $allCsv"
Write-Host "  $outCsv"
Write-Host "  $inCsv"
Write-Host "  $signInsCsv"
Write-Host "  $ipIntelCsv"
Write-Host "  $html"
Write-Host ("  summary: outbound={0}; inbound={1}; high={2}; medium={3}" -f `
        $summary.OutboundMultiTenantAppCount, $summary.InboundExternalSpCount, $summary.HighSeverityCount, $summary.MediumSeverityCount)
#endregion
