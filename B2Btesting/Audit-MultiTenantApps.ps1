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

.EXAMPLE
    # Prefer: sign in once in an external PowerShell window, then run the audit (reuses session)
    Connect-MgGraph -TenantId contoso.com -Scopes Application.Read.All,Directory.Read.All,DelegatedPermissionGrant.Read.All -UseDeviceCode
    .\Audit-MultiTenantApps.ps1 -TenantId contoso.com

.EXAMPLE
    .\Audit-MultiTenantApps.ps1 -TenantId contoso.com -DeviceCode

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

    # Internal: set when relaunched into an external console from Cursor/VS Code.
    [switch]$SkipExternalRelaunch
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

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

function Get-GraphPaged {
    param([Parameter(Mandatory)][string]$Uri, [int]$MaxPages = 200)

    $items = [System.Collections.Generic.List[object]]::new()
    $next = $Uri
    $page = 0
    while ($next -and $page -lt $MaxPages) {
        $page++
        $response = Invoke-MgGraphRequest -Method GET -Uri $next -ErrorAction Stop
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
        Write-AuditMsg ("Reusing existing Graph session (AuthType={0}; TenantId={1}). Use -ForceReconnect to sign in again." -f $existing.AuthType, $existing.TenantId) Ok
        return [string]$existing.TenantId
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
        # Application.Read.All / Directory.Read.All cover appRoleAssignments reads;
        # DelegatedPermissionGrant.Read.All covers oauth2PermissionGrants.
        $scopes = @(
            'Application.Read.All',
            'Directory.Read.All',
            'DelegatedPermissionGrant.Read.All'
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
        $owners = @(Get-GraphPaged -Uri ("https://graph.microsoft.com/v1.0/applications/{0}/owners?`$select=id,displayName" -f $ApplicationObjectId))
        return @($owners).Count
    }
    catch {
        return -1
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
            foreach ($a in @(Get-GraphPaged -Uri $uri)) { $apps.Add($a) }
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
        $fallbackPublic = [bool](Get-GraphProp -Object $app -Name 'isFallbackPublicClient')
        $homepage = [string](Get-GraphProp -Object (Get-GraphProp -Object $app -Name 'info') -Name 'homepage')

        $risk = [System.Collections.Generic.List[string]]::new()
        if ($permInfo.HighRiskCount -gt 0) { [void]$risk.Add('HighRiskGraphPermissions') }
        if ($creds.SecretCount -gt 0) { [void]$risk.Add('ClientSecretsPresent') }
        if ($creds.ExpiredCount -gt 0) { [void]$risk.Add('ExpiredCredentials') }
        if ($creds.Expiring30Count -gt 0) { [void]$risk.Add('CredentialsExpiring30Days') }
        if ($creds.CertCount -eq 0 -and $creds.SecretCount -eq 0) { [void]$risk.Add('NoCredentialsConfigured') }
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

function Collect-InboundExternalServicePrincipals {
    param(
        [Parameter(Mandatory)][string]$TenantOrgId,
        $GraphRoleMap,
        [switch]$IncludeMicrosoft
    )

    Write-AuditMsg 'Collecting inbound enterprise apps (service principals from other tenants)...'
    $select = 'id,appId,displayName,appOwnerOrganizationId,accountEnabled,createdDateTime,servicePrincipalType,preferredSingleSignOnMode,homepage,replyUrls,keyCredentials,passwordCredentials,verifiedPublisher,publisherName,tags,notes,info'
    $sps = Get-GraphPaged -Uri ('https://graph.microsoft.com/v1.0/servicePrincipals?$select={0}' -f $select)

    $rows = [System.Collections.Generic.List[object]]::new()
    $i = 0
    foreach ($sp in $sps) {
        $homeTenantId = [string](Get-GraphProp -Object $sp -Name 'appOwnerOrganizationId')
        if ([string]::IsNullOrWhiteSpace($homeTenantId)) { continue }
        if ([string]::Equals($homeTenantId, $TenantOrgId, [StringComparison]::OrdinalIgnoreCase)) { continue }

        $isMs = Test-IsMicrosoftTenantId -OrgId $homeTenantId
        if ($isMs -and -not $IncludeMicrosoft) { continue }

        $i++
        if ($i % 50 -eq 0) { Write-AuditMsg ("  Processed {0} inbound external SPs..." -f $i) }

        $spId = [string](Get-GraphProp -Object $sp -Name 'id')
        $appId = [string](Get-GraphProp -Object $sp -Name 'appId')
        $name = [string](Get-GraphProp -Object $sp -Name 'displayName')
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
        $ownerSummary = Get-SpOwnerSummary -ServicePrincipalId $spId
        $assignedToSummary = Get-SpAppRoleAssignedToSummary -ServicePrincipalId $spId -GraphRoleMap $GraphRoleMap

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
        if ($ownerSummary.OwnerCount -eq 0) { [void]$risk.Add('NoOwners') }
        if ($assignedToSummary.AssignmentCount -gt 0) { [void]$risk.Add('HasUserGroupAssignments') }
        if ($enabled -eq $false) { [void]$risk.Add('DisabledButPresent') }
        if ([string]::IsNullOrWhiteSpace($verifiedName) -and -not $isMs) { [void]$risk.Add('UnverifiedPublisher') }
        if ($creds.SecretCount -gt 0 -or $creds.CertCount -gt 0) { [void]$risk.Add('LocalCredentialsOnSp') }
        foreach ($f in @($redirectFlags | Select-Object -Unique)) { [void]$risk.Add($f) }

        $severity = 'Low'
        if (-not $isMs -and ($highRiskTotal -gt 0 -or $dirRoles.RoleCount -gt 0)) {
            $severity = 'High'
        }
        elseif (-not $isMs -and ($assignmentCount -gt 0 -or $adminGrantCount -gt 0 -or $userGrantCount -gt 0)) {
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
                        if ($ownerSummary.OwnerCount -eq 0) { 'No owners on this enterprise app — assign an accountable admin.' }
                        if ($assignedToSummary.AssignmentCount -gt 0) { 'Users/groups are assigned to this app — see AssignedPrincipals.' }
                        if ($enabled -eq $false) { 'Account disabled but object remains — confirm grants are revoked.' }
                        if ($isMs) { 'Microsoft first-party application (filtered in by -IncludeMicrosoftFirstParty).' }
                    ) -join ' '
                )
            })
    }

    Write-AuditMsg ("  Inbound external service principals: {0}" -f $rows.Count) Ok
    return , $rows.ToArray()
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
        [Parameter(Mandatory)][object[]]$AllRows,
        [Parameter(Mandatory)][string]$RunFolder
    )

    $outbound = @($AllRows | Where-Object { $_.Direction -eq 'Outbound' })
    $inbound = @($AllRows | Where-Object { $_.Direction -eq 'Inbound' })
    $high = @($AllRows | Where-Object { $_.Severity -eq 'High' })
    $medium = @($AllRows | Where-Object { $_.Severity -eq 'Medium' })

    function Esc([string]$t) {
        if ($null -eq $t) { return '' }
        return [System.Net.WebUtility]::HtmlEncode($t)
    }

    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.AppendLine('<!DOCTYPE html><html><head><meta charset="utf-8"/><title>Multi-tenant app audit</title>')
    [void]$sb.AppendLine('<style>body{font-family:Segoe UI,Arial,sans-serif;margin:24px;color:#1b1b1b}table{border-collapse:collapse;width:100%;margin:12px 0 28px}th,td{border:1px solid #ccc;padding:6px 8px;font-size:13px;vertical-align:top}th{background:#f3f3f3;text-align:left}.high{background:#fde7e9}.medium{background:#fff4ce}.muted{color:#666}code{font-size:12px}</style>')
    [void]$sb.AppendLine('</head><body>')
    [void]$sb.AppendLine('<h1>Multi-tenant / cross-tenant application audit</h1>')
    [void]$sb.AppendLine(('<p>Tenant: <strong>{0}</strong> (<code>{1}</code>)<br/>Generated: {2:u}<br/>Output: <code>{3}</code></p>' -f (Esc $Org.DisplayName), (Esc $Org.Id), [DateTime]::UtcNow, (Esc $RunFolder)))
    [void]$sb.AppendLine('<h2>Summary</h2><ul>')
    [void]$sb.AppendLine(('<li>Outbound multi-tenant app registrations: <strong>{0}</strong></li>' -f (Get-ObjectCount $outbound)))
    [void]$sb.AppendLine(('<li>Inbound external enterprise apps (non-home SP): <strong>{0}</strong></li>' -f (Get-ObjectCount $inbound)))
    [void]$sb.AppendLine(('<li>High severity rows: <strong>{0}</strong></li>' -f (Get-ObjectCount $high)))
    [void]$sb.AppendLine(('<li>Medium severity rows: <strong>{0}</strong></li>' -f (Get-ObjectCount $medium)))
    [void]$sb.AppendLine('</ul>')
    [void]$sb.AppendLine('<p class="muted">Outbound = apps this tenant publishes for other tenants to consent (requested permissions). Inbound = apps from other tenants consented into this tenant (granted application permissions, delegated scopes, and Entra directory roles).</p>')

    [void]$sb.AppendLine('<h2>Highest concern rows</h2>')
    [void]$sb.AppendLine('<table><tr><th>Severity</th><th>Direction</th><th>DisplayName</th><th>AppId</th><th>RiskFlags</th><th>Admin consent permissions</th><th>User consent permissions</th><th>Directory roles</th><th>Owners / admins</th><th>Notes</th></tr>')
    foreach ($r in @($AllRows | Sort-Object @{ Expression = { switch ($_.Severity) { 'High' { 0 } 'Medium' { 1 } default { 2 } } } }, DisplayName | Select-Object -First 75)) {
        $cls = switch ($r.Severity) { 'High' { 'high' } 'Medium' { 'medium' } default { '' } }
        [void]$sb.AppendLine(('<tr class="{0}"><td>{1}</td><td>{2}</td><td>{3}</td><td><code>{4}</code></td><td>{5}</td><td>{6}</td><td>{7}</td><td>{8}</td><td>{9}</td><td>{10}</td></tr>' -f `
                $cls,
                (Esc $r.Severity),
                (Esc $r.Direction),
                (Esc $r.DisplayName),
                (Esc $r.AppId),
                (Esc $r.RiskFlags),
                (Esc $(if ($r.AdminConsentPermissions) { $r.AdminConsentPermissions } else { '—' })),
                (Esc $(if ($r.UserConsentPermissions) { $r.UserConsentPermissions } else { '—' })),
                (Esc $(if ($r.DirectoryRoles) { $r.DirectoryRoles } else { '—' })),
                (Esc $(if ($r.Owners) { $r.Owners } else { '—' })),
                (Esc $r.SecurityNotes)))
    }
    [void]$sb.AppendLine('</table>')

    [void]$sb.AppendLine('<h2>Inbound service principals — admin consent vs user consent</h2>')
    [void]$sb.AppendLine('<table><tr><th>DisplayName</th><th>AppId</th><th>Severity</th><th>Admin consent (app roles + AllPrincipals delegated)</th><th>User consent (Principal delegated)</th><th>Admin scopes</th><th>User scopes</th><th>Directory roles</th><th>Owners</th><th>Assigned users/groups</th></tr>')
    $inboundSorted = @(
        $inbound | Sort-Object @{ Expression = { switch ($_.Severity) { 'High' { 0 } 'Medium' { 1 } default { 2 } } } }, DisplayName
    )
    if ((Get-ObjectCount $inboundSorted) -eq 0) {
        [void]$sb.AppendLine('<tr><td colspan="10" class="muted">No inbound external service principals in this run.</td></tr>')
    }
    else {
        foreach ($r in $inboundSorted) {
            $cls = switch ($r.Severity) { 'High' { 'high' } 'Medium' { 'medium' } default { '' } }
            $cell = {
                param($v)
                if ([string]::IsNullOrWhiteSpace([string]$v)) { '—' } else { [string]$v }
            }
            [void]$sb.AppendLine(('<tr class="{0}"><td>{1}</td><td><code>{2}</code></td><td>{3}</td><td>{4}</td><td>{5}</td><td>{6}</td><td>{7}</td><td>{8}</td><td>{9}</td><td>{10}</td></tr>' -f `
                    $cls,
                    (Esc $r.DisplayName),
                    (Esc $r.AppId),
                    (Esc $r.Severity),
                    (Esc (& $cell $r.AdminConsentPermissions)),
                    (Esc (& $cell $r.UserConsentPermissions)),
                    (Esc (& $cell $r.AdminConsentDelegatedScopes)),
                    (Esc (& $cell $r.UserConsentDelegatedScopes)),
                    (Esc (& $cell $r.DirectoryRoles)),
                    (Esc (& $cell $r.Owners)),
                    (Esc (& $cell $r.AssignedPrincipals))))
        }
    }
    [void]$sb.AppendLine('</table>')
    [void]$sb.AppendLine('<p class="muted">Admin consent = application permissions (appRoleAssignments) plus delegated grants with consentType=AllPrincipals. User consent = delegated grants with consentType=Principal (per-user).</p>')
    [void]$sb.AppendLine('<p class="muted">Full inventories including counts and risk flags are in the CSV files in the output folder.</p>')
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

$graphRoleMap = Get-GraphAppRoleValueMap
$outboundRows = ConvertTo-ObjectArray (Collect-OutboundMultiTenantApps -TenantOrgId $resolvedTenantId -GraphRoleMap $graphRoleMap)
$inboundRows = ConvertTo-ObjectArray (Collect-InboundExternalServicePrincipals -TenantOrgId $resolvedTenantId -GraphRoleMap $graphRoleMap `
        -IncludeMicrosoft:$IncludeMicrosoftFirstParty)

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
$html = Join-Path $runFolder 'multitenant-apps-report.html'

Export-AuditCsv -Rows $allRows -Path $allCsv
Export-AuditCsv -Rows $outboundRows -Path $outCsv
Export-AuditCsv -Rows $inboundRows -Path $inCsv
New-HtmlReport -Path $html -Org $org -AllRows $allRows -RunFolder $runFolder

$summary = [PSCustomObject]@{
    TenantId                     = $resolvedTenantId
    TenantDisplayName            = $org.DisplayName
    OutboundMultiTenantAppCount  = (Get-ObjectCount $outboundRows)
    InboundExternalSpCount       = (Get-ObjectCount $inboundRows)
    HighSeverityCount            = (Get-ObjectCount @($allRows | Where-Object { $_.Severity -eq 'High' }))
    MediumSeverityCount          = (Get-ObjectCount @($allRows | Where-Object { $_.Severity -eq 'Medium' }))
    IncludeMicrosoftFirstParty   = [bool]$IncludeMicrosoftFirstParty
    GeneratedUtc                 = [DateTime]::UtcNow.ToString('o')
}
$summary | ConvertTo-Json | Set-Content -Path (Join-Path $runFolder 'summary.json') -Encoding UTF8

Write-Host ''
Write-AuditMsg 'Exported:' Ok
Write-Host "  $allCsv"
Write-Host "  $outCsv"
Write-Host "  $inCsv"
Write-Host "  $html"
Write-Host ("  summary: outbound={0}; inbound={1}; high={2}; medium={3}" -f `
        $summary.OutboundMultiTenantAppCount, $summary.InboundExternalSpCount, $summary.HighSeverityCount, $summary.MediumSeverityCount)
#endregion
