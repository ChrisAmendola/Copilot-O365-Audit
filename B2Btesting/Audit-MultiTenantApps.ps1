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

.EXAMPLE
    .\Audit-MultiTenantApps.ps1 -TenantId contoso.com

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

    [string]$GraphCertificateThumbprint
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

function Get-GraphProp {
    param($Object, [string]$Name)
    if ($null -eq $Object) { return $null }
    if ($Object -is [hashtable] -or $Object -is [System.Collections.IDictionary]) {
        if ($Object.ContainsKey($Name)) { return $Object[$Name] }
        return $null
    }
    $p = $Object.PSObject.Properties[$Name]
    if ($p) { return $p.Value }
    return $null
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
    return @($items)
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

    if ($UseAppOnly) {
        if ([string]::IsNullOrWhiteSpace($appId) -or [string]::IsNullOrWhiteSpace($thumb)) {
            throw 'AppOnly requires GraphAppId/B2B_GR_APP_ID and GraphCertificateThumbprint/B2B_GR_CERT_THUMBPRINT.'
        }
        Write-AuditMsg "Connecting app-only Graph (TenantId=$TargetTenant; AppId=$appId)..."
        Connect-MgGraph -TenantId $TargetTenant -ClientId $appId -CertificateThumbprint $thumb -NoWelcome
    }
    else {
        Write-AuditMsg "Connecting delegated Graph (TenantId=$TargetTenant)..."
        Connect-MgGraph -TenantId $TargetTenant -Scopes @(
            'Application.Read.All',
            'Directory.Read.All',
            'AppRoleAssignment.Read.All',
            'DelegatedPermissionGrant.Read.All'
        ) -NoWelcome
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
    $uri = 'https://graph.microsoft.com/v1.0/servicePrincipals?$filter=appId eq ''00000003-0000-0000-c000-000000000000''&$select=id,appRoles'
    $response = Invoke-MgGraphRequest -Method GET -Uri $uri -ErrorAction Stop
    $sp = @((Get-GraphProp -Object $response -Name 'value')) | Select-Object -First 1
    $map = @{}
    foreach ($role in @((Get-GraphProp -Object $sp -Name 'appRoles'))) {
        $id = [string](Get-GraphProp -Object $role -Name 'id')
        $value = [string](Get-GraphProp -Object $role -Name 'value')
        if ($id -and $value) { $map[$id] = $value }
    }
    return @{
        SpId     = [string](Get-GraphProp -Object $sp -Name 'id')
        RolesById = $map
    }
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
        $owners = Get-GraphPaged -Uri ("https://graph.microsoft.com/v1.0/applications/{0}/owners?`$select=id,displayName" -f $ApplicationObjectId)
        return $owners.Count
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
                OwnerCount             = $ownerCount
                CertCount              = $creds.CertCount
                SecretCount            = $creds.SecretCount
                ExpiredCredentialCount = $creds.ExpiredCount
                Expiring30DayCount     = $creds.Expiring30Count
                RedirectUriCount       = $redirects.RedirectUriCount
                RedirectUris           = $redirects.RedirectUris
                PermissionCount        = $permInfo.PermissionCount
                ApplicationRoleCount   = $permInfo.ApplicationRoleCount
                DelegatedScopeCount    = $permInfo.DelegatedScopeCount
                HighRiskPermissionCount = $permInfo.HighRiskCount
                HighRiskPermissions    = $permInfo.HighRiskPermissions
                Permissions            = $permInfo.Permissions
                AccountEnabled         = ''
                AppRoleAssignmentCount = ''
                Oauth2GrantCount       = ''
                RiskFlags              = ($risk -join ',')
                Severity               = $severity
                SecurityNotes          = (
                    @(
                        'Multi-tenant app registration owned by this tenant; other tenants can admin-consent it.'
                        if ($permInfo.HighRiskCount -gt 0) { 'Requests privileged Graph permissions — review necessity and least privilege.' }
                        if ($creds.SecretCount -gt 0) { 'Client secrets are present; prefer certificates and rotate regularly.' }
                        if ($ownerCount -eq 0) { 'No owners assigned — ownership/accountability gap.' }
                        if ($audience -eq 'AzureADandPersonalMicrosoftAccount') { 'Also allows personal Microsoft accounts — broader attack surface.' }
                    ) -join ' '
                )
            })
    }

    Write-AuditMsg ("  Outbound multi-tenant app registrations: {0}" -f $rows.Count) Ok
    return @($rows)
}

function Get-SpAppRoleAssignmentSummary {
    param([Parameter(Mandatory)][string]$ServicePrincipalId, $GraphRoleMap)

    $high = [System.Collections.Generic.List[string]]::new()
    $all = [System.Collections.Generic.List[string]]::new()
    try {
        $assignments = Get-GraphPaged -Uri ("https://graph.microsoft.com/v1.0/servicePrincipals/{0}/appRoleAssignments" -f $ServicePrincipalId)
    }
    catch {
        return [PSCustomObject]@{ Count = -1; HighRiskCount = 0; HighRisk = ''; All = '' }
    }

    foreach ($a in $assignments) {
        $roleId = [string](Get-GraphProp -Object $a -Name 'appRoleId')
        $resName = [string](Get-GraphProp -Object $a -Name 'resourceDisplayName')
        $label = $roleId
        if ($GraphRoleMap.RolesById.ContainsKey($roleId)) {
            $label = [string]$GraphRoleMap.RolesById[$roleId]
        }
        $entry = '{0}/{1}' -f $(if ($resName) { $resName } else { 'resource' }), $label
        [void]$all.Add($entry)
        if (Test-IsHighRiskPermission -Value $label) { [void]$high.Add($entry) }
    }

    return [PSCustomObject]@{
        Count         = $assignments.Count
        HighRiskCount = $high.Count
        HighRisk      = ($high -join '; ')
        All           = ($all -join '; ')
    }
}

function Get-SpOauth2GrantCount {
    param([Parameter(Mandatory)][string]$ServicePrincipalId)

    try {
        $filter = [uri]::EscapeDataString("clientId eq '$ServicePrincipalId'")
        $grants = Get-GraphPaged -Uri ('https://graph.microsoft.com/v1.0/oauth2PermissionGrants?$filter={0}' -f $filter)
        return $grants.Count
    }
    catch {
        return -1
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
        $grantCount = Get-SpOauth2GrantCount -ServicePrincipalId $spId

        $replyUrls = @((Get-GraphProp -Object $sp -Name 'replyUrls'))
        $redirectFlags = [System.Collections.Generic.List[string]]::new()
        foreach ($u in $replyUrls) {
            if ($u -match '(?i)^http:') { [void]$redirectFlags.Add('HttpRedirectUri') }
            if ($u -match '(?i)\*') { [void]$redirectFlags.Add('WildcardRedirectUri') }
        }

        $risk = [System.Collections.Generic.List[string]]::new()
        [void]$risk.Add('ExternalHomeTenant')
        if ($isMs) { [void]$risk.Add('MicrosoftFirstParty') } else { [void]$risk.Add('ThirdPartyPublisher') }
        if ($roleSummary.HighRiskCount -gt 0) { [void]$risk.Add('HighRiskAppRoleAssignments') }
        if ($roleSummary.Count -gt 0) { [void]$risk.Add('HasApplicationPermissions') }
        if ($grantCount -gt 0) { [void]$risk.Add('HasDelegatedGrants') }
        if ($enabled -eq $false) { [void]$risk.Add('DisabledButPresent') }
        if ([string]::IsNullOrWhiteSpace($verifiedName) -and -not $isMs) { [void]$risk.Add('UnverifiedPublisher') }
        if ($creds.SecretCount -gt 0 -or $creds.CertCount -gt 0) { [void]$risk.Add('LocalCredentialsOnSp') }
        foreach ($f in @($redirectFlags | Select-Object -Unique)) { [void]$risk.Add($f) }

        $severity = 'Low'
        if (-not $isMs -and $roleSummary.HighRiskCount -gt 0) {
            $severity = 'High'
        }
        elseif (-not $isMs -and ($roleSummary.Count -gt 0 -or $grantCount -gt 5)) {
            $severity = 'Medium'
        }
        elseif ($isMs -and $roleSummary.HighRiskCount -gt 0) {
            $severity = 'Medium'
        }

        $rows.Add([PSCustomObject][ordered]@{
                Direction              = 'Inbound'
                ObjectType             = 'ServicePrincipal'
                AppId                  = $appId
                ObjectId               = $spId
                DisplayName            = $name
                SignInAudience         = ''
                HomeTenantId           = $homeTenantId
                PublisherDomain        = ''
                VerifiedPublisher      = $verifiedName
                Homepage               = [string](Get-GraphProp -Object $sp -Name 'homepage')
                CreatedDateTime        = [string](Get-GraphProp -Object $sp -Name 'createdDateTime')
                OwnerCount             = ''
                CertCount              = $creds.CertCount
                SecretCount            = $creds.SecretCount
                ExpiredCredentialCount = $creds.ExpiredCount
                Expiring30DayCount     = $creds.Expiring30Count
                RedirectUriCount       = $replyUrls.Count
                RedirectUris           = ($replyUrls -join '; ')
                PermissionCount        = $(if ($roleSummary.Count -ge 0) { $roleSummary.Count } else { '' })
                ApplicationRoleCount   = $(if ($roleSummary.Count -ge 0) { $roleSummary.Count } else { '' })
                DelegatedScopeCount    = $(if ($grantCount -ge 0) { $grantCount } else { '' })
                HighRiskPermissionCount = $roleSummary.HighRiskCount
                HighRiskPermissions    = $roleSummary.HighRisk
                Permissions            = $roleSummary.All
                AccountEnabled         = $enabled
                AppRoleAssignmentCount = $(if ($roleSummary.Count -ge 0) { $roleSummary.Count } else { '' })
                Oauth2GrantCount       = $(if ($grantCount -ge 0) { $grantCount } else { '' })
                RiskFlags              = ($risk -join ',')
                Severity               = $severity
                SecurityNotes          = (
                    @(
                        'Service principal home tenant differs from this tenant (external / multi-tenant consent).'
                        if (-not $isMs -and $roleSummary.HighRiskCount -gt 0) { 'Third-party app holds privileged application permissions in THIS tenant — review and remove if unused.' }
                        if ($grantCount -gt 0) { 'Has delegated oauth2PermissionGrants — users/admins consented scopes.' }
                        if ($enabled -eq $false) { 'Account disabled but object remains — confirm grants are revoked.' }
                        if ($isMs) { 'Microsoft first-party application (filtered in by -IncludeMicrosoftFirstParty).' }
                    ) -join ' '
                )
            })
    }

    Write-AuditMsg ("  Inbound external service principals: {0}" -f $rows.Count) Ok
    return @($rows)
}

function Export-AuditCsv {
    param([object[]]$Rows, [string]$Path)
    if (-not $Rows -or $Rows.Count -eq 0) {
        [PSCustomObject]@{ Notice = 'No rows' } | Export-Csv -Path $Path -NoTypeInformation -Encoding UTF8
        return
    }
    $Rows | Export-Csv -Path $Path -NoTypeInformation -Encoding UTF8
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
    [void]$sb.AppendLine(('<li>Outbound multi-tenant app registrations: <strong>{0}</strong></li>' -f $outbound.Count))
    [void]$sb.AppendLine(('<li>Inbound external enterprise apps (non-home SP): <strong>{0}</strong></li>' -f $inbound.Count))
    [void]$sb.AppendLine(('<li>High severity rows: <strong>{0}</strong></li>' -f $high.Count))
    [void]$sb.AppendLine(('<li>Medium severity rows: <strong>{0}</strong></li>' -f $medium.Count))
    [void]$sb.AppendLine('</ul>')
    [void]$sb.AppendLine('<p class="muted">Outbound = apps this tenant publishes for other tenants to consent. Inbound = apps from other tenants (or Microsoft) consented into this tenant.</p>')

    [void]$sb.AppendLine('<h2>Highest concern rows</h2>')
    [void]$sb.AppendLine('<table><tr><th>Severity</th><th>Direction</th><th>DisplayName</th><th>AppId</th><th>HomeTenantId</th><th>RiskFlags</th><th>HighRiskPermissions</th><th>Notes</th></tr>')
    foreach ($r in @($AllRows | Sort-Object @{ Expression = { switch ($_.Severity) { 'High' { 0 } 'Medium' { 1 } default { 2 } } } }, DisplayName | Select-Object -First 75)) {
        $cls = switch ($r.Severity) { 'High' { 'high' } 'Medium' { 'medium' } default { '' } }
        [void]$sb.AppendLine(('<tr class="{0}"><td>{1}</td><td>{2}</td><td>{3}</td><td><code>{4}</code></td><td><code>{5}</code></td><td>{6}</td><td>{7}</td><td>{8}</td></tr>' -f `
                $cls, (Esc $r.Severity), (Esc $r.Direction), (Esc $r.DisplayName), (Esc $r.AppId), (Esc $r.HomeTenantId), (Esc $r.RiskFlags), (Esc $r.HighRiskPermissions), (Esc $r.SecurityNotes)))
    }
    [void]$sb.AppendLine('</table>')
    [void]$sb.AppendLine('<p class="muted">See CSV files in the output folder for full inventories.</p>')
    [void]$sb.AppendLine('</body></html>')
    [System.IO.File]::WriteAllText($Path, $sb.ToString(), [System.Text.UTF8Encoding]::new($false))
}

#region Main
Write-Host '========================================' -ForegroundColor Cyan
Write-Host 'Multi-tenant / B2B application audit' -ForegroundColor Cyan
Write-Host '========================================' -ForegroundColor Cyan

$resolvedTenantId = Connect-AuditGraph -TargetTenant $TenantId -UseAppOnly:$AppOnly
$org = Get-CurrentOrganization
if ($org.Id) { $resolvedTenantId = $org.Id }
Write-AuditMsg ("Organization: {0} ({1})" -f $org.DisplayName, $resolvedTenantId) Ok

$graphRoleMap = Get-GraphAppRoleValueMap
$outboundRows = Collect-OutboundMultiTenantApps -TenantOrgId $resolvedTenantId -GraphRoleMap $graphRoleMap
$inboundRows = Collect-InboundExternalServicePrincipals -TenantOrgId $resolvedTenantId -GraphRoleMap $graphRoleMap `
    -IncludeMicrosoft:$IncludeMicrosoftFirstParty

$allRows = @($outboundRows + $inboundRows)

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
    OutboundMultiTenantAppCount  = $outboundRows.Count
    InboundExternalSpCount       = $inboundRows.Count
    HighSeverityCount            = @($allRows | Where-Object { $_.Severity -eq 'High' }).Count
    MediumSeverityCount          = @($allRows | Where-Object { $_.Severity -eq 'Medium' }).Count
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
