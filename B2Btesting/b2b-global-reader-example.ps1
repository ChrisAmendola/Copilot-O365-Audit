#Requires -Version 5.1
<#
.SYNOPSIS
    Example: multi-tenant Entra app so home tenant AA can read resource tenant BB
    with Global Reader + Graph application permissions (certificate auth).

.DESCRIPTION
    This is a cross-tenant *application* access pattern (multi-tenant app + admin
    consent + Global Reader on the service principal in BB). It is not the same as
    inviting a B2B guest user.

    Modes:
      Home     - Run in tenant AA. Creates multi-tenant app + certificate, prints
                 admin-consent URL for BB, writes .b2b-global-reader.local.ps1.
      Resource - Run in tenant BB after admin consent. Assigns Global Reader to the
                 app's service principal and ensures Graph app-role assignments.
      Test     - Run from AA operator host. Connects app-only into BB and runs a
                 small read smoke test (organization + directoryRoles).

.PARAMETER Mode
    Home | Resource | Test

.PARAMETER TenantId
    Entra tenant ID (GUID) or domain for the tenant you are operating in:
      Home / Test home context: AA
      Resource / Test -ResourceTenantId: BB

.PARAMETER ResourceTenantId
    Required for -Mode Test: BB tenant ID (GUID preferred).

.PARAMETER AppId
    Client ID from Home mode. Required for Resource and Test (or set via helper env).

.PARAMETER DisplayName
    App display name when creating in Home mode.

.PARAMETER CertValidMonths
    Certificate validity in months (default 12).

.PARAMETER OutputPath
    Directory for PFX + helper script (default: this script's folder).

.EXAMPLE
    # 1) In AA (Application Administrator / Global Admin)
    .\b2b-global-reader-example.ps1 -Mode Home -TenantId 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'

    # 2) BB Global Admin opens the printed adminconsent URL

    # 3) In BB
    .\b2b-global-reader-example.ps1 -Mode Resource -TenantId 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb' `
      -AppId '<client-id-from-home>'

    # 4) From AA operator machine (cert in CurrentUser\My or helper env)
    . .\.b2b-global-reader.local.ps1
    .\b2b-global-reader-example.ps1 -Mode Test -TenantId 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa' `
      -ResourceTenantId 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb'
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateSet('Home', 'Resource', 'Test')]
    [string]$Mode,

    [Parameter(Mandatory)]
    [string]$TenantId,

    [string]$ResourceTenantId,

    [string]$AppId,

    [string]$DisplayName = 'B2B-Example-GlobalReader-CrossTenant',

    [ValidateRange(1, 24)]
    [int]$CertValidMonths = 12,

    [string]$OutputPath = $PSScriptRoot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$Script:GraphResourceAppId = '00000003-0000-0000-c000-000000000000'
$Script:RequiredGraphAppRoles = @(
    'Directory.Read.All',
    'User.Read.All',
    'Group.Read.All',
    'Organization.Read.All',
    'RoleManagement.Read.Directory',
    'AuditLog.Read.All',
    'Policy.Read.All'
)

function Write-Step {
    param([string]$Message, [ValidateSet('Info', 'Warn', 'Ok')][string]$Level = 'Info')
    $color = switch ($Level) {
        'Warn' { 'Yellow' }
        'Ok'   { 'Green' }
        default { 'Cyan' }
    }
    Write-Host $Message -ForegroundColor $color
}

function Get-GraphObjectProperty {
    param($Object, [string]$PropertyName)
    if ($null -eq $Object) { return $null }
    if ($Object -is [hashtable] -or $Object -is [System.Collections.IDictionary]) {
        if ($Object.ContainsKey($PropertyName)) { return $Object[$PropertyName] }
        return $null
    }
    $prop = $Object.PSObject.Properties[$PropertyName]
    if ($prop) { return $prop.Value }
    return $null
}

function Import-GraphAuthModule {
    if (-not (Get-Module -ListAvailable -Name 'Microsoft.Graph.Authentication')) {
        throw 'Microsoft.Graph.Authentication is required. Install-Module Microsoft.Graph.Authentication -Scope CurrentUser'
    }
    Import-Module Microsoft.Graph.Authentication -ErrorAction Stop
}

function Connect-DelegatedAdminGraph {
    param([Parameter(Mandatory)][string]$TargetTenantId)

    $scopes = @(
        'Application.ReadWrite.All',
        'AppRoleAssignment.ReadWrite.All',
        'RoleManagement.ReadWrite.Directory',
        'Directory.Read.All'
    )
    Write-Step "Connecting to Microsoft Graph (delegated) TenantId=$TargetTenantId ..."
    Connect-MgGraph -TenantId $TargetTenantId -Scopes $scopes -NoWelcome
    $ctx = Get-MgContext
    if (-not $ctx) { throw 'Connect-MgGraph did not establish a context.' }
    Write-Step "  Connected as $($ctx.Account) AuthType=$($ctx.AuthType)" Ok
}

function Get-MicrosoftGraphAppRoleMap {
    $uri = 'https://graph.microsoft.com/v1.0/servicePrincipals?$filter=appId eq ''{0}''&$select=id,appId,appRoles' -f $Script:GraphResourceAppId
    $response = Invoke-MgGraphRequest -Method GET -Uri $uri -ErrorAction Stop
    $sp = @((Get-GraphObjectProperty -Object $response -PropertyName 'value')) | Select-Object -First 1
    if (-not $sp) {
        throw 'Could not resolve the Microsoft Graph service principal.'
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
        AppId              = $Script:GraphResourceAppId
        RolesByValue       = $roles
    }
}

function New-ExampleAppCertificate {
    param(
        [Parameter(Mandatory)][string]$SubjectName,
        [Parameter(Mandatory)][int]$ValidMonths,
        [Parameter(Mandatory)][string]$PfxPath
    )

    $cert = New-SelfSignedCertificate `
        -Subject "CN=$SubjectName" `
        -CertStoreLocation 'Cert:\CurrentUser\My' `
        -KeyExportPolicy Exportable `
        -KeySpec Signature `
        -KeyLength 2048 `
        -KeyAlgorithm RSA `
        -HashAlgorithm SHA256 `
        -NotAfter (Get-Date).AddMonths($ValidMonths) `
        -ErrorAction Stop

    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $bytes = New-Object byte[] 32
    $rng.GetBytes($bytes)
    $pwdPlain = [Convert]::ToBase64String($bytes)
    $pwdSecure = ConvertTo-SecureString -String $pwdPlain -AsPlainText -Force
    $null = Export-PfxCertificate -Cert $cert -FilePath $PfxPath -Password $pwdSecure -ErrorAction Stop

    return [PSCustomObject]@{
        Certificate    = $cert
        Thumbprint     = [string]$cert.Thumbprint
        PfxPath        = $PfxPath
        PasswordPlain  = $pwdPlain
        PasswordSecure = $pwdSecure
        KeyBase64      = [Convert]::ToBase64String($cert.RawData)
    }
}

function Grant-GraphAppRolesToPrincipal {
    param(
        [Parameter(Mandatory)][string]$PrincipalSpId,
        [Parameter(Mandatory)]$GraphSpMap,
        [Parameter(Mandatory)][string[]]$PermissionValues
    )

    $failures = [System.Collections.Generic.List[string]]::new()
    foreach ($perm in $PermissionValues) {
        if (-not $GraphSpMap.RolesByValue.ContainsKey($perm)) {
            [void]$failures.Add("$perm (role missing on Graph SP)")
            continue
        }
        $body = @{
            principalId = $PrincipalSpId
            resourceId  = $GraphSpMap.ServicePrincipalId
            appRoleId   = $GraphSpMap.RolesByValue[$perm]
        }
        try {
            Invoke-MgGraphRequest -Method POST `
                -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$($GraphSpMap.ServicePrincipalId)/appRoleAssignedTo" `
                -Body $body -ContentType 'application/json' -ErrorAction Stop | Out-Null
            Write-Step "  App role assigned: $perm" Ok
        }
        catch {
            $msg = $_.Exception.Message
            if ($msg -match '(?i)Permission being assigned already exists|Conflict') {
                Write-Step "  App role already present: $perm" Info
            }
            else {
                [void]$failures.Add("$perm ($msg)")
                Write-Step ("  App role assignment failed: {0} - {1}" -f $perm, $msg) Warn
            }
        }
    }
    return @($failures)
}

function Get-ServicePrincipalByAppId {
    param([Parameter(Mandatory)][string]$ClientId)

    $filter = [uri]::EscapeDataString("appId eq '$ClientId'")
    $uri = 'https://graph.microsoft.com/v1.0/servicePrincipals?$filter={0}&$select=id,appId,displayName' -f $filter
    $response = Invoke-MgGraphRequest -Method GET -Uri $uri -ErrorAction Stop
    return @((Get-GraphObjectProperty -Object $response -PropertyName 'value')) | Select-Object -First 1
}

function Grant-GlobalReaderRole {
    param([Parameter(Mandatory)][string]$PrincipalSpId)

    $uri = 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions?$filter=displayName eq ''Global Reader''&$select=id,displayName'
    $response = Invoke-MgGraphRequest -Method GET -Uri $uri -ErrorAction Stop
    $roleDef = @((Get-GraphObjectProperty -Object $response -PropertyName 'value')) | Select-Object -First 1
    $roleDefId = [string](Get-GraphObjectProperty -Object $roleDef -PropertyName 'id')
    if (-not $roleDefId) {
        throw 'Could not resolve the Global Reader role definition in this tenant.'
    }

    try {
        Invoke-MgGraphRequest -Method POST `
            -Uri 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments' `
            -Body @{
                '@odata.type'    = '#microsoft.graph.unifiedRoleAssignment'
                principalId      = $PrincipalSpId
                roleDefinitionId = $roleDefId
                directoryScopeId = '/'
            } -ContentType 'application/json' -ErrorAction Stop | Out-Null
        Write-Step '  Assigned Entra role: Global Reader' Ok
        return $true
    }
    catch {
        if ($_.Exception.Message -match '(?i)already exist|Conflict') {
            Write-Step '  Global Reader role assignment already exists.' Info
            return $true
        }
        throw
    }
}

function Resolve-AppId {
    param([string]$ExplicitAppId)

    if (-not [string]::IsNullOrWhiteSpace($ExplicitAppId)) { return $ExplicitAppId.Trim() }
    $envApp = [Environment]::GetEnvironmentVariable('B2B_GR_APP_ID')
    if (-not [string]::IsNullOrWhiteSpace($envApp)) { return $envApp.Trim() }
    return $null
}

function Resolve-CertThumbprint {
    $envThumb = [Environment]::GetEnvironmentVariable('B2B_GR_CERT_THUMBPRINT')
    if (-not [string]::IsNullOrWhiteSpace($envThumb)) { return $envThumb.Trim() }
    return $null
}

function Invoke-HomeMode {
    param(
        [Parameter(Mandatory)][string]$HomeTenantId,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][int]$ValidMonths,
        [Parameter(Mandatory)][string]$OutDir
    )

    Import-GraphAuthModule
    Connect-DelegatedAdminGraph -TargetTenantId $HomeTenantId

    if (-not (Test-Path -LiteralPath $OutDir)) {
        $null = New-Item -ItemType Directory -Path $OutDir -Force
    }

    Write-Step "`n[Home] Creating multi-tenant app in AA..."
    $graphSp = Get-MicrosoftGraphAppRoleMap
    $missing = @($Script:RequiredGraphAppRoles | Where-Object { -not $graphSp.RolesByValue.ContainsKey($_) })
    if ($missing.Count -gt 0) {
        throw "Microsoft Graph is missing app roles: $($missing -join ', ')"
    }

    $resourceAccess = @(
        foreach ($perm in $Script:RequiredGraphAppRoles) {
            @{ id = $graphSp.RolesByValue[$perm]; type = 'Role' }
        }
    )

    $pfxPath = Join-Path $OutDir '.b2b-global-reader.local.pfx'
    $certInfo = New-ExampleAppCertificate -SubjectName $Name -ValidMonths $ValidMonths -PfxPath $pfxPath
    Write-Step "  Certificate thumbprint=$($certInfo.Thumbprint); PFX=$pfxPath" Ok

    $appBody = @{
        displayName            = $Name
        signInAudience         = 'AzureADMultipleOrgs'
        keyCredentials         = @(
            @{
                type        = 'AsymmetricX509Cert'
                usage       = 'Verify'
                key         = $certInfo.KeyBase64
                displayName = "CN=$Name"
            }
        )
        requiredResourceAccess = @(
            @{
                resourceAppId  = $graphSp.AppId
                resourceAccess = $resourceAccess
            }
        )
    }

    $app = Invoke-MgGraphRequest -Method POST -Uri 'https://graph.microsoft.com/v1.0/applications' `
        -Body $appBody -ContentType 'application/json' -ErrorAction Stop
    $clientId = [string](Get-GraphObjectProperty -Object $app -PropertyName 'appId')
    $objectId = [string](Get-GraphObjectProperty -Object $app -PropertyName 'id')
    if (-not $clientId) { throw 'Application create returned no appId.' }
    Write-Step "  Created application ObjectId=$objectId AppId=$clientId" Ok

    $homeSp = Invoke-MgGraphRequest -Method POST -Uri 'https://graph.microsoft.com/v1.0/servicePrincipals' `
        -Body @{ appId = $clientId } -ContentType 'application/json' -ErrorAction Stop
    $homeSpId = [string](Get-GraphObjectProperty -Object $homeSp -PropertyName 'id')
    Write-Step "  Created home-tenant service principal Id=$homeSpId" Ok

    # Consent Graph roles in AA (handy for testing against AA itself; BB still needs its own consent).
    $null = Grant-GraphAppRolesToPrincipal -PrincipalSpId $homeSpId -GraphSpMap $graphSp `
        -PermissionValues $Script:RequiredGraphAppRoles

    $helperPath = Join-Path $OutDir '.b2b-global-reader.local.ps1'
    $pwdEsc = $certInfo.PasswordPlain -replace "'", "''"
    $pfxEsc = $pfxPath -replace "'", "''"
    $thumb = $certInfo.Thumbprint
    $helperLines = @(
        '# Generated by b2b-global-reader-example.ps1 -Mode Home - DO NOT COMMIT'
        "# Home tenant (AA): $HomeTenantId"
        "# App: $Name"
        "`$env:B2B_GR_APP_ID = '$clientId'"
        "`$env:B2B_GR_CERT_THUMBPRINT = '$thumb'"
        "`$env:B2B_GR_CERT_PATH = '$pfxEsc'"
        "`$env:B2B_GR_CERT_PASSWORD = '$pwdEsc'"
        '# After BB admin consent + Resource mode:'
        '# . .\.b2b-global-reader.local.ps1'
        "# .\b2b-global-reader-example.ps1 -Mode Test -TenantId '$HomeTenantId' -ResourceTenantId 'BB-TENANT-ID'"
    )
    [System.IO.File]::WriteAllText($helperPath, ($helperLines -join [Environment]::NewLine) + [Environment]::NewLine, [System.Text.UTF8Encoding]::new($false))

    $consentTemplate = 'https://login.microsoftonline.com/BB-TENANT-ID/adminconsent?client_id={0}' -f $clientId

    Write-Host ''
    Write-Host '========== Home (AA) registration complete ==========' -ForegroundColor Green
    Write-Host ('AppId (Client ID): {0}' -f $clientId) -ForegroundColor Green
    Write-Host ('Certificate thumbprint: {0}' -f $thumb) -ForegroundColor Green
    Write-Host ('PFX:               {0}' -f $pfxPath) -ForegroundColor Cyan
    Write-Host ('Helper:            {0}' -f $helperPath) -ForegroundColor Cyan
    Write-Host ''
    Write-Host 'Next - BB Global Admin opens admin consent (replace BB-TENANT-ID):' -ForegroundColor Yellow
    Write-Host ('  {0}' -f $consentTemplate) -ForegroundColor Yellow
    Write-Host ''
    Write-Host 'Then in BB run Resource mode:' -ForegroundColor Yellow
    Write-Host ('  .\b2b-global-reader-example.ps1 -Mode Resource -TenantId BB-TENANT-ID -AppId {0}' -f $clientId) -ForegroundColor Yellow
    Write-Host '=====================================================' -ForegroundColor Green
}

function Invoke-ResourceMode {
    param(
        [Parameter(Mandatory)][string]$ResourceTenant,
        [Parameter(Mandatory)][string]$ClientId
    )

    Import-GraphAuthModule
    Connect-DelegatedAdminGraph -TargetTenantId $ResourceTenant

    Write-Step "`n[Resource] Configuring app in BB (AppId=$ClientId)..."
    $appSp = Get-ServicePrincipalByAppId -ClientId $ClientId
    if (-not $appSp) {
        throw ("Service principal for AppId {0} was not found in tenant {1}. Complete admin consent first: https://login.microsoftonline.com/{1}/adminconsent?client_id={0}" -f $ClientId, $ResourceTenant)
    }

    $spId = [string](Get-GraphObjectProperty -Object $appSp -PropertyName 'id')
    $display = [string](Get-GraphObjectProperty -Object $appSp -PropertyName 'displayName')
    Write-Step "  Found Enterprise app / SP: $display ($spId)" Ok

    $graphSp = Get-MicrosoftGraphAppRoleMap
    $null = Grant-GraphAppRolesToPrincipal -PrincipalSpId $spId -GraphSpMap $graphSp `
        -PermissionValues $Script:RequiredGraphAppRoles
    $null = Grant-GlobalReaderRole -PrincipalSpId $spId

    Write-Host ''
    Write-Host '========== Resource (BB) configuration complete ==========' -ForegroundColor Green
    Write-Host "AppId:          $ClientId" -ForegroundColor Green
    Write-Host "SP objectId:    $spId" -ForegroundColor Green
    Write-Host 'Role:           Global Reader' -ForegroundColor Green
    Write-Host 'Graph app roles: consented/assigned (see log above)' -ForegroundColor Cyan
    Write-Host ''
    Write-Host 'From AA, test with:' -ForegroundColor Yellow
    Write-Host '  . .\.b2b-global-reader.local.ps1' -ForegroundColor Yellow
    Write-Host ('  .\b2b-global-reader-example.ps1 -Mode Test -TenantId AA-TENANT-ID -ResourceTenantId {0}' -f $ResourceTenant) -ForegroundColor Yellow
    Write-Host '==========================================================' -ForegroundColor Green
}

function Invoke-TestMode {
    param(
        [Parameter(Mandatory)][string]$HomeTenantId,
        [Parameter(Mandatory)][string]$ResourceTenant,
        [Parameter(Mandatory)][string]$ClientId,
        [Parameter(Mandatory)][string]$Thumbprint
    )

    Import-GraphAuthModule

    Write-Step "`n[Test] App-only connect into BB ($ResourceTenant) as AppId=$ClientId ..."
    Write-Step "  (Home tenant AA=$HomeTenantId holds the private key; token is issued for BB.)"

    try {
        $null = Get-Item -Path "Cert:\CurrentUser\My\$Thumbprint" -ErrorAction Stop
    }
    catch {
        $pfx = [Environment]::GetEnvironmentVariable('B2B_GR_CERT_PATH')
        $pwd = [Environment]::GetEnvironmentVariable('B2B_GR_CERT_PASSWORD')
        if ([string]::IsNullOrWhiteSpace($pfx) -or -not (Test-Path -LiteralPath $pfx)) {
            throw "Certificate thumbprint $Thumbprint not in CurrentUser\My and B2B_GR_CERT_PATH missing/invalid. Dot-source .b2b-global-reader.local.ps1 or import the PFX."
        }
        Write-Step '  Importing PFX into CurrentUser\My for this session...' Warn
        $secure = ConvertTo-SecureString -String $pwd -AsPlainText -Force
        $flags = [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable -bor
            [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::PersistKeySet
        $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($pfx, $secure, $flags)
        $store = [System.Security.Cryptography.X509Certificates.X509Store]::new('My', 'CurrentUser')
        $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
        try { $store.Add($cert) } finally { $store.Close() }
        $Thumbprint = $cert.Thumbprint
    }

    Connect-MgGraph -TenantId $ResourceTenant -ClientId $ClientId `
        -CertificateThumbprint $Thumbprint -NoWelcome -ErrorAction Stop
    $ctx = Get-MgContext
    Write-Step "  Connected AuthType=$($ctx.AuthType) TenantId=$($ctx.TenantId)" Ok

    $org = Invoke-MgGraphRequest -Method GET `
        -Uri 'https://graph.microsoft.com/v1.0/organization?$select=id,displayName,verifiedDomains' `
        -ErrorAction Stop
    $orgItem = @((Get-GraphObjectProperty -Object $org -PropertyName 'value')) | Select-Object -First 1
    $orgName = [string](Get-GraphObjectProperty -Object $orgItem -PropertyName 'displayName')
    $orgId = [string](Get-GraphObjectProperty -Object $orgItem -PropertyName 'id')

    $roles = Invoke-MgGraphRequest -Method GET `
        -Uri 'https://graph.microsoft.com/v1.0/directoryRoles?$select=id,displayName' `
        -ErrorAction Stop
    $roleCount = @((Get-GraphObjectProperty -Object $roles -PropertyName 'value')).Count

    Write-Host ''
    Write-Host '========== Smoke test OK ==========' -ForegroundColor Green
    Write-Host "BB organization: $orgName ($orgId)" -ForegroundColor Green
    Write-Host "directoryRoles readable: $roleCount" -ForegroundColor Green
    Write-Host '===================================' -ForegroundColor Green
}

#region Main
Write-Host 'B2B / cross-tenant Global Reader example' -ForegroundColor Cyan
Write-Host 'Note: uses Global Reader (read-only), not Global Administrator.' -ForegroundColor DarkGray

switch ($Mode) {
    'Home' {
        Invoke-HomeMode -HomeTenantId $TenantId -Name $DisplayName `
            -ValidMonths $CertValidMonths -OutDir $OutputPath
    }
    'Resource' {
        $resolvedAppId = Resolve-AppId -ExplicitAppId $AppId
        if ([string]::IsNullOrWhiteSpace($resolvedAppId)) {
            throw '-AppId is required for Resource mode (or set env B2B_GR_APP_ID from the Home helper).'
        }
        Invoke-ResourceMode -ResourceTenant $TenantId -ClientId $resolvedAppId
    }
    'Test' {
        if ([string]::IsNullOrWhiteSpace($ResourceTenantId)) {
            throw '-ResourceTenantId (BB) is required for Test mode.'
        }
        $resolvedAppId = Resolve-AppId -ExplicitAppId $AppId
        if ([string]::IsNullOrWhiteSpace($resolvedAppId)) {
            throw '-AppId is required for Test mode (or dot-source .b2b-global-reader.local.ps1).'
        }
        $thumb = Resolve-CertThumbprint
        if ([string]::IsNullOrWhiteSpace($thumb)) {
            throw 'Certificate thumbprint required. Dot-source .b2b-global-reader.local.ps1 or set B2B_GR_CERT_THUMBPRINT.'
        }
        Invoke-TestMode -HomeTenantId $TenantId -ResourceTenant $ResourceTenantId `
            -ClientId $resolvedAppId -Thumbprint $thumb
    }
}
#endregion
