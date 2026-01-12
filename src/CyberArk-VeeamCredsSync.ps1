<#
.SYNOPSIS
  Sync CyberArk AIM secrets into Veeam Backup & Replication Credentials Manager.

.DESCRIPTION
  For each CyberArk "Object" you provide, this script fetches the secret via the
  CyberArk AIM WebService endpoint and then adds/updates a Linux credential inside
  Veeam Backup & Replication.

  ✅ Supports PS 5.1 and PS 7+
  ✅ Supports objects inline or via an objects file
  ✅ Does NOT log passwords
  ✅ Safe matching logic: updates by UserName + "Object=<name>" in Description

  Run on the Veeam Backup & Replication server (or a server with the Veeam PS module).

.PARAMETER CyberArkServer
  CyberArk AIM host or URL.
  Examples:
    cyberark.example.com
    https://cyberark.example.com
    https://cyberark.example.com:8443

.PARAMETER AppID
  CyberArk Application ID configured for AIM access.

.PARAMETER Safe
  CyberArk Safe containing accounts.

.PARAMETER Folder
  CyberArk folder (default: Root)

.PARAMETER Objects
  One or more CyberArk object names.

.PARAMETER ObjectsFile
  Path to a text file containing CyberArk object names, one per line.

.PARAMETER AIMPath
  AIM endpoint path (default: /AIMWebService/api/Accounts)

.PARAMETER LogFile
  Log file path (default: C:\Logs\CyberArk_VeeamCredsSync.log)

.PARAMETER TimeoutSec
  HTTP timeout seconds (default: 60)

.PARAMETER SkipCertificateCheck
  Bypass TLS validation (NOT recommended). Use only if needed in lab environments.

.EXAMPLE
  pwsh .\src\CyberArk-VeeamCredsSync.ps1 `
    -CyberArkServer "cyberark.example.com" `
    -AppID "MY_APPID" `
    -Safe "LinuxSafe" `
    -Folder "Root" `
    -ObjectsFile ".\examples\objects.txt"

.EXAMPLE
  pwsh .\src\CyberArk-VeeamCredsSync.ps1 `
    -CyberArkServer "https://cyberark.example.com:8443" `
    -AppID "MY_APPID" `
    -Safe "LinuxSafe" `
    -Objects "linux-host01","linux-host02" `
    -SkipCertificateCheck

.NOTES
  - Recommended: Use valid TLS certificates rather than bypassing validation.
  - Requires Veeam.Backup.PowerShell module (Veeam Backup & Replication).
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string]$CyberArkServer,
    [Parameter(Mandatory)] [string]$AppID,
    [Parameter(Mandatory)] [string]$Safe,
    [Parameter()] [string]$Folder = 'Root',

    [Parameter()] [string[]]$Objects,
    [Parameter()] [string]$ObjectsFile,

    [Parameter()] [string]$AIMPath = '/AIMWebService/api/Accounts',
    [Parameter()] [int]$TimeoutSec = 60,

    [Parameter()] [string]$LogFile = 'C:\Logs\CyberArk_VeeamCredsSync.log',
    [Parameter()] [switch]$SkipCertificateCheck
)

# -------------------------
# Helpers: Input Resolution
# -------------------------
function Resolve-Objects {
    param([string[]]$Objects, [string]$ObjectsFile)

    $all = @()

    if ($ObjectsFile) {
        if (-not (Test-Path -LiteralPath $ObjectsFile)) {
            throw "ObjectsFile not found: $ObjectsFile"
        }
        $all += Get-Content -LiteralPath $ObjectsFile -ErrorAction Stop
    }

    if ($Objects) {
        $all += $Objects
    }

    # If nothing provided, allow interactive entry
    if (-not $all -or $all.Count -eq 0) {
        $inputValue = Read-Host "Enter CyberArk Object names (comma-separated) OR a path to a .txt file"
        if ([string]::IsNullOrWhiteSpace($inputValue)) { throw "No objects provided." }

        if (Test-Path -LiteralPath $inputValue) {
            $all += Get-Content -LiteralPath $inputValue -ErrorAction Stop
        } else {
            $all += ($inputValue -split ',')
        }
    }

    $all |
        ForEach-Object { $_.Trim() } |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
        Sort-Object -Unique
}

$Objects = Resolve-Objects -Objects $Objects -ObjectsFile $ObjectsFile

# -------------------------
# Logging
# -------------------------
if (-not (Test-Path (Split-Path $LogFile))) {
    New-Item -ItemType Directory -Path (Split-Path $LogFile) -Force | Out-Null
}

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    $line = "$timestamp [$Level] $Message"
    Add-Content -Path $LogFile -Value $line
    Write-Host $line
}

# -------------------------
# HTTP + TLS settings
# -------------------------
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Only bypass TLS validation if explicitly requested (not recommended)
if ($SkipCertificateCheck) {
    if ($PSVersionTable.PSVersion.Major -ge 7) {
        # handled by Invoke-RestMethod parameter
        Write-Log "WARNING: TLS certificate validation is DISABLED (SkipCertificateCheck enabled)." "WARN"
    } else {
        add-type @"
using System.Net;
using System.Security.Cryptography.X509Certificates;
public class TrustAllCertsPolicy : ICertificatePolicy {
    public bool CheckValidationResult(ServicePoint p, X509Certificate c, WebRequest r, int problem) { return true; }
}
"@
        [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
        Write-Log "WARNING: TLS certificate validation is DISABLED (SkipCertificateCheck enabled)." "WARN"
    }
}

$Headers = @{ Accept = 'application/json' }
$BaseInvoke = @{
    Method     = 'GET'
    Headers    = $Headers
    TimeoutSec = $TimeoutSec
}

if ($PSVersionTable.PSVersion.Major -ge 7 -and $SkipCertificateCheck) {
    $BaseInvoke['SkipCertificateCheck'] = $true
}

function Get-ObjectUrl([string]$ObjectName) {
    $base = $CyberArkServer.Trim().TrimEnd('/')
    if ($base -notmatch '^https?://') { $base = "https://$base" }

    $path = $AIMPath.Trim()
    if (-not $path.StartsWith('/')) { $path = "/$path" }

    $encoded = [uri]::EscapeDataString($ObjectName)
    "$base$path?AppID=$AppID&Safe=$Safe&Folder=$Folder&Object=$encoded"
}

function Invoke-CyberArk([string]$Url) {
    try {
        Invoke-RestMethod @BaseInvoke -Uri $Url -ErrorAction Stop
    } catch {
        $resp = $_.Exception.Response
        if ($resp) {
            $status = [int]$resp.StatusCode
            try {
                $sr = New-Object System.IO.StreamReader($resp.GetResponseStream())
                $body = $sr.ReadToEnd()
            } catch {
                $body = "<unable to read response body>"
            }
            Write-Log ("CyberArk request failed. Status={0}. Url={1}. Body={2}" -f $status, $Url, $body) "WARN"
        } else {
            Write-Log ("CyberArk request failed. Url={0}. Error={1}" -f $Url, $_.Exception.Message) "WARN"
        }
        $null
    }
}

# -------------------------
# Veeam helper
# -------------------------
function Ensure-VeeamLinuxCredential {
    param(
        [Parameter(Mandatory)] [string]$UserName,
        [Parameter(Mandatory)] [securestring]$PasswordSecure,
        [Parameter(Mandatory)] [string]$ObjectName,
        [Parameter(Mandatory)] [string]$Description
    )

    # Match existing credentials by:
    # - Type Linux
    # - Same username
    # - Contains Object=<ObjectName> in Description
    $existing = Get-VBRCredentials | Where-Object {
        $_.Type -eq 'Linux' -and
        $_.UserName -eq $UserName -and
        $_.Description -like "*Object=$ObjectName*"
    }

    if ($existing) {
        try {
            Set-VBRCredentials -Credentials $existing[0] -Password $PasswordSecure -Description $Description -ErrorAction Stop
            Write-Log ("Updated Veeam credential: {0} (Object={1})" -f $UserName, $ObjectName)
            return "Updated"
        } catch {
            Write-Log ("Update failed for {0} (Object={1}): {2}" -f $UserName, $ObjectName, $_.Exception.Message) "WARN"
            return "Failed"
        }
    } else {
        try {
            $new = Add-VBRCredentials -Type Linux -User $UserName -Password $PasswordSecure -Description $Description -ErrorAction Stop
            Write-Log ("Added Veeam credential: {0} (Object={1})" -f $new.UserName, $ObjectName)
            return "Added"
        } catch {
            Write-Log ("Add failed for {0} (Object={1}): {2}" -f $UserName, $ObjectName, $_.Exception.Message) "ERROR"
            return "Failed"
        }
    }
}

# -------------------------
# Main
# -------------------------
try {
    if (-not $Objects -or $Objects.Count -eq 0) { throw "No objects provided." }

    Import-Module Veeam.Backup.PowerShell -ErrorAction Stop

    $Results = @()

    foreach ($ObjectName in $Objects) {
        $url  = Get-ObjectUrl $ObjectName
        $resp = Invoke-CyberArk $url

        if (-not $resp) {
            $Results += [pscustomobject]@{ Object=$ObjectName; User=""; Status="Failed" }
            Write-Log ("{0}: no response from CyberArk" -f $ObjectName) "WARN"
            continue
        }

        # Parse response (JSON preferred, XML fallback)
        $UserName = $null
        $PasswordPlain = $null

        if ($null -ne $resp.UserName -or $null -ne $resp.Content) {
            # JSON-like object
            $UserName      = [string]$resp.UserName
            $PasswordPlain = [string]$resp.Content
        } else {
            # XML fallback
            try {
                [xml]$xml = $resp
                $UserName      = $xml.SelectSingleNode('//UserName').InnerText
                $PasswordPlain = $xml.SelectSingleNode('//Content').InnerText
            } catch {
                Write-Log ("{0}: unrecognized response format from CyberArk" -f $ObjectName) "WARN"
            }
        }

        if ([string]::IsNullOrWhiteSpace($UserName) -or [string]::IsNullOrWhiteSpace($PasswordPlain)) {
            $Results += [pscustomobject]@{ Object=$ObjectName; User=$UserName; Status="Skipped" }
            Write-Log ("{0}: missing UserName or Content. Skipping." -f $ObjectName) "WARN"
            continue
        }

        $PasswordSecure = ConvertTo-SecureString $PasswordPlain -AsPlainText -Force
        $PasswordPlain = $null  # best-effort plaintext cleanup

        # Standardized description (used for matching later)
        $Description = "CyberArk | Object=$ObjectName | Safe=$Safe | User=$UserName"

        $status = Ensure-VeeamLinuxCredential -UserName $UserName -PasswordSecure $PasswordSecure -ObjectName $ObjectName -Description $Description
        $Results += [pscustomobject]@{ Object=$ObjectName; User=$UserName; Status=$status }
    }

    Write-Host "`nSummary Report:"
    $Results | Format-Table -AutoSize

    $ok      = ($Results | Where-Object { $_.Status -in @("Added","Updated") }).Count
    $skipped = ($Results | Where-Object { $_.Status -eq "Skipped" }).Count
    $failed  = ($Results | Where-Object { $_.Status -eq "Failed" }).Count

    Write-Host "`nTotals"
    Write-Host ("Successful : {0}" -f $ok)
    Write-Host ("Skipped    : {0}" -f $skipped)
    Write-Host ("Failed     : {0}" -f $failed)

    Write-Log ("Summary → Successful: {0} | Skipped: {1} | Failed: {2}" -f $ok, $skipped, $failed)
}
catch {
    Write-Error ("Fatal error: {0}" -f $_.Exception.Message)
    Write-Log ("Fatal error: {0}" -f $_.Exception.Message) "ERROR"
    exit 1
}
