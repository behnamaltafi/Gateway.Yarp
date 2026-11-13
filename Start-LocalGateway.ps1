[CmdletBinding()]
param([switch]$VerifyLogin, [switch]$DependenciesOnly, [switch]$Http)

$ErrorActionPreference = 'Stop'
if ($PSVersionTable.PSVersion -lt [version]'7.4') {
    throw 'Run this script with PowerShell 7.4 or later (pwsh).'
}

$local = Join-Path $PSScriptRoot $(if ($Http) { '.gapcode/sso-http' } else { '.gapcode/sso-local' })
foreach ($file in 'settings.json', 'iam.json', 'application-id.txt', 'Start-Hosts.ps1') {
    if (!(Test-Path -LiteralPath (Join-Path $local $file) -PathType Leaf)) {
        throw "Missing local IAM setup file: $file. Restore the provisioned .gapcode/sso-local directory."
    }
}

$settings = Get-Content -LiteralPath (Join-Path $local 'settings.json') -Raw | ConvertFrom-Json
$running = docker inspect --type container --format '{{.State.Running}}' $settings.container
if ($LASTEXITCODE -ne 0) { throw 'Cannot inspect the provisioned Keycloak container. Check Docker Desktop and the local container.' }
if ($running -ne 'true') {
    docker start $settings.container | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Could not start the local Keycloak container.' }
}

& (Join-Path $local 'Start-Hosts.ps1')
if ($DependenciesOnly) { return }
& (Join-Path $local 'Start-Hosts.ps1') -SkipIam
if ($VerifyLogin) { & (Join-Path $local 'Verify-Dashboard.ps1') }

"Gateway Dashboard: $($settings.gateway)/aneiang"
"IAM Admin: $($settings.ui)/"
