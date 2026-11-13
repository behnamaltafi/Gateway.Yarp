#requires -Version 7.4
[CmdletBinding()]
param(
    [string]$IamPath = (Join-Path $PSScriptRoot '../../IAM'),
    [string]$SqlServer = '.\MSSQLSERVER2'
)

$ErrorActionPreference = 'Stop'
$workspace = Split-Path $PSScriptRoot
$source = Join-Path $PSScriptRoot 'local-http'
$runtime = Join-Path $workspace '.gapcode/sso-http'
$env:GATEWAY_IAM_SOURCE = (Resolve-Path -LiteralPath $IamPath).Path
$env:GATEWAY_IAM_SQL_SERVER = $SqlServer
[IO.Directory]::CreateDirectory($runtime) | Out-Null
$acl = [Security.AccessControl.DirectorySecurity]::new()
$acl.SetAccessRuleProtection($true, $false)
foreach ($sid in @([Security.Principal.WindowsIdentity]::GetCurrent().User, [Security.Principal.SecurityIdentifier]'S-1-5-18')) {
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($sid, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow'))
}
Set-Acl -LiteralPath $runtime -AclObject $acl
Copy-Item "$source/*.ps1" -Destination $runtime
function InvokeDotnet {
    dotnet @args
    if ($LASTEXITCODE) { throw "dotnet failed with exit code $LASTEXITCODE" }
}
InvokeDotnet build "$env:GATEWAY_IAM_SOURCE/IAM.Api/IAM.Api.csproj" -m:1
InvokeDotnet build "$env:GATEWAY_IAM_SOURCE/IAM.Admin/IAM.Admin.csproj" -m:1 -o "$runtime/AdminBuild"
InvokeDotnet build "$source/IamHost/IamHost.csproj" "-p:IamSource=$env:GATEWAY_IAM_SOURCE" -m:1 -o "$runtime/IamHost"
InvokeDotnet build "$workspace/samples/SampleGateway/SampleGateway.csproj" -m:1 -o "$runtime/GatewayBuild"
if (!(Test-Path "$runtime/tools/dotnet-ef.exe")) {
    InvokeDotnet tool install dotnet-ef --version 10.0.12 --tool-path "$runtime/tools"
}
if (!(Test-Path "$runtime/application-id.txt")) {
    & "$runtime/Prepare.ps1"
    & "$runtime/Start-Hosts.ps1"
    & "$runtime/Provision.ps1"
}
& "$runtime/Start-Hosts.ps1" -SkipIam -ConfigureOnly
'Local profile ready. Use SampleGateway Local HTTP in Visual Studio or Start-LocalGateway.ps1 -Http.'
