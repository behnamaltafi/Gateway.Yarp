param([switch]$SkipIam,[switch]$ConfigureOnly)
$ErrorActionPreference='Stop'
$root=$PSScriptRoot
$s=Get-Content "$root/settings.json" -Raw | ConvertFrom-Json
$iam=$env:GATEWAY_IAM_SOURCE
$gateway=(Join-Path (Split-Path (Split-Path $root)) "samples/SampleGateway")
function WriteConfig($name,$config) {
    $config | ConvertTo-Json -Depth 20 | Set-Content "$root/$name.json" -Encoding utf8
}
function StartHost($name,$workingDir,$dll,$variables) {
    if (!(Test-Path -LiteralPath $dll -PathType Leaf)) { throw "Build output is missing for ${name}: $dll" }
    if (Test-Path "$root/$name.pid") {
        $processId=[int](Get-Content "$root/$name.pid")
        $running=Get-CimInstance Win32_Process -Filter "ProcessId=$processId"
        if ($running -and $running.Name -eq 'dotnet.exe' -and
            $running.CommandLine.Replace('\','/').Contains($dll, [StringComparison]::OrdinalIgnoreCase)) {
            Write-Host "$name is already running."
            return
        }
    }
    if (!$variables.ContainsKey('ASPNETCORE_ENVIRONMENT')) { $variables.ASPNETCORE_ENVIRONMENT='Development' }
    $p=Start-Process (Get-Command dotnet).Source -ArgumentList ('"' + $dll + '"') -WorkingDirectory $workingDir -Environment $variables -WindowStyle Hidden -PassThru -RedirectStandardOutput "$root/$name.out" -RedirectStandardError "$root/$name.err"
    Set-Content "$root/$name.pid" $p.Id
}
function WaitHttp($url,$status) {
    for($i=0;$i -lt 35;$i++) {
        try {
            $response=Invoke-WebRequest -NoProxy $url -TimeoutSec 3 -SkipHttpErrorCheck -MaximumRedirection 0 -ErrorAction SilentlyContinue
            if ([int]$response.StatusCode -eq $status) { return }
        } catch {}
        Start-Sleep -Milliseconds 800
    }
    throw "Expected HTTP $status from $url"
}
$tls=@{Subject='localhost';Store='My';Location='LocalMachine';AllowInvalid=$false}
if (!$SkipIam) {
    WaitHttp "$($s.issuer)/.well-known/openid-configuration" 200
    StartHost iam $root "$root/IamHost/IamHost.dll" @{IAM_LOCAL_SETTINGS="$root/iam.json";ASPNETCORE_ENVIRONMENT="Development";IAM_ALLOW_LOCAL_HTTP="1"}
    WaitHttp "$($s.api)/health/live" 200
    StartHost iam-admin "$root/AdminBuild" "$root/AdminBuild/IAM.Admin.dll" @{
        IAM_ALLOW_LOCAL_HTTP='1';ASPNETCORE_URLS=$s.ui;Oidc__Authority=$s.issuer;Oidc__ClientId='iam-admin-ui';Oidc__ClientSecret=$s.uiSecret;IamApi__BaseAddress=$s.api
        Kestrel__Certificates__Default__Subject='localhost';Kestrel__Certificates__Default__Store='My';Kestrel__Certificates__Default__Location='LocalMachine'
    }
    WaitHttp "$($s.ui)/" 200
    'IAM API and Admin available over loopback HTTP.'
    return
}
$application=(Get-Content "$root/application-id.txt" -Raw).Trim()
WriteConfig gateway @{
    AllowedHosts='localhost'
    Kestrel=@{Endpoints=@{Dashboard=@{Url=$s.gateway}};Certificates=@{Default=$tls}}
    Gateway=@{
        Deployment=@{Mode='AllInOne'}
        Dashboard=@{RoutePrefix='aneiang';Sso=@{Enabled=$true;Authority=$s.issuer;ClientId='gateway-dashboard';ManagementAudience='gateway-management';ApplicationId=$application;DataProtectionKeyPath="$root/keys"}}
        Storage=@{Sqlite=@{ConnectionString="Data Source=$root/gateway.sqlite"}}
        Iam=@{Enabled=$true;Authority=$s.issuer;Issuer=$s.issuer;Audience='lab-api';PolicyBundleEndpoint="$($s.api)/internal/v1/policy-bundles/current"
            EntitlementEndpoint="$($s.api)/internal/v1/entitlements/resolve";InternalTokenEndpoint="$($s.issuer)/protocol/openid-connect/token";InternalClientId='iam-gateway';IamTimeout='00:00:10';InternalClientSecret=$s.gatewaySecret}
    }
}
if ($ConfigureOnly) { return }
StartHost gateway $root "$root/GatewayBuild/SampleGateway.dll" @{
    IAM_LOCAL_SETTINGS="$root/gateway.json";GATEWAY_DASHBOARD_OIDC_CLIENT_SECRET=$s.dashboardSecret;ASPNETCORE_AUTO_BROWSER='0';GATEWAY_VISUAL_STUDIO_LOCAL='http-direct'
}
WaitHttp "$($s.gateway)/aneiang" 302
'Gateway Dashboard redirects to Keycloak.'
