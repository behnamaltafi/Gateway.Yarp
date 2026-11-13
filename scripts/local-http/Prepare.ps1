$ErrorActionPreference='Stop'
$root=$PSScriptRoot
$local=Join-Path (Split-Path $root) 'sso-local'
if (!$env:GATEWAY_IAM_SOURCE) { throw 'GATEWAY_IAM_SOURCE is required.' }
function NewSecret { [Convert]::ToHexString([Security.Cryptography.RandomNumberGenerator]::GetBytes(32)) }
if (Test-Path "$root/settings.json") {
    $s=Get-Content "$root/settings.json" -Raw | ConvertFrom-Json
} else {
    $s=@{
        id='gateway_http'; realm='gateway-local-http'; container='gateway-local-http'
        issuer='http://localhost:18445/realms/gateway-local-http'; api='http://localhost:17463'
        ui='http://localhost:17464'; gateway='http://localhost:17465'
        userId=[guid]::NewGuid().ToString(); dashboardUserId=[guid]::NewGuid().ToString(); gatewayId=[guid]::NewGuid().ToString()
        password='Bb@123123'; dashboardPassword='Bb@123123'
        uiSecret=(NewSecret); dashboardSecret=(NewSecret); gatewaySecret=(NewSecret)
    }
}
function JsonFile($path,$object) { $object | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $path -Encoding utf8 }
function Browser($id,$secret,$redirect,$audience) {
    $client=@{clientId=$id;secret=$secret;publicClient=(!$secret);standardFlowEnabled=$true;directAccessGrantsEnabled=$false;redirectUris=@($redirect);attributes=@{'pkce.code.challenge.method'='S256'};enabled=$true;protocol='openid-connect'}
    if ($audience) { $client.protocolMappers=@((Audience $audience)) }
    $client
}
function Audience($aud) { @{name=$aud;protocol='openid-connect';protocolMapper='oidc-audience-mapper';config=@{'included.custom.audience'=$aud;'access.token.claim'='true';'id.token.claim'='false'}} }
function User($id,$name,$password) { @{id=$id;username=$name;enabled=$true;firstName='Local';lastName='Admin';email="$name@example.invalid";emailVerified=$true;credentials=@(@{type='password';value=$password;temporary=$false})} }
$dashboard=Browser 'gateway-dashboard' $s.dashboardSecret "$($s.gateway)/signin-gateway-dashboard" ''
$dashboard.attributes['post.logout.redirect.uris']="$($s.gateway)/signout-gateway-dashboard"
$realm=@{realm=$s.realm;enabled=$true;sslRequired='none';clients=@(
    $dashboard
    (Browser 'iam-admin-ui' $s.uiSecret "$($s.ui)/signin-oidc" 'iam-admin')
    (Browser 'iam-lab-browser' '' "$($s.ui)/lab-token" 'iam-admin')
    @{clientId='iam-gateway';secret=$s.gatewaySecret;enabled=$true;protocol='openid-connect';serviceAccountsEnabled=$true;publicClient=$false;standardFlowEnabled=$false;directAccessGrantsEnabled=$false;protocolMappers=@((Audience 'iam-internal'))}
);users=@(
    (User $s.userId 'iam-test-admin' $s.password)
    (User $s.dashboardUserId 'gateway-local-admin' $s.dashboardPassword)
    @{id=$s.gatewayId;username='service-account-iam-gateway';enabled=$true;serviceAccountClientId='iam-gateway'}
)}
JsonFile "$root/settings.json" $s
if (!(docker ps -a --filter "name=^/$($s.container)$" --format '{{.Names}}')) {
    if ($LASTEXITCODE) { throw 'Docker is unavailable.' }
    New-Item -ItemType Directory -Force "$root/import" | Out-Null
    $realmFile="$root/import/$($s.realm)-realm.json"
    JsonFile $realmFile $realm
    docker create --name $s.container -p 127.0.0.1:18445:8080 quay.io/keycloak/keycloak:26.8.2 start-dev --hostname=http://localhost:18445 --import-realm | Out-Null
    if ($LASTEXITCODE) { throw 'Keycloak container creation failed.' }
    docker cp "$root/import" "$($s.container):/opt/keycloak/data/import"
    if ($LASTEXITCODE) { throw 'Keycloak realm copy failed.' }
    Remove-Item -LiteralPath $realmFile
}
docker start $s.container | Out-Null
if ($LASTEXITCODE) { throw 'Keycloak failed to start.' }
$ready=$false
for($i=0;$i -lt 40;$i++){
    try { if ((Invoke-WebRequest -NoProxy "$($s.issuer)/.well-known/openid-configuration" -TimeoutSec 2).StatusCode -eq 200) {$ready=$true;break} } catch{}
    Start-Sleep -Seconds 1
}
if(!$ready){throw 'Local HTTP realm discovery did not become ready.'}
$token=(Invoke-RestMethod -NoProxy "$($s.issuer)/protocol/openid-connect/token" -Method Post -Body @{grant_type='client_credentials';client_id='iam-gateway';client_secret=$s.gatewaySecret}).access_token
$part=$token.Split('.')[1].Replace('-','+').Replace('_','/')
$identity=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($part.PadRight([int](4 * [Math]::Ceiling($part.Length / 4.0)),'='))) | ConvertFrom-Json
$cfg=@{
  ServiceName='IAM.Api'; ExternalIntegrations=@{Enabled=$false}; ConnectionStrings=@{}
  Authentication=@{Audience='iam-admin'}
  InternalAuthentication=@{Audience='iam-internal'; AllowedRemoteAddresses=@('127.0.0.1','::1')}
}
$cfg.LocalHttp=$true
$cfg.ConnectionStrings.ApplicationDbContext="Server=$($env:GATEWAY_IAM_SQL_SERVER);Database=IAM_AuthorizationLab_gateway_http;Integrated Security=true;TrustServerCertificate=true"
$cfg.Kestrel=@{Endpoints=@{Http=@{Url=$s.api}}}
$cfg.Authentication.Authority=$s.issuer
$cfg.Authentication.TrustedPrincipalIssuers=@($s.issuer)
$cfg.InternalAuthentication.Authority=$s.issuer
$cfg.InternalAuthentication.Callers=@(@{Issuer=$s.issuer;Subject=$identity.sub;ClientId='iam-gateway'})
$cfg.Bootstrap=@{Enabled=$true;Issuer=$s.issuer;Subject=$s.userId}
JsonFile "$root/iam.json" $cfg
$env:IAM_DESIGN_CONNECTION=$cfg.ConnectionStrings.ApplicationDbContext
Push-Location $env:GATEWAY_IAM_SOURCE
try {
    & "$root/tools/dotnet-ef.exe" database update --project IAM.Infrastructure --startup-project IAM.Infrastructure --no-build
    if ($LASTEXITCODE) { throw 'HTTP lab migration failed.' }
} finally { Pop-Location }
$env:ASPNETCORE_ENVIRONMENT='Development'
$env:IAM_ALLOW_LOCAL_HTTP='1'
$env:IAM_LOCAL_SETTINGS="$root/iam.json"
Push-Location $root
try {
    dotnet "$env:GATEWAY_IAM_SOURCE/IAM.Api/bin/Debug/net10.0/IAM.Api.dll" --bootstrap-admin
    if($LASTEXITCODE){throw 'HTTP lab IAM bootstrap failed.'}
} finally { Pop-Location }
$cfg.Bootstrap.Enabled=$false
JsonFile "$root/iam.json" $cfg
