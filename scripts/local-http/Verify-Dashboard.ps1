$ErrorActionPreference='Stop'
$s=Get-Content "$PSScriptRoot/settings.json" -Raw | ConvertFrom-Json
$session=New-Object Microsoft.PowerShell.Commands.WebRequestSession
function SubmitLocalKeycloak($url,$action,$user,$password) {
    $jar=Join-Path $PSScriptRoot ("cookies-"+[guid]::NewGuid().ToString('N')+".tmp")
    try {
        curl.exe --noproxy "*" -fsSL -c $jar -o NUL "$url"
        if($LASTEXITCODE){throw 'Keycloak form request failed'}
        # Refresh the form and cookie jar together.
        $html=(curl.exe --noproxy "*" -fsSL -c $jar "$url") -join "`n"
        $match=[regex]::Match($html,'<form\b[^>]*id="kc-form-login"[^>]*action="([^"]+)"')
        if(!$match.Success){ [regex]::Matches($html, '(?is)<(?:title|h1|p)[^>]*>([^<]+)</(?:title|h1|p)>') | ForEach-Object {$_.Groups[1].Value} | Write-Host; throw 'Keycloak form unavailable' }
        $target=[uri][Net.WebUtility]::HtmlDecode($match.Groups[1].Value)
        if(!$target.AbsoluteUri.StartsWith("$($s.issuer)/login-actions/",[StringComparison]::Ordinal)){throw 'Unexpected Keycloak form target'}
        $body="username=$([uri]::EscapeDataString($user))&password=$([uri]::EscapeDataString($password))&credentialId="
        $headers=($body | curl.exe --noproxy "*" -sS -b $jar -D - -o NUL -H 'Content-Type: application/x-www-form-urlencoded' --data-binary '@-' $target.AbsoluteUri) -join "`n"
        $location=[regex]::Match($headers,'(?im)^location:\s*([^\r\n]+)').Groups[1].Value.Trim()
        if(!$location){throw 'Keycloak did not return a login callback'}
        [pscustomobject]@{Headers=@{Location=$location};StatusCode=302}
    } finally { if(Test-Path -LiteralPath $jar){Remove-Item -LiteralPath $jar} }
}
$redirect=Invoke-WebRequest -NoProxy "$($s.gateway)/aneiang" -WebSession $session -MaximumRedirection 0 -SkipHttpErrorCheck -ErrorAction SilentlyContinue
$url=[uri]@($redirect.Headers.Location)[0]
if(!$url.AbsoluteUri.StartsWith("$($s.issuer)/protocol/openid-connect/auth?",[StringComparison]::Ordinal)){throw 'Unexpected authorization endpoint'}
$login=SubmitLocalKeycloak $url $null 'gateway-local-admin' $s.dashboardPassword
$callback=[uri]@($login.Headers.Location)[0]
if($callback.GetLeftPart([UriPartial]::Path) -ne "$($s.gateway)/signin-gateway-dashboard"){throw 'Unexpected OIDC callback'}
$result=Invoke-WebRequest -NoProxy $callback -WebSession $session -MaximumRedirection 0 -SkipHttpErrorCheck -ErrorAction SilentlyContinue
if([int]$result.StatusCode -ne 302){throw "OIDC callback returned HTTP $([int]$result.StatusCode)."}
$status=Invoke-RestMethod -NoProxy "$($s.gateway)/aneiang/api/auth/status" -WebSession $session
if($status.data.authMode -ne 'KeycloakSso'){throw 'Gateway did not report Keycloak SSO.'}
$dashboard=Invoke-WebRequest -NoProxy "$($s.gateway)/aneiang" -WebSession $session
if($dashboard.StatusCode -ne 200){throw 'Dashboard did not render.'}
'PASS live Keycloak code flow, Gateway session, IAM gateway.admin, and Dashboard HTTP 200.'
