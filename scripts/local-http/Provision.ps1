$ErrorActionPreference='Stop'
$root=$PSScriptRoot
$s=Get-Content "$root/settings.json" -Raw | ConvertFrom-Json
$base=$s.issuer
$session=New-Object Microsoft.PowerShell.Commands.WebRequestSession
function SubmitLocalKeycloak($url,$action,$user,$password) {
    $jar=Join-Path $PSScriptRoot ("cookies-"+[guid]::NewGuid().ToString('N')+".tmp")
    try {
        curl.exe --noproxy "*" -fsS -c $jar -o NUL $url
        if($LASTEXITCODE){throw 'Keycloak form request failed'}
        # Refresh the form and cookie jar together.
        $html=(curl.exe --noproxy "*" -fsS -c $jar $url) -join "`n"
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
$verifier=[Convert]::ToHexString([Security.Cryptography.RandomNumberGenerator]::GetBytes(32))
$challenge=[Convert]::ToBase64String([Security.Cryptography.SHA256]::HashData([Text.Encoding]::ASCII.GetBytes($verifier))).TrimEnd('=').Replace('+','-').Replace('/','_')
$redirect="$($s.ui)/lab-token"
$state=[guid]::NewGuid().ToString('N')
$start="$base/protocol/openid-connect/auth?client_id=iam-lab-browser&response_type=code&scope=openid&redirect_uri=$([uri]::EscapeDataString($redirect))&code_challenge=$challenge&code_challenge_method=S256&state=$state"
$login=SubmitLocalKeycloak $start $null 'iam-test-admin' $s.password
if(!$login.Headers.Location){ [regex]::Matches($login.Content,'(?is)<(?:title|h1|p)[^>]*>([^<]+)</(?:title|h1|p)>') | ForEach-Object {$_.Groups[1].Value} | Write-Host; throw "Keycloak login returned HTTP $([int]$login.StatusCode)"}
$callback=[uri]@($login.Headers.Location)[0]
if($callback.GetLeftPart([UriPartial]::Path) -ne $redirect){throw 'Unexpected PKCE callback'}
$query=@{}
foreach($pair in $callback.Query.TrimStart('?').Split('&')) { $pieces=$pair.Split('=',2); $query[$pieces[0]]=[uri]::UnescapeDataString($pieces[1]) }
if($query.state -ne $state -or !$query.code){throw 'Invalid PKCE callback'}
$token=(Invoke-RestMethod -NoProxy "$base/protocol/openid-connect/token" -Method Post -Body @{grant_type='authorization_code';client_id='iam-lab-browser';redirect_uri=$redirect;code=$query.code;code_verifier=$verifier}).access_token
function Iam($method,$path,$body=$null) {
    $request=@{Uri="$($s.api)/api/v1/$path";Method=$method;Headers=@{Authorization="Bearer $token"}}
    if($null -ne $body){$request.ContentType='application/json';$request.Body=($body|ConvertTo-Json -Depth 10 -Compress)}
    $reply=Invoke-RestMethod -NoProxy -AllowUnencryptedAuthentication @request
    if(!$reply.isSuccess){throw "IAM rejected $method $path"}
    $reply.data
}
$application=(Iam Get 'applications').items | Where-Object code -eq 'gateway-management'
if(!$application){$application=Iam Post 'applications' @{code='gateway-management';name='Local Gateway Management'}}
$permission=(Iam Get "permissions?applicationId=$($application.id)").items | Where-Object code -eq 'gateway.admin'
if(!$permission){$permission=Iam Post 'permissions' @{applicationId=$application.id;code='gateway.admin';name='Gateway administrator'}}
$principal=(Iam Get 'principals').items | Where-Object subject -eq $s.dashboardUserId
if(!$principal){$principal=Iam Post 'principals/user-mappings' @{issuer=$base;subject=$s.dashboardUserId}}
$null=Iam Put "principals/$($principal.id)/direct-permissions" @{applicationId=$application.id;rowVersion=$principal.rowVersion;grants=@(@{targetId=$permission.id;scopeKind='Global'})}
Set-Content "$root/application-id.txt" $application.id
'IAM registered the Dashboard user and assigned Global gateway.admin.'
