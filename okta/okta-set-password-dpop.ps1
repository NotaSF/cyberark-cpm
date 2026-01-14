param(
  [Parameter(Mandatory=$true)][string]$OktaDomain,    # https://domain.okta.com
  [Parameter(Mandatory=$true)][string]$ClientId,      # woooo...
  [Parameter(Mandatory=$true)][string]$PfxPath,       # C:\...\okta.pfx
  [Parameter(Mandatory=$false)][string]$PfxPassword = "",
  [Parameter(Mandatory=$false)][string]$Scope = "okta.users.manage",
  [Parameter(Mandatory=$false)][string]$Kid = "",

  [Parameter(Mandatory=$true)][string]$UserLogin,     # user@company.com
  [Parameter(Mandatory=$true)][string]$NewPassword    # new password to set
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Base64UrlEncode([byte[]]$bytes) {
  ([Convert]::ToBase64String($bytes)).TrimEnd('=').Replace('+','-').Replace('/','_')
}

function Sha256B64Url([string]$s) {
  $sha = [System.Security.Cryptography.SHA256]::Create()
  try {
    $hash = $sha.ComputeHash([Text.Encoding]::ASCII.GetBytes($s))
    return Base64UrlEncode($hash)
  } finally {
    $sha.Dispose()
  }
}

function Export-RsaPublicJwk([System.Security.Cryptography.RSA]$Rsa) {
  $p = $Rsa.ExportParameters($false)
  @{ kty="RSA"; e=Base64UrlEncode($p.Exponent); n=Base64UrlEncode($p.Modulus) }
}

function New-Jwt([hashtable]$Header, [hashtable]$Payload, [System.Security.Cryptography.RSA]$Rsa) {
  $h = Base64UrlEncode([Text.Encoding]::UTF8.GetBytes(($Header  | ConvertTo-Json -Compress)))
  $p = Base64UrlEncode([Text.Encoding]::UTF8.GetBytes(($Payload | ConvertTo-Json -Compress)))
  $toSign = [Text.Encoding]::ASCII.GetBytes("$h.$p")

  $sig = $Rsa.SignData(
    $toSign,
    [System.Security.Cryptography.HashAlgorithmName]::SHA256,
    [System.Security.Cryptography.RSASignaturePadding]::Pkcs1
  )
  "$h.$p.$(Base64UrlEncode($sig))"
}

function New-ClientAssertionJwt([string]$ClientId,[string]$Audience,[System.Security.Cryptography.RSA]$Rsa,[string]$Kid) {
  $now = [DateTimeOffset]::UtcNow
  $header = @{ alg="RS256"; typ="JWT" }
  if ($Kid) { $header.kid = $Kid }

  $payload = @{
    iss=$ClientId; sub=$ClientId; aud=$Audience
    iat=[int]$now.ToUnixTimeSeconds()
    exp=[int]$now.AddMinutes(1).ToUnixTimeSeconds()
    jti=([Guid]::NewGuid().ToString())
  }

  New-Jwt -Header $header -Payload $payload -Rsa $Rsa
}

function New-DpopProofJwt {
  param(
    [Parameter(Mandatory=$true)][string]$Htm,
    [Parameter(Mandatory=$true)][string]$Htu,
    [Parameter(Mandatory=$true)][System.Security.Cryptography.RSA]$Rsa,
    [Parameter(Mandatory=$false)][string]$Nonce,
    [Parameter(Mandatory=$false)][string]$Ath
  )

  $now = [DateTimeOffset]::UtcNow
  $jwk = Export-RsaPublicJwk -Rsa $Rsa

  $header = @{ typ="dpop+jwt"; alg="RS256"; jwk=$jwk }

  $payload = @{
    htm = $Htm.ToUpperInvariant()
    htu = $Htu
    iat = [int]$now.ToUnixTimeSeconds()
    jti = ([Guid]::NewGuid().ToString())
  }
  if ($Nonce) { $payload.nonce = $Nonce }
  if ($Ath)   { $payload.ath   = $Ath }   # bind proof to access token for resource requests

  New-Jwt -Header $header -Payload $payload -Rsa $Rsa
}

function Invoke-DpopRequest {
  param(
    [string]$Method,
    [string]$Url,
    [System.Security.Cryptography.RSA]$Rsa,
    [string]$AccessToken,
    [string]$Body = $null,
    [hashtable]$ExtraHeaders = $null,
    [string]$Nonce = "",
    [switch]$IncludeAth
  )

  $ath = if ($IncludeAth) { Sha256B64Url $AccessToken } else { "" }

  # Okta DPoP htu strictness: use scheme+host+path only (no query)
    $u = [Uri]$Url
    $htu = $u.GetLeftPart([System.UriPartial]::Path)

    $dpop = New-DpopProofJwt -Htm $Method -Htu $htu -Rsa $Rsa -Nonce $Nonce -Ath $ath


  $headers = @{
    "Accept"        = "application/json"
    "Authorization" = "DPoP $AccessToken"
    "DPoP"          = $dpop
    "Content-Type" = "application/json"
  }
  if ($ExtraHeaders) {
    foreach ($k in $ExtraHeaders.Keys) { $headers[$k] = $ExtraHeaders[$k] }
  }

  $params = @{
    Method = $Method
    Uri    = $Url
    Headers = $headers
    SkipHttpErrorCheck = $true
  }
  if ($null -ne $Body) {
    $params["ContentType"] = "application/json"
    $params["Body"] = $Body
  }

  Invoke-WebRequest @params
}

function Get-OktaTokenDpop {
  param([string]$OktaDomain,[string]$ClientId,[System.Security.Cryptography.RSA]$Rsa,[string]$Scope,[string]$Kid)

  $OktaDomain = $OktaDomain.TrimEnd("/")
  $tokenUrl = "$OktaDomain/oauth2/v1/token"

  $attempt = {
    param($nonce)

    $clientAssertion = New-ClientAssertionJwt -ClientId $ClientId -Audience $tokenUrl -Rsa $Rsa -Kid $Kid

    $body =
      "grant_type=client_credentials" +
      "&scope=$([uri]::EscapeDataString($Scope))" +
      "&client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer" +
      "&client_assertion=$([uri]::EscapeDataString($clientAssertion))"

    $dpop = New-DpopProofJwt -Htm "POST" -Htu $tokenUrl -Rsa $Rsa -Nonce $nonce

    Invoke-WebRequest -Method POST -Uri $tokenUrl `
      -Headers @{ "DPoP" = $dpop; "Accept"="application/json" } `
      -ContentType "application/x-www-form-urlencoded" `
      -Body $body `
      -SkipHttpErrorCheck
  }

  $r1 = & $attempt ""
  if ($r1.StatusCode -eq 200) { return ($r1.Content | ConvertFrom-Json).access_token }

  $err = $null; try { $err = $r1.Content | ConvertFrom-Json } catch {}
  if ($r1.StatusCode -eq 400 -and $err -and $err.error -eq "use_dpop_nonce") {
    $nonce = @($r1.Headers["DPoP-Nonce"])[0]
    if (-not $nonce) { throw "Token endpoint required nonce but did not return DPoP-Nonce header." }
    $r2 = & $attempt $nonce
    if ($r2.StatusCode -eq 200) { return ($r2.Content | ConvertFrom-Json).access_token }
    throw ("Token retry failed. HTTP " + $r2.StatusCode + " Body: " + $r2.Content)
  }

  throw ("Token request failed. HTTP " + $r1.StatusCode + " Body: " + $r1.Content)
}

function Invoke-ResourceWithNonceRetry {
  param(
    [string]$Method,
    [string]$Url,
    [System.Security.Cryptography.RSA]$Rsa,
    [string]$AccessToken,
    [string]$Body = $null,
    [hashtable]$ExtraHeaders = $null
  )

  function Dump-Response($resp, $label) {
    Write-Host "---- $label ----"
    Write-Host ("URL: " + $Url)
    Write-Host ("HTTP: " + $resp.StatusCode)

    # Header names + key headers of interest
    try {
      $headerNames = @($resp.Headers.Keys) -join ", "
      Write-Host ("Headers: " + $headerNames)

      $dpopNonce = @($resp.Headers["DPoP-Nonce"])[0]
      if ($dpopNonce) { Write-Host ("DPoP-Nonce: " + $dpopNonce) }

      $wwwAuth = @($resp.Headers["WWW-Authenticate"])[0]
      if ($wwwAuth) { Write-Host ("WWW-Authenticate: " + $wwwAuth) }
    } catch {}

    # Raw content length (Content is sometimes empty in PS even when there is body)
    try {
      $rawLen = if ($resp.RawContent) { $resp.RawContent.Length } else { 0 }
      Write-Host ("RawContent length: " + $rawLen)
    } catch {}

    $contentOut = $resp.Content
    if (-not $contentOut -or $contentOut.Trim().Length -eq 0) {
      Write-Host "Body: <empty>"
    } else {
      Write-Host ("Body: " + $contentOut)
    }
    Write-Host "--------------"
  }

  $r1 = Invoke-DpopRequest -Method $Method -Url $Url -Rsa $Rsa -AccessToken $AccessToken -Body $Body -ExtraHeaders $ExtraHeaders -Nonce "" -IncludeAth

  if ($r1.StatusCode -ge 200 -and $r1.StatusCode -lt 300) { return $r1 }

  Dump-Response $r1 "RESOURCE FAIL (attempt 1)"

  $nonceHeader = @($r1.Headers["DPoP-Nonce"])[0]

  # Try JSON parse if present
  $err = $null
  try { $err = $r1.Content | ConvertFrom-Json } catch {}

  if ($r1.StatusCode -eq 400 -and ($nonceHeader -or ($err -and $err.error -eq "use_dpop_nonce"))) {
    if (-not $nonceHeader) {
      throw "Resource call indicates nonce required but DPoP-Nonce header is missing."
    }

    Write-Host "DPoP nonce requested; retrying resource call..."
    $r2 = Invoke-DpopRequest -Method $Method -Url $Url -Rsa $Rsa -AccessToken $AccessToken -Body $Body -ExtraHeaders $ExtraHeaders -Nonce $nonceHeader -IncludeAth

    if ($r2.StatusCode -ge 200 -and $r2.StatusCode -lt 300) { return $r2 }

    Dump-Response $r2 "RESOURCE FAIL (attempt 2)"
    throw "Resource retry failed."
  }

  throw "Resource request failed."
}



try {
  $OktaDomain = $OktaDomain.TrimEnd("/")

  $flags = [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable `
        -bor [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::MachineKeySet

  $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($PfxPath, $PfxPassword, $flags)
  $rsa  = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($cert)
  if (-not $rsa) { throw "No RSA private key available from PFX." }

  Write-Host "Getting DPoP access token..."
  $token = Get-OktaTokenDpop -OktaDomain $OktaDomain -ClientId $ClientId -Rsa $rsa -Scope $Scope -Kid $Kid

  Write-Host "Resolving user id for $UserLogin..."
  # Use filter query to avoid encoded-path issues with DPoP htu strictness
    $filter = 'profile.login eq "' + $UserLogin + '"'
    $userUrl = "$OktaDomain/api/v1/users?filter=$([uri]::EscapeDataString($filter))"

    $uResp = Invoke-ResourceWithNonceRetry -Method "GET" -Url $userUrl -Rsa $rsa -AccessToken $token
    $users = $uResp.Content | ConvertFrom-Json

    if (-not $users -or $users.Count -lt 1 -or -not $users[0].id) {
      throw "User not found for login '$UserLogin'."
    }

    $user = $users[0]


  Write-Host "Setting password for userId $($user.id)..."
  $setUrl = "$OktaDomain/api/v1/users/$($user.id)"
  $body = @{
    credentials = @{
      password = @{ value = $NewPassword }
    }
  } | ConvertTo-Json -Depth 5 -Compress

  $hdrs = @{ "Content-Type"="application/json" }
  $setResp = Invoke-ResourceWithNonceRetry -Method "POST" -Url $setUrl -Rsa $rsa -AccessToken $token -Body $body -ExtraHeaders $hdrs

  Write-Host "OK: password set for $UserLogin"
  exit 0
}
catch {
  Write-Error ("FAIL: " + $_.Exception.ToString())
  exit 1
}
