<#
Okta-Reconcile.ps1 (CPM/TPC-ready)

Purpose:
  Reconcile-only password reset for an Okta user using:
    - OAuth 2.0 Client Credentials
    - private_key_jwt client authentication
    - DPoP (including nonce challenge)
  Loads signing key from a SINGLE CyberArk string:
    PfxBundle = "<base64_pfx>::<pfx_password>"
  If no PFX password, use "<base64_pfx>::"

Run requirements:
  - PowerShell 7+ (pwsh.exe)

Exit codes:
  0 = success
  1 = failure
#>

[CmdletBinding()]
param(
  # Managed account
  [Parameter(Mandatory=$true)][string]$OktaDomain,     # e.g. https://yourorg.okta.com
  [Parameter(Mandatory=$true)][string]$ManagedLogin,   # user@domain.com
  [Parameter(Mandatory=$true)][string]$NewPassword,    # CPM-generated new password

  # Reconcile account
  [Parameter(Mandatory=$true)][string]$ClientId,       # Okta service app client_id
  [Parameter(Mandatory=$true)][string]$PfxBundle,      # "<base64_pfx>::<pfx_password>" or "<base64_pfx>::"

  # Optional
  [string]$Scope = "okta.users.manage",
  [string]$Kid = ""                                    # if your Okta app key requires 'kid'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# --- helpers ---
function Base64UrlEncode([byte[]]$bytes) {
  ([Convert]::ToBase64String($bytes)).TrimEnd('=').Replace('+','-').Replace('/','_')
}

function Sha256B64Url([string]$s) {
  $sha = [System.Security.Cryptography.SHA256]::Create()
  try {
    $hash = $sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($s))
    return Base64UrlEncode($hash)
  } finally { $sha.Dispose() }
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
  if ($Kid -and $Kid.Trim().Length -gt 0) { $header.kid = $Kid }

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
    [string]$Nonce = "",
    [string]$Ath = ""
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
  if ($Nonce -and $Nonce.Trim().Length -gt 0) { $payload.nonce = $Nonce }
  if ($Ath   -and $Ath.Trim().Length -gt 0)   { $payload.ath   = $Ath }

  New-Jwt -Header $header -Payload $payload -Rsa $Rsa
}

function Parse-PfxBundle([string]$bundle) {
  $parts = $bundle.Split("::", 2, [System.StringSplitOptions]::None)
  if (-not $parts -or -not $parts[0] -or $parts[0].Trim().Length -eq 0) {
    throw "PfxBundle is missing base64 PFX data."
  }
  $pfxB64 = $parts[0]
  $pfxPass = if ($parts.Count -gt 1) { $parts[1] } else { "" }
  return @{ PfxB64 = $pfxB64; PfxPass = $pfxPass }
}

function Load-RsaFromPfxBundle([string]$bundle) {
  $p = Parse-PfxBundle $bundle
  $pfxBytes = [Convert]::FromBase64String($p.PfxB64)

  $flags = [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable `
        -bor [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::MachineKeySet

  $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($pfxBytes, $p.PfxPass, $flags)
  if (-not $cert.HasPrivateKey) { throw "PFX loaded but does not contain a private key." }

  $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($cert)
  if (-not $rsa) { throw "Unable to access RSA private key from PFX." }
  return $rsa
}

function Get-CanonicalHtu([string]$url) {
  # Okta DPoP: htu must be scheme+host+path only (no query)
  $u = [Uri]$url
  $u.GetLeftPart([System.UriPartial]::Path)
}

function Invoke-WebRequestSafe {
  param(
    [Parameter(Mandatory=$true)][string]$Method,
    [Parameter(Mandatory=$true)][string]$Url,
    [hashtable]$Headers,
    [string]$ContentType = $null,
    [string]$Body = $null
  )

  $args = @{
    Method = $Method
    Uri = $Url
    Headers = $Headers
    SkipHttpErrorCheck = $true
  }
  if ($ContentType) { $args.ContentType = $ContentType }
  if ($null -ne $Body) { $args.Body = $Body }
  Invoke-WebRequest @args
}

function Get-DpopNonceFromHeaders($resp) {
  @($resp.Headers["DPoP-Nonce"])[0]
}

function Get-OktaTokenDpop {
  param(
    [string]$OktaDomain,
    [string]$ClientId,
    [System.Security.Cryptography.RSA]$Rsa,
    [string]$Scope,
    [string]$Kid
  )

  $OktaDomain = $OktaDomain.TrimEnd("/")
  $tokenUrl = "$OktaDomain/oauth2/v1/token"
  $htu = Get-CanonicalHtu $tokenUrl

  function AttemptToken([string]$nonce) {
    $clientAssertion = New-ClientAssertionJwt -ClientId $ClientId -Audience $tokenUrl -Rsa $Rsa -Kid $Kid
    $dpop = New-DpopProofJwt -Htm "POST" -Htu $htu -Rsa $Rsa -Nonce $nonce

    $body =
      "grant_type=client_credentials" +
      "&scope=$([uri]::EscapeDataString($Scope))" +
      "&client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer" +
      "&client_assertion=$([uri]::EscapeDataString($clientAssertion))"

    Invoke-WebRequestSafe -Method "POST" -Url $tokenUrl `
      -Headers @{ "DPoP"=$dpop; "Accept"="application/json" } `
      -ContentType "application/x-www-form-urlencoded" `
      -Body $body
  }

  $r1 = AttemptToken ""
  if ($r1.StatusCode -eq 200) {
    return ($r1.Content | ConvertFrom-Json).access_token
  }

  $nonce = Get-DpopNonceFromHeaders $r1
  $err = $null; try { $err = $r1.Content | ConvertFrom-Json } catch {}

  if ($r1.StatusCode -eq 400 -and ($nonce -or ($err -and $err.error -eq "use_dpop_nonce"))) {
    if (-not $nonce) { throw "Token endpoint required nonce but did not return DPoP-Nonce header." }
    $r2 = AttemptToken $nonce
    if ($r2.StatusCode -eq 200) {
      return ($r2.Content | ConvertFrom-Json).access_token
    }
    throw ("Token retry failed. HTTP {0} Body: {1}" -f $r2.StatusCode, ($r2.Content ?? "<empty>"))
  }

  throw ("Token request failed. HTTP {0} Body: {1}" -f $r1.StatusCode, ($r1.Content ?? "<empty>"))
}

function Invoke-DpopResourceWithNonceRetry {
  param(
    [string]$Method,
    [string]$Url,
    [System.Security.Cryptography.RSA]$Rsa,
    [string]$AccessToken,
    [string]$Body = $null,
    [hashtable]$ExtraHeaders = $null
  )

  $htu = Get-CanonicalHtu $Url
  $ath = Sha256B64Url $AccessToken

  function Attempt([string]$nonce) {
    $dpop = New-DpopProofJwt -Htm $Method -Htu $htu -Rsa $Rsa -Nonce $nonce -Ath $ath

    $headers = @{
      "Accept" = "application/json"
      "Authorization" = "DPoP $AccessToken"
      "DPoP" = $dpop
    }
    if ($ExtraHeaders) {
      foreach ($k in $ExtraHeaders.Keys) { $headers[$k] = $ExtraHeaders[$k] }
    }

    if ($null -ne $Body) {
      return Invoke-WebRequestSafe -Method $Method -Url $Url -Headers $headers -ContentType "application/json" -Body $Body
    } else {
      return Invoke-WebRequestSafe -Method $Method -Url $Url -Headers $headers
    }
  }

  $r1 = Attempt ""
  if ($r1.StatusCode -ge 200 -and $r1.StatusCode -lt 300) { return $r1 }

  $nonce = Get-DpopNonceFromHeaders $r1
  $err = $null; try { $err = $r1.Content | ConvertFrom-Json } catch {}

  if ($r1.StatusCode -eq 400 -and ($nonce -or ($err -and $err.error -eq "use_dpop_nonce"))) {
    if (-not $nonce) { throw "Resource call required nonce but did not return DPoP-Nonce header." }
    $r2 = Attempt $nonce
    if ($r2.StatusCode -ge 200 -and $r2.StatusCode -lt 300) { return $r2 }
    $b2 = $r2.Content; if (-not $b2 -or $b2.Trim().Length -eq 0) { $b2 = "<empty>" }
    throw ("Resource retry failed. HTTP {0} Body: {1}" -f $r2.StatusCode, $b2)
  }

  $b1 = $r1.Content; if (-not $b1 -or $b1.Trim().Length -eq 0) { $b1 = "<empty>" }
  throw ("Resource request failed. HTTP {0} Body: {1}" -f $r1.StatusCode, $b1)
}

# --- main ---
try {
  if ($PSVersionTable.PSEdition -ne 'Core') {
    throw "This script must be run with PowerShell 7+ (pwsh.exe)."
  }

  # Normalize OktaDomain (CPM passes https://ADDRESS, but be defensive)
  if ($OktaDomain -notmatch '^https?://') {
    $OktaDomain = "https://$OktaDomain"
  }
  $OktaDomain = $OktaDomain.TrimEnd('/')


  $rsa = Load-RsaFromPfxBundle -bundle $PfxBundle

  # 1) Acquire DPoP token
  $token = Get-OktaTokenDpop -OktaDomain $OktaDomain -ClientId $ClientId -Rsa $rsa -Scope $Scope -Kid $Kid
  if (-not $token) { throw "Failed to acquire access token." }

  # 2) Resolve user by login (direct endpoint)
  $userUrl = "$OktaDomain/api/v1/users/$([uri]::EscapeDataString($ManagedLogin))"
  $uResp = Invoke-DpopResourceWithNonceRetry -Method "GET" -Url $userUrl -Rsa $rsa -AccessToken $token
  $user = $uResp.Content | ConvertFrom-Json
  if (-not $user -or -not $user.id) {
    throw "User not found or unreadable for login '$ManagedLogin'."
  }

  # 3) Set password (admin set)
  $setUrl = "$OktaDomain/api/v1/users/$($user.id)"
  $payload = @{
    credentials = @{
      password = @{ value = $NewPassword }
    }
  } | ConvertTo-Json -Depth 6 -Compress

  $null = Invoke-DpopResourceWithNonceRetry -Method "POST" -Url $setUrl -Rsa $rsa -AccessToken $token -Body $payload -ExtraHeaders @{ "Content-Type"="application/json" }

  Write-Host "OK"
  exit 0
}
catch {
  # CPM-friendly: single-line error
  $msg = $_.Exception.Message
  if (-not $msg -or $msg.Trim().Length -eq 0) { $msg = $_.ToString() }
  Write-Error $msg
  exit 1
}
