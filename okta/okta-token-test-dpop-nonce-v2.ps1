param(
  [Parameter(Mandatory=$true)][string]$OktaDomain,
  [Parameter(Mandatory=$true)][string]$ClientId,
  [Parameter(Mandatory=$true)][string]$PfxPath,
  [Parameter(Mandatory=$false)][string]$PfxPassword = "",
  [Parameter(Mandatory=$false)][string]$Scope = "okta.users.manage",
  [Parameter(Mandatory=$false)][string]$Kid = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Base64UrlEncode([byte[]]$bytes) {
  ([Convert]::ToBase64String($bytes)).TrimEnd('=').Replace('+','-').Replace('/','_')
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
    jti=([Guid]::NewGuid().ToString())   # NEW EACH TIME
  }

  New-Jwt -Header $header -Payload $payload -Rsa $Rsa
}

function New-DpopProofJwt([string]$Htm,[string]$Htu,[System.Security.Cryptography.RSA]$Rsa,[string]$Nonce) {
  $now = [DateTimeOffset]::UtcNow
  $jwk = Export-RsaPublicJwk -Rsa $Rsa

  $header = @{ typ="dpop+jwt"; alg="RS256"; jwk=$jwk }

  $payload = @{
    htm = $Htm.ToUpperInvariant()
    htu = $Htu
    iat = [int]$now.ToUnixTimeSeconds()
    jti = ([Guid]::NewGuid().ToString()) # NEW EACH TIME
  }
  if ($Nonce) { $payload.nonce = $Nonce }

  New-Jwt -Header $header -Payload $payload -Rsa $Rsa
}

function Invoke-TokenAttempt {
  param(
    [string]$TokenUrl,
    [string]$OktaDomain,
    [string]$ClientId,
    [string]$Scope,
    [System.Security.Cryptography.RSA]$Rsa,
    [string]$Kid,
    [string]$Nonce
  )

  # IMPORTANT: new client_assertion each attempt
  $clientAssertion = New-ClientAssertionJwt -ClientId $ClientId -Audience $TokenUrl -Rsa $Rsa -Kid $Kid
  $dpopProof       = New-DpopProofJwt       -Htm "POST" -Htu $TokenUrl -Rsa $Rsa -Nonce $Nonce

  $body =
    "grant_type=client_credentials" +
    "&scope=$([uri]::EscapeDataString($Scope))" +
    "&client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer" +
    "&client_assertion=$([uri]::EscapeDataString($clientAssertion))"

  Invoke-WebRequest -Method POST -Uri $TokenUrl `
    -Headers @{ "DPoP" = $dpopProof; "Accept"="application/json" } `
    -ContentType "application/x-www-form-urlencoded" `
    -Body $body `
    -SkipHttpErrorCheck
}

try {
  $OktaDomain = $OktaDomain.TrimEnd("/")
  $tokenUrl   = "$OktaDomain/oauth2/v1/token"

  $flags = [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable `
        -bor [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::MachineKeySet

  $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($PfxPath, $PfxPassword, $flags)
  $rsa  = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($cert)
  if (-not $rsa) { throw "No RSA private key available from PFX." }

  # Attempt 1 (no nonce)
  $r1 = Invoke-TokenAttempt -TokenUrl $tokenUrl -OktaDomain $OktaDomain -ClientId $ClientId -Scope $Scope -Rsa $rsa -Kid $Kid -Nonce ""

  if ($r1.StatusCode -eq 200) {
    $json = $r1.Content | ConvertFrom-Json
    Write-Host "OK: access token acquired (DPoP)."
    Write-Host ("token_type: " + $json.token_type)
    Write-Host ("expires_in: " + $json.expires_in)
    exit 0
  }

  $err = $null
  try { $err = $r1.Content | ConvertFrom-Json } catch {}

  if ($r1.StatusCode -eq 400 -and $err -and $err.error -eq "use_dpop_nonce") {
    $nonce = $r1.Headers["DPoP-Nonce"]
    if (-not $nonce) { throw "Okta requested nonce but did not return DPoP-Nonce header." }

    # Attempt 2 (with nonce) — NEW client_assertion + NEW DPoP proof
    $r2 = Invoke-TokenAttempt -TokenUrl $tokenUrl -OktaDomain $OktaDomain -ClientId $ClientId -Scope $Scope -Rsa $rsa -Kid $Kid -Nonce $nonce

    if ($r2.StatusCode -eq 200) {
      $json = $r2.Content | ConvertFrom-Json
      Write-Host "OK: access token acquired (DPoP + nonce)."
      Write-Host ("token_type: " + $json.token_type)
      Write-Host ("expires_in: " + $json.expires_in)
      exit 0
    }

    throw ("Token retry failed. HTTP " + $r2.StatusCode + " Body: " + $r2.Content)
  }

  throw ("Token request failed. HTTP " + $r1.StatusCode + " Body: " + $r1.Content)
}
catch {
  Write-Error ("FAIL: " + $_.Exception.Message)
  exit 1
}
