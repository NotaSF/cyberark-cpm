param(
  [Parameter(Mandatory=$true)]
  [string]$PemPath,          # C:\keys\okta-private.pem

  [Parameter(Mandatory=$true)]
  [string]$OutPfxPath,       # C:\keys\okta-service.pfx

  [Parameter(Mandatory=$false)]
  [string]$PfxPassword = "", # optional; empty allowed

  [Parameter(Mandatory=$false)]
  [string]$OutCerPath = ""   # optional; C:\keys\okta-service.cer
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# Read PEM
$pem = Get-Content -LiteralPath $PemPath -Raw

# Import RSA from PEM (PS7+)
$rsa = [System.Security.Cryptography.RSA]::Create()
$rsa.ImportFromPem($pem)

# Create a minimal self-signed cert using the same RSA key
$dn  = [System.Security.Cryptography.X509Certificates.X500DistinguishedName]::new("CN=CyberArk-Okta-Service")
$req = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
  $dn,
  $rsa,
  [System.Security.Cryptography.HashAlgorithmName]::SHA256,
  [System.Security.Cryptography.RSASignaturePadding]::Pkcs1
)

# Self-signed validity
$cert = $req.CreateSelfSigned(
  [DateTimeOffset]::UtcNow.AddDays(-1),
  [DateTimeOffset]::UtcNow.AddYears(10)
)

# Export PFX bytes
$pfxBytes = $cert.Export(
  [System.Security.Cryptography.X509Certificates.X509ContentType]::Pfx,
  $PfxPassword
)

[IO.File]::WriteAllBytes($OutPfxPath, $pfxBytes)
Write-Host "Wrote PFX: $OutPfxPath"

# Optional: export public cert (.cer) for Okta upload
if ($OutCerPath -and $OutCerPath.Trim().Length -gt 0) {
  $cerBytes = $cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)
  [IO.File]::WriteAllBytes($OutCerPath, $cerBytes)
  Write-Host "Wrote CER: $OutCerPath"
}

# Validate we can load the PFX and access the private key (Windows-friendly)
$flags = [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable `
      -bor [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::MachineKeySet

$test = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(
  $OutPfxPath,
  $PfxPassword,
  $flags
)

if (-not $test.HasPrivateKey) { throw "PFX does not contain a private key." }
$rsa2 = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($test)
if (-not $rsa2) { throw "Could not read RSA private key from PFX." }


Write-Host "OK: PFX contains usable private key."
