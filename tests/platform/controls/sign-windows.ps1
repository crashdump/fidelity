# Signs the subject of the Windows identity controls, so those controls have an
# image whose signature validates.
#
#     sign-windows.ps1 -Source <exe> -OutDir <directory>
#
# Image identity on Windows reads the signature of the running image, so a
# clean control needs a signed subject and no other kind of setup reaches it.
# The script makes two certificates:
#
#   trusted    lands in the root store and the publisher store, so the
#              signature that it makes validates, and the clean control runs;
#   untrusted  lands in neither, so the signature that it makes does not
#              validate, and the second hostile control runs.
#
# It writes four files under the output directory: the two signed copies, and
# the SHA-256 of each certificate. The SHA-256 is the value that a host pins,
# and `crates/probe/fidelity-probe-windows/src/identity.rs` compares it against
# the certificate that signed the running image.
#
# The certificate that this script trusts is one that this machine made, so the
# control proves that the tier reads a signature and compares a signer. It does
# not prove what Microsoft's own anchor accepts. `run.sh` runs this in the
# guest only, because the script writes to the root store of the machine.
param(
    [Parameter(Mandatory = $true)][string]$Source,
    [Parameter(Mandatory = $true)][string]$OutDir
)
$ErrorActionPreference = 'Stop'

# A second run must measure the same thing as the first, so the certificates of
# an earlier run go first.
foreach ($name in 'My', 'Root', 'TrustedPublisher') {
    $store = New-Object System.Security.Cryptography.X509Certificates.X509Store($name, 'LocalMachine')
    $store.Open('ReadWrite')
    $store.Certificates |
        Where-Object { $_.Subject -like 'CN=fidelity-control-*' } |
        ForEach-Object { $store.Remove($_) }
    $store.Close()
}

# The store of the machine holds these certificates, and the store of the user
# does not. A key container of a user needs a profile that a logon loads, and
# this guest answers over SSH with no person at the screen. The answer file
# logs the account in three times, and a guest that boots a fourth time has no
# interactive session at all. `New-SelfSignedCertificate` then stops with
# `NTE_PERM`, which names a permission and not the missing profile. The store
# of the machine needs no profile, and the session of an administrator writes
# it. Measured on 2026-08-16.
$trusted = New-SelfSignedCertificate -Type CodeSigningCert `
    -Subject 'CN=fidelity-control-trusted' -CertStoreLocation Cert:\LocalMachine\My `
    -KeyExportPolicy Exportable -NotAfter (Get-Date).AddYears(5)
$untrusted = New-SelfSignedCertificate -Type CodeSigningCert `
    -Subject 'CN=fidelity-control-untrusted' -CertStoreLocation Cert:\LocalMachine\My `
    -KeyExportPolicy Exportable -NotAfter (Get-Date).AddYears(5)

# Only the first certificate becomes an anchor. The second stays unknown, which
# is what makes the signature that it writes fail to validate.
foreach ($name in 'Root', 'TrustedPublisher') {
    $store = New-Object System.Security.Cryptography.X509Certificates.X509Store($name, 'LocalMachine')
    $store.Open('ReadWrite')
    $store.Add($trusted)
    $store.Close()
}

# The script makes its own output directory. It relied on one that an earlier
# run left behind, so a rename of that directory broke all three arms at once
# with a `DirectoryNotFoundException` that named no cause. Its two sibling
# controls each create theirs.
New-Item -ItemType Directory -Path $OutDir -Force | Out-Null

$signedTrusted = Join-Path $OutDir 'signed-trusted.exe'
$signedUntrusted = Join-Path $OutDir 'signed-untrusted.exe'
Copy-Item $Source $signedTrusted -Force
Copy-Item $Source $signedUntrusted -Force

# `Set-AuthenticodeSignature` reports the state of the chain rather than the
# state of the write. The second call answers `UnknownError`, because nothing
# anchors that certificate, and it still writes the signature that the control
# needs. Measured on 2026-08-15.
Set-AuthenticodeSignature -FilePath $signedTrusted -Certificate $trusted | Out-Null
Set-AuthenticodeSignature -FilePath $signedUntrusted -Certificate $untrusted | Out-Null

$state = (Get-AuthenticodeSignature $signedTrusted).Status
if ($state -ne 'Valid') {
    Write-Error "the trusted signature reports $state, and the clean control needs Valid"
    exit 1
}

function Sha256($certificate) {
    [BitConverter]::ToString($certificate.GetCertHash('SHA256')).Replace('-', '').ToLower()
}
Set-Content -Path (Join-Path $OutDir 'trusted-sha256.txt') -Value (Sha256 $trusted) -NoNewline
Set-Content -Path (Join-Path $OutDir 'untrusted-sha256.txt') -Value (Sha256 $untrusted) -NoNewline
