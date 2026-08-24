# Signs one bound guarded-value build with the two existing control certificates.
param(
    [Parameter(Mandatory = $true)][string]$Source,
    [Parameter(Mandatory = $true)][string]$OutDir
)
$ErrorActionPreference = 'Stop'

$trusted = Get-ChildItem Cert:\LocalMachine\My |
    Where-Object { $_.Subject -eq 'CN=fidelity-control-trusted' } |
    Select-Object -First 1
$untrusted = Get-ChildItem Cert:\LocalMachine\My |
    Where-Object { $_.Subject -eq 'CN=fidelity-control-untrusted' } |
    Select-Object -First 1
if ($null -eq $trusted -or $null -eq $untrusted) {
    Write-Error 'sign-windows.ps1 must create both control certificates first'
    exit 1
}

New-Item -ItemType Directory -Path $OutDir -Force | Out-Null
$trustedPath = Join-Path $OutDir 'guarded-trusted.exe'
$untrustedPath = Join-Path $OutDir 'guarded-untrusted.exe'
Copy-Item $Source $trustedPath -Force
Copy-Item $Source $untrustedPath -Force
Set-AuthenticodeSignature -FilePath $trustedPath -Certificate $trusted | Out-Null
Set-AuthenticodeSignature -FilePath $untrustedPath -Certificate $untrusted | Out-Null

if ((Get-AuthenticodeSignature $trustedPath).Status -ne 'Valid') {
    Write-Error 'the trusted guarded-value signature is invalid'
    exit 1
}
