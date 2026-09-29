# Test-signs the driver with a local self-signed code-signing certificate
# (created on first run) and exports the public .cer for VM import.
#
# Lab VM one-time prep (see README.md): Secure Boot off, memory integrity
# off, `bcdedit /set testsigning on`, then import the .cer into
# Root + TrustedPublisher.
param(
    [string]$Path = "",
    [string]$Subject = "SecOutfall Test Driver",
    [string]$CerOut = ""
)

$ErrorActionPreference = "Stop"

# Certificate store operations run in a child powershell.exe with a
# sanitized PSModulePath: when pwsh 7 module paths leak into Windows
# PowerShell's environment, the certificate provider fails to load
# ("Cert: drive does not exist" / duplicate type data). A clean child is
# immune; signtool below does not depend on it either way.
$cerPath = if ($CerOut) { $CerOut } else { Join-Path $PSScriptRoot "secoutfall-test.cer" }

$inner = @'
$ErrorActionPreference = "Stop"
$subject = "CN=__SUBJECT__"
$cerPath = "__CERPATH__"
$cert = Get-ChildItem Cert:\CurrentUser\My |
    Where-Object { $_.Subject -eq $subject -and $_.HasPrivateKey } |
    Sort-Object NotAfter -Descending |
    Select-Object -First 1
if (-not $cert) {
    $cert = New-SelfSignedCertificate -Type CodeSigningCert -Subject $subject `
        -KeyAlgorithm RSA -KeyLength 2048 -HashAlgorithm SHA256 `
        -CertStoreLocation Cert:\CurrentUser\My -NotAfter (Get-Date).AddYears(5)
    Write-Output "created certificate $($cert.Thumbprint)"
}
else {
    Write-Output "using existing certificate $($cert.Thumbprint)"
}
Export-Certificate -Cert $cert -FilePath $cerPath | Out-Null
Write-Output "THUMBPRINT=$($cert.Thumbprint)"
'@
$inner = $inner.Replace("__SUBJECT__", $Subject).Replace("__CERPATH__", $cerPath)

$oldModulePath = $env:PSModulePath
$env:PSModulePath = Join-Path $env:windir "System32\WindowsPowerShell\v1.0\Modules"
try {
    $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($inner))
    $output = & powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand $encoded 2>&1
}
finally {
    $env:PSModulePath = $oldModulePath
}
if ($LASTEXITCODE -ne 0) { throw ($output | Out-String) }

$output | Where-Object { $_ -like "*certificate*" } | ForEach-Object { Write-Host $_ }
Write-Host "Public certificate: $cerPath"
Write-Host "VM import (one-time): certutil -addstore Root `"$cerPath`"; certutil -addstore TrustedPublisher `"$cerPath`""

# locate signtool from the newest Windows Kits install
$kitsBin = Join-Path ${env:ProgramFiles(x86)} "Windows Kits\10\bin"
$signtool = Get-ChildItem $kitsBin -Directory |
    Where-Object { $_.Name -like "10.*" } |
    Sort-Object Name -Descending |
    ForEach-Object { Join-Path $_.FullName "x64\signtool.exe" } |
    Where-Object { Test-Path $_ } |
    Select-Object -First 1
if (-not $signtool) { throw "signtool.exe not found under $kitsBin" }

$target = if ($Path) { $Path } else { Join-Path $PSScriptRoot "secoutfall\x64\Release\secoutfall.sys" }
if (-not (Test-Path $target)) { throw "target not found: $target (build first: .\build.ps1)" }

& $signtool sign /fd SHA256 /ph /n $Subject $target
if ($LASTEXITCODE -ne 0) { throw "signing failed" }
Write-Host "Signed: $target"
