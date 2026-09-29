# Builds the driver and the console dumper (x64, Debug or Release).
# Prerequisites: Visual Studio 2022 (MSBuild + v143) and the WDK
# (WindowsKernelModeDriver10.0 toolset). CI uses the same script.
param(
    [ValidateSet("Debug", "Release")]
    [string]$Configuration = "Release"
)

$ErrorActionPreference = "Stop"
$root = $PSScriptRoot

$vswhere = Join-Path ${env:ProgramFiles(x86)} "Microsoft Visual Studio\Installer\vswhere.exe"
if (-not (Test-Path $vswhere)) { throw "vswhere.exe not found - is Visual Studio installed?" }
$msbuild = & $vswhere -latest -products * -requires Microsoft.Component.MSBuild -find "MSBuild\**\Bin\MSBuild.exe" | Select-Object -First 1
if (-not $msbuild) { throw "MSBuild not found via vswhere" }
Write-Host "MSBuild: $msbuild"

foreach ($project in @("secoutfall\secoutfall.vcxproj", "dump\dump.vcxproj")) {
    Write-Host "=== Building $project ($Configuration|x64) ==="
    & $msbuild (Join-Path $root $project) "/p:Configuration=$Configuration" "/p:Platform=x64" "/m" "/nologo" "/v:m"
    if ($LASTEXITCODE -ne 0) { throw "build failed: $project" }
}

$sys = Join-Path $root "secoutfall\x64\$Configuration\secoutfall.sys"
if (-not (Test-Path $sys)) { throw "driver binary missing after build: $sys" }
Write-Host ""
Write-Host "Done."
Write-Host "Driver: $sys"
Write-Host "Dumper: $(Join-Path $root "dump\x64\$Configuration\dump.exe")"
