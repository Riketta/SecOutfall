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
# Pin to VS2022 (17.x): the WDK 26100 build tasks are version-matched to the
# MSBuild major (Microsoft.DriverKit.Build.Tasks.<major>.0.dll). Under VS18's
# MSBuild the WDK targets ask for an 18.0 tasks assembly the 26100 WDK never
# shipped (MSB4062), even though the toolset stub exists there. When the WDK
# gains a VS18-integrated release, widen the range together with the WDK bump.
$msbuild = & $vswhere -latest -products * -version "[17.0,18.0)" -requires Microsoft.Component.MSBuild -find "MSBuild\**\Bin\MSBuild.exe" | Select-Object -First 1
if (-not $msbuild) { throw "VS2022 (17.x) with MSBuild not found - the WDK 26100 toolset requires it (see comment above)" }
Write-Host "MSBuild: $msbuild"

foreach ($project in @("secoutfall\secoutfall.vcxproj", "dump\dump.vcxproj", "wiretest\wiretest.vcxproj")) {
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
Write-Host "Wiretest: $(Join-Path $root "wiretest\x64\$Configuration\wiretest.exe")"
