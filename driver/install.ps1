# Installs the secoutfall driver as a kernel service and registers the
# Filter Manager instance (altitude) the minifilter attaches through.
#
# Lab prerequisites (one-time, see README.md): test-signing on, the test
# certificate imported into Root + TrustedPublisher, Secure Boot and memory
# integrity off.
#
# usage:
#   install.ps1                create the service + instance keys
#   install.ps1 -Start         ... and start it now
#   install.ps1 -Remove        stop, delete instance keys and service
param(
    [switch]$Start,
    [switch]$Remove
)

$ErrorActionPreference = "Stop"
$name = "secoutfall"
$altitude = "389910.02"   # lab altitude: FSFilter activity-monitor range
$instance = "SecOutfall Instance"
$instancesKey = "HKLM:\SYSTEM\CurrentControlSet\Services\$name\Instances"

if ($Remove) {
    sc.exe stop $name | Out-Null
    Remove-ItemProperty -Path $instancesKey -Name "DefaultInstance" -ErrorAction SilentlyContinue
    Remove-Item -Path "$instancesKey\$instance" -ErrorAction SilentlyContinue
    Remove-Item -Path $instancesKey -ErrorAction SilentlyContinue
    sc.exe delete $name | Out-Null
    Write-Host "Removed service '$name' and instance keys."
    return
}

$sys = Join-Path $PSScriptRoot "secoutfall\x64\Release\secoutfall.sys"
if (-not (Test-Path $sys)) { throw "driver not found: $sys (build first: .\build.ps1)" }

# Kernel service, demand start: the agent (or an explicit sc start) brings it
# up; a sandbox VM image can also flip start to auto later via config.
sc.exe create $name type= kernel start= demand binPath= "`"$sys`"" | Out-Null
if ($LASTEXITCODE -ne 0) { throw "sc.exe create failed ($LASTEXITCODE) - already installed? use -Remove first" }

# Filter Manager instances: without these keys FltMgr has nothing to attach
# and FltStartFiltering reports no instances (file telemetry stays silent
# while the control device still works).
New-Item -Path $instancesKey -Force | Out-Null
Set-ItemProperty -Path $instancesKey -Name "DefaultInstance" -Value $instance
New-Item -Path "$instancesKey\$instance" -Force | Out-Null
Set-ItemProperty -Path "$instancesKey\$instance" -Name "Altitude" -Value $altitude
Set-ItemProperty -Path "$instancesKey\$instance" -Name "Flags" -Value 0 -Type DWord

Write-Host "Installed service '$name' (demand start), instance '$instance' at altitude $altitude."
if ($Start) {
    sc.exe start $name | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "sc.exe start failed ($LASTEXITCODE)" }
    Write-Host "Started. Dump events: .\dump\x64\Release\dump.exe --files *"
}
