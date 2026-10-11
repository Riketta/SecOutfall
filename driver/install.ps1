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
    Remove-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Debug Print Filter" `
        -Name "IHVDRIVER" -ErrorAction SilentlyContinue
    Write-Host "Removed service '$name', instance keys and the IHVDRIVER print filter override."
    return
}

$sys = Join-Path $PSScriptRoot "secoutfall\x64\Release\secoutfall.sys"
if (-not (Test-Path $sys)) { throw "driver not found: $sys (build first: .\build.ps1)" }

# Kernel service, system start + Filter group: loaded during boot before any
# auto-start service (the agent) or user code (malware); the Filter group
# orders it after FltMgr so the minifilter instance attaches.
sc.exe create $name type= kernel start= system group= Filter binPath= "`"$sys`"" | Out-Null
if ($LASTEXITCODE -ne 0) { throw "sc.exe create failed ($LASTEXITCODE) - already installed? use -Remove first" }

# Filter Manager instances: without these keys FltMgr has nothing to attach
# and FltStartFiltering reports no instances (file telemetry stays silent
# while the control device still works).
New-Item -Path $instancesKey -Force | Out-Null
Set-ItemProperty -Path $instancesKey -Name "DefaultInstance" -Value $instance
New-Item -Path "$instancesKey\$instance" -Force | Out-Null
Set-ItemProperty -Path "$instancesKey\$instance" -Name "Altitude" -Value $altitude
Set-ItemProperty -Path "$instancesKey\$instance" -Name "Flags" -Value 0 -Type DWord

# Raise the driver's print filter so SF_LOG WARNING/INFO reach DebugView and
# a kernel debugger (ERROR level prints by default). 0xF = ERROR|WARNING|INFO|TRACE.
$printFilter = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Debug Print Filter"
New-Item -Path $printFilter -Force | Out-Null
Set-ItemProperty -Path $printFilter -Name "IHVDRIVER" -Value 15 -Type DWord

Write-Host "Installed service '$name' (system start, Filter group), instance '$instance' at altitude $altitude."
if ($Start) {
	sc.exe start $name | Out-Null
	if ($LASTEXITCODE -ne 0) { throw "sc.exe start failed ($LASTEXITCODE)" }
	Write-Host "Started. Dump events: .\dump\x64\Release\dump.exe"
}
