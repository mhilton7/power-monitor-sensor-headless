[CmdletBinding()]
param(
    [ValidatePattern('^[0-9]+\.[0-9]+\.[0-9]+-rc\.[0-9]+$')][string]$Version = '0.1.0-rc.20',
    [ValidateRange(1,2147483647)][int]$BuildNumber = 23,
    [ValidatePattern('^https://')][string]$DownloadBase = 'https://power-monitor.home.arpa:8443/api/firmware/releases/0.1.0-rc.20',
    [string]$BuildDirectory = (Join-Path $PSScriptRoot '..\build-release'),
    [string]$OutputDirectory = (Join-Path $PSScriptRoot '..\release\out\0.1.0-rc.20')
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
if (-not $env:IDF_PATH) { throw 'Run this script from the pinned ESP-IDF v6.0.2 PowerShell environment.' }
$idfVersion = (& git -C $env:IDF_PATH describe --tags --exact-match).Trim()
if ($idfVersion -ne 'v6.0.2') { throw "ESP-IDF v6.0.2 is required; found $idfVersion." }
& (Join-Path $PSScriptRoot 'Run-HostTests.ps1')
if ($LASTEXITCODE -ne 0) { throw 'Host tests failed.' }
& idf.py -B $BuildDirectory `
    -D "SDKCONFIG=$BuildDirectory/sdkconfig" `
    -D 'SDKCONFIG_DEFAULTS=sdkconfig.defaults;sdkconfig.release-candidate' `
    -D "PM_FIRMWARE_VERSION=$Version" set-target esp32s3 build
if ($LASTEXITCODE -ne 0) { throw 'ESP-IDF release-candidate build failed.' }
& python (Join-Path $PSScriptRoot 'verify_firmware_profile.py') `
    --sdkconfig-header (Join-Path $BuildDirectory 'config\sdkconfig.h') --profile release-candidate
if ($LASTEXITCODE -ne 0) { throw 'Compiled firmware profile verification failed.' }
$auditPath = Join-Path $root 'test-results\dependency-audit.json'
& python (Join-Path $PSScriptRoot 'audit_dependencies.py') --output $auditPath
if ($LASTEXITCODE -ne 0) { throw 'OSV dependency audit failed.' }
if (Test-Path -LiteralPath $OutputDirectory) {
    $resolvedOutput = [IO.Path]::GetFullPath($OutputDirectory)
    $safeRoot = [IO.Path]::GetFullPath((Join-Path $root 'release\out'))
    if (-not $resolvedOutput.StartsWith($safeRoot + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'OutputDirectory must be below release/out.'
    }
    Remove-Item -LiteralPath $resolvedOutput -Recurse -Force
}
New-Item -ItemType Directory -Path $OutputDirectory | Out-Null
& python (Join-Path $PSScriptRoot 'build_release.py') --build-dir $BuildDirectory --output-dir $OutputDirectory `
    --version $Version --build-number $BuildNumber --download-base $DownloadBase `
    --hardware-status (Join-Path $root 'release\hardware-certification-status.json') `
    --dependency-audit-report $auditPath
if ($LASTEXITCODE -ne 0) { throw 'Release assembly failed.' }
