[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$Port,
    [Parameter(Mandatory)][ValidateScript({ Test-Path -LiteralPath $_ -PathType Container })][string]$ArtifactDirectory,
    [ValidateRange(115200,2000000)][int]$Baud = 921600,
    [switch]$Provision,
    [hashtable]$ProvisionArguments
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'PowerMeterSerial.psm1') -Force
$root = (Resolve-Path -LiteralPath $ArtifactDirectory).Path
$flashArgsPath = Join-Path $root 'flash_args.json'
if (-not (Test-Path -LiteralPath $flashArgsPath -PathType Leaf)) { throw 'flash_args.json is missing.' }
$flash = Get-Content -LiteralPath $flashArgsPath -Raw | ConvertFrom-Json
if ($flash.schema -ne 'pm-flash-args/1.0.0' -or $flash.chip -ne 'esp32s3') { throw 'Unsupported flash manifest.' }
$selectedPort = Select-PowerMeterPort -Port $Port
$arguments = @('--chip','esp32s3','--port',$selectedPort,'--baud',"$Baud",'--before','default-reset','--after','hard-reset','write-flash')
foreach ($image in $flash.images) {
    $path = Join-Path $root $image.file
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Missing flash image $($image.file)." }
    $actual = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actual -ne $image.sha256) { throw "SHA-256 mismatch for $($image.file)." }
    $arguments += @($image.offset, $path)
}
if ($PSCmdlet.ShouldProcess($selectedPort, "Flash verified ESP32-S3 artifacts from $root")) {
    & python -m esptool @arguments
    if ($LASTEXITCODE -ne 0) { throw "esptool failed with exit code $LASTEXITCODE." }
}
if ($Provision) {
    if ($null -eq $ProvisionArguments) { throw '-Provision requires -ProvisionArguments.' }
    & (Join-Path $PSScriptRoot 'Provision-PowerMeterSensor.ps1') -Port $selectedPort @ProvisionArguments
}
