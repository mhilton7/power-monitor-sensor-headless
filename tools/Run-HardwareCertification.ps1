[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Port,
    [Parameter(Mandatory)][ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })][string]$Fixture,
    [Parameter(Mandatory)][ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })][string]$FirmwareBin,
    [Parameter(Mandatory)][string]$Version,
    [Parameter(Mandatory)][string]$Output,
    [ValidateRange(72,720)][double]$DurationHours = 72,
    [Security.SecureString]$FixtureToken
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ($null -eq $FixtureToken) { $FixtureToken = Read-Host 'Physical HIL fixture token' -AsSecureString }
$pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($FixtureToken)
try {
    $env:PM_HIL_FIXTURE_TOKEN = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer)
    & python (Join-Path $PSScriptRoot '..\test\hardware\run_hil.py') --port $Port --fixture $Fixture `
        --firmware-bin $FirmwareBin --version $Version --duration-hours $DurationHours --output $Output
    if ($LASTEXITCODE -ne 0) { throw "Physical HIL certification failed with exit code $LASTEXITCODE." }
} finally {
    Remove-Item Env:PM_HIL_FIXTURE_TOKEN -ErrorAction SilentlyContinue
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer)
}
