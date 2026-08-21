[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$Port,
    [ValidateSet('Status','RollbackConfiguration','SafeReboot')][string]$Action = 'Status'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'PowerMeterSerial.psm1') -Force
$selectedPort = Select-PowerMeterPort -Port $Port
$serial = Open-PowerMeterPort -PortName $selectedPort
try {
    $status = Invoke-PowerMeterRequest -Serial $serial -Operation 'status'
    Write-Host "Device $($status.device_fingerprint), firmware $($status.firmware), provisioned=$($status.provisioned), physical-recovery=$($status.physical_recovery)"
    switch ($Action) {
        'Status' { }
        'RollbackConfiguration' {
            if ($PSCmdlet.ShouldProcess($status.device_fingerprint, 'Roll back uncommitted candidate configuration')) {
                [void](Invoke-PowerMeterRequest -Serial $serial -Operation 'rollback_config')
                Write-Host 'Prior committed configuration retained.'
            }
        }
        'SafeReboot' {
            if ($PSCmdlet.ShouldProcess($status.device_fingerprint, 'Request configuration-checkpointed safe reboot')) {
                [void](Invoke-PowerMeterRequest -Serial $serial -Operation 'safe_reboot')
            }
        }
    }
} finally {
    $serial.Dispose()
}
