[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$Port,
    [ValidateSet('Status','RollbackConfiguration','SafeReboot','FactoryReset')][string]$Action = 'Status',
    [string]$TypedConfirmation
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'PowerMeterSerial.psm1') -Force
$selectedPort = Select-PowerMeterPort -Port $Port
$serial = Open-PowerMeterPort -PortName $selectedPort
try {
    $status = Invoke-PowerMeterRequest -Serial $serial -Operation 'status'
    Write-Host "Device $($status.device_fingerprint), firmware $($status.firmware), provisioned=$($status.provisioned), physical-recovery=$($status.physical_recovery), sequence-floor=$($status.sequence_floor)"
    switch ($Action) {
        'Status' { }
        'RollbackConfiguration' {
            if ($PSCmdlet.ShouldProcess($status.device_fingerprint, 'Roll back uncommitted candidate configuration')) {
                [void](Invoke-PowerMeterRequest -Serial $serial -Operation 'rollback_config')
                Write-Host 'Prior committed configuration retained.'
            }
        }
        'SafeReboot' {
            if ($PSCmdlet.ShouldProcess($status.device_fingerprint, 'Request storage-checkpointed safe reboot')) {
                [void](Invoke-PowerMeterRequest -Serial $serial -Operation 'safe_reboot')
            }
        }
        'FactoryReset' {
            if (-not $status.physical_recovery) { throw 'Factory reset requires the physical recovery input at boot.' }
            $prepared = Invoke-PowerMeterRequest -Serial $serial -Operation 'factory_reset_prepare'
            Write-Warning $prepared.warning
            if ($TypedConfirmation -ne "RESET $($status.device_fingerprint)") {
                throw "Re-run with -TypedConfirmation 'RESET $($status.device_fingerprint)' within a physical recovery session."
            }
            if ($PSCmdlet.ShouldProcess($status.device_fingerprint, 'Factory-reset configuration; preserve device/sequence identity')) {
                [void](Invoke-PowerMeterRequest -Serial $serial -Operation 'factory_reset_commit' -Fields @{
                    confirmation_token = $prepared.confirmation_token
                })
            }
        }
    }
} finally {
    $serial.Dispose()
}
