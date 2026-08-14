[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$Port,
    [Parameter(Mandatory)][ValidateLength(1,48)][string]$FriendlyName,
    [Parameter(Mandatory)][ValidateLength(1,32)][string]$WifiSsid,
    [Security.SecureString]$WifiPassword,
    [Parameter(Mandatory)][ValidatePattern('^https://[^/]+(?::[0-9]+)?$')][string]$ServerOrigin,
    [Parameter(Mandatory)][ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })][string]$CaCertificatePath,
    [Security.SecureString]$EnrollmentToken,
    [ValidateSet('DHCP','Static')][string]$Ipv4Mode = 'DHCP',
    [ipaddress]$Ipv4Address,
    [ipaddress]$Ipv4Gateway,
    [ipaddress]$Ipv4Netmask,
    [ipaddress]$DnsPrimary,
    [ipaddress]$DnsSecondary,
    [ValidateRange(1,100)][int]$CtRatingA = 100,
    [ValidateSet('pzem-004t-v4-classic')][string]$PzemVariant = 'pzem-004t-v4-classic',
    [ValidatePattern('^[A-Za-z_+.-]+(?:/[A-Za-z0-9_+.-]+)+$')][string]$Timezone = 'America/Los_Angeles'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'PowerMeterSerial.psm1') -Force

function ConvertTo-NetworkUInt32([ipaddress]$Address) {
    if ($null -eq $Address -or $Address.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork) {
        throw 'A valid IPv4 address is required.'
    }
    $bytes = $Address.GetAddressBytes()
    return [uint32]($bytes[0] -bor ($bytes[1] -shl 8) -bor ($bytes[2] -shl 16) -bor ($bytes[3] -shl 24))
}

if ($null -eq $WifiPassword) { $WifiPassword = Read-Host 'Wi-Fi password' -AsSecureString }
if ($null -eq $EnrollmentToken) { $EnrollmentToken = Read-Host 'One-time enrollment token' -AsSecureString }
$caPem = [IO.File]::ReadAllText((Resolve-Path -LiteralPath $CaCertificatePath))
if ($caPem -notmatch '^-----BEGIN CERTIFICATE-----' -or $caPem -notmatch '-----END CERTIFICATE-----\s*$') {
    throw 'The CA file must contain one or more PEM certificates.'
}
if ($Ipv4Mode -eq 'Static' -and ($null -eq $Ipv4Address -or $null -eq $Ipv4Gateway -or
    $null -eq $Ipv4Netmask -or $null -eq $DnsPrimary)) {
    throw 'Static mode requires Ipv4Address, Ipv4Gateway, Ipv4Netmask, and DnsPrimary.'
}

$selectedPort = Select-PowerMeterPort -Port $Port
$serial = Open-PowerMeterPort -PortName $selectedPort
$wifiPlain = $null
$tokenPlain = $null
try {
    $hello = Invoke-PowerMeterRequest -Serial $serial -Operation 'hello'
    Write-Host "Device $($hello.device_fingerprint), firmware $($hello.firmware), sequence floor $($hello.sequence_floor) on $selectedPort"
    $wifiPlain = ConvertFrom-SecureValue $WifiPassword
    $tokenPlain = ConvertFrom-SecureValue $EnrollmentToken
    $config = [ordered]@{
        friendly_name = $FriendlyName
        wifi_ssid = $WifiSsid
        wifi_password = $wifiPlain
        ipv4_mode = if ($Ipv4Mode -eq 'DHCP') { 0 } else { 1 }
        server_origin = $ServerOrigin
        ca_pem = $caPem
        enrollment_token = $tokenPlain
        ct_rating_a = $CtRatingA
        pzem_variant = $PzemVariant
        timezone = $Timezone
    }
    if ($Ipv4Mode -eq 'Static') {
        $config.ipv4_address = ConvertTo-NetworkUInt32 $Ipv4Address
        $config.ipv4_gateway = ConvertTo-NetworkUInt32 $Ipv4Gateway
        $config.ipv4_netmask = ConvertTo-NetworkUInt32 $Ipv4Netmask
        $config.dns_primary = ConvertTo-NetworkUInt32 $DnsPrimary
        $config.dns_secondary = if ($null -eq $DnsSecondary) { 0 } else { ConvertTo-NetworkUInt32 $DnsSecondary }
    }
    if (-not $PSCmdlet.ShouldProcess($hello.device_fingerprint, 'Test and transactionally commit sensor configuration')) { return }
    [void](Invoke-PowerMeterRequest -Serial $serial -Operation 'begin_config' -Fields @{ config = $config })
    try {
        $tested = Invoke-PowerMeterRequest -Serial $serial -Operation 'test_config'
        Write-Host "Configuration tests: $($tested.stage)"
        $committed = Invoke-PowerMeterRequest -Serial $serial -Operation 'commit_config'
        Write-Host "Configuration $($committed.stage); secrets were not returned by the device."
        [void](Invoke-PowerMeterRequest -Serial $serial -Operation 'safe_reboot')
    } catch {
        try { [void](Invoke-PowerMeterRequest -Serial $serial -Operation 'rollback_config') } catch { }
        throw
    }
} finally {
    $wifiPlain = $null
    $tokenPlain = $null
    if ($null -ne $serial) { $serial.Dispose() }
}
