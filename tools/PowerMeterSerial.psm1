Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-PowerMeterPorts {
    [CmdletBinding()]
    param()
    $ports = [System.IO.Ports.SerialPort]::GetPortNames() | Sort-Object
    foreach ($port in $ports) {
        $description = $port
        try {
            $device = Get-CimInstance Win32_PnPEntity -Filter "Name LIKE '%($port)%'" -ErrorAction Stop |
                Select-Object -First 1
            if ($null -ne $device -and $device.Name) { $description = $device.Name }
        } catch { }
        [pscustomobject]@{ Port = $port; Description = $description }
    }
}

function ConvertFrom-SecureValue {
    [CmdletBinding()]
    param([Parameter(Mandatory)][Security.SecureString]$Value)
    $pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Value)
    try { [Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer) }
    finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer) }
}

function Open-PowerMeterPort {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$PortName)
    $serial = [System.IO.Ports.SerialPort]::new($PortName, 115200, 'None', 8, 'One')
    $serial.NewLine = "`n"
    $serial.ReadTimeout = 5000
    $serial.WriteTimeout = 5000
    $serial.DtrEnable = $false
    $serial.RtsEnable = $false
    $serial.Open()
    Start-Sleep -Milliseconds 250
    $serial.DiscardInBuffer()
    return $serial
}

function Invoke-PowerMeterRequest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][System.IO.Ports.SerialPort]$Serial,
        [Parameter(Mandatory)][string]$Operation,
        [hashtable]$Fields = @{}
    )
    $request = [ordered]@{
        protocol = 'pm-com/1.0.0'
        id = [guid]::NewGuid().ToString('D')
        op = $Operation
    }
    foreach ($key in $Fields.Keys) { $request[$key] = $Fields[$key] }
    $line = $request | ConvertTo-Json -Compress -Depth 8
    if ([Text.Encoding]::UTF8.GetByteCount($line) -ge 8192) {
        throw 'Provisioning request exceeds the device 8192-byte JSONL limit.'
    }
    $Serial.WriteLine($line)
    $deadline = [DateTimeOffset]::UtcNow.AddSeconds(30)
    do {
        $responseLine = $Serial.ReadLine().Trim()
        if (-not $responseLine.StartsWith('{')) { continue }
        try { $response = $responseLine | ConvertFrom-Json -Depth 8 }
        catch { continue }
        if ($response.protocol -ne 'pm-com/1.0.0' -or $response.id -ne $request.id) { continue }
        if (-not $response.ok) {
            $reason = if ($response.error) { $response.error } else { 'device_rejected_request' }
            throw "Device rejected $Operation`: $reason"
        }
        return $response
    } while ([DateTimeOffset]::UtcNow -lt $deadline)
    throw "Timed out waiting for $Operation response."
}

function Select-PowerMeterPort {
    [CmdletBinding()]
    param([string]$Port)
    if ($Port) { return $Port }
    $ports = @(Get-PowerMeterPorts)
    if ($ports.Count -eq 0) { throw 'No COM ports were found.' }
    if ($ports.Count -eq 1) { return $ports[0].Port }
    for ($index = 0; $index -lt $ports.Count; $index++) {
        Write-Host "[$($index + 1)] $($ports[$index].Port) - $($ports[$index].Description)"
    }
    $selection = Read-Host 'Select COM port number'
    $number = 0
    if (-not [int]::TryParse($selection, [ref]$number) -or $number -lt 1 -or $number -gt $ports.Count) {
        throw 'Invalid COM port selection.'
    }
    return $ports[$number - 1].Port
}

Export-ModuleMember -Function Get-PowerMeterPorts, ConvertFrom-SecureValue, Open-PowerMeterPort, Invoke-PowerMeterRequest, Select-PowerMeterPort
