Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:CaCertificateLimit = 4096
$script:LocalCaFileDiagnostic = 'CaCertificatePath must name a readable existing local certificate file; URLs, UNC/network paths, directories, and non-filesystem providers are not supported.'

function ConvertTo-PowerMeterServerOrigin {
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Value)

    $diagnostic = 'ServerOrigin must be an HTTPS origin only (for example, https://power-monitor.home.arpa:8443); paths, query strings, fragments, user information, and insecure HTTP are not allowed. One trailing slash is accepted and removed.'
    if ([string]::IsNullOrWhiteSpace($Value) -or $Value -cne $Value.Trim() -or
        $Value.Contains('?') -or $Value.Contains('#') -or
        $Value.Contains('@') -or $Value.Contains('\')) {
        throw $diagnostic
    }

    $origin = $null
    if (-not [Uri]::TryCreate($Value, [UriKind]::Absolute, [ref]$origin) -or
        $origin.Scheme -ne [Uri]::UriSchemeHttps -or [string]::IsNullOrWhiteSpace($origin.Host) -or
        -not [string]::IsNullOrEmpty($origin.UserInfo) -or
        -not [string]::IsNullOrEmpty($origin.Query) -or
        -not [string]::IsNullOrEmpty($origin.Fragment)) {
        throw $diagnostic
    }

    $schemeSeparator = $Value.IndexOf('://', [StringComparison]::Ordinal)
    $pathStart = if ($schemeSeparator -ge 0) {
        $Value.IndexOf('/', $schemeSeparator + 3)
    } else {
        -1
    }
    if (($pathStart -ge 0 -and $Value.Substring($pathStart) -cne '/') -or
        $origin.AbsolutePath -ne '/') {
        throw $diagnostic
    }
    return $origin.GetLeftPart([UriPartial]::Authority)
}

function Read-PowerMeterCaCertificate {
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path) -or
        $Path -match '^[A-Za-z][A-Za-z0-9+.-]*://' -or $Path.StartsWith('\\') -or
        $Path.StartsWith('//')) {
        throw $script:LocalCaFileDiagnostic
    }

    try {
        $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    } catch {
        throw $script:LocalCaFileDiagnostic
    }
    if ($item -isnot [IO.FileInfo] -or $null -eq $item.PSProvider -or
        $item.PSProvider.Name -ne 'FileSystem') {
        throw $script:LocalCaFileDiagnostic
    }

    $fileUri = $null
    if ([Uri]::TryCreate($item.FullName, [UriKind]::Absolute, [ref]$fileUri) -and $fileUri.IsUnc) {
        throw $script:LocalCaFileDiagnostic
    }
    if ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) {
        $pathRoot = [IO.Path]::GetPathRoot($item.FullName)
        if (-not [string]::IsNullOrEmpty($pathRoot)) {
            try {
                if ([IO.DriveInfo]::new($pathRoot).DriveType -eq [IO.DriveType]::Network) {
                    throw $script:LocalCaFileDiagnostic
                }
            } catch [ArgumentException] {
                throw $script:LocalCaFileDiagnostic
            }
        }
    }

    try {
        $pem = [IO.File]::ReadAllText($item.FullName)
    } catch {
        throw $script:LocalCaFileDiagnostic
    }
    $byteCount = [Text.Encoding]::UTF8.GetByteCount($pem)
    if ($pem.Length -gt $script:CaCertificateLimit -or
        $byteCount -gt $script:CaCertificateLimit) {
        throw "The CA certificate must not exceed the device limit of $($script:CaCertificateLimit) UTF-8 bytes or characters (maximum 4096). Use a smaller PEM CA certificate or bundle."
    }

    $certificatePattern = [regex]::new(
        '-----BEGIN CERTIFICATE-----[\r\n]+(?<body>[A-Za-z0-9+/=\r\n]+?)[\r\n]+-----END CERTIFICATE-----',
        [Text.RegularExpressions.RegexOptions]::CultureInvariant
    )
    $matches = $certificatePattern.Matches($pem)
    if ($matches.Count -eq 0 -or
        -not [string]::IsNullOrWhiteSpace($certificatePattern.Replace($pem, ''))) {
        throw 'The CA file must contain only one or more PEM-encoded X.509 certificates.'
    }
    foreach ($match in $matches) {
        $certificate = $null
        try {
            $body = [regex]::Replace($match.Groups['body'].Value, '\s', '')
            $der = [Convert]::FromBase64String($body)
            $certificate = [Security.Cryptography.X509Certificates.X509Certificate2]::new($der)
            if ($certificate.RawData.Length -eq 0) {
                throw 'Empty certificate data.'
            }
        } catch {
            throw 'The CA file must contain only one or more PEM-encoded X.509 certificates.'
        } finally {
            if ($null -ne $certificate) { $certificate.Dispose() }
        }
    }
    return $pem
}

function Test-PowerMeterSerialTimeoutException {
    [CmdletBinding()]
    param([Parameter(Mandatory)][Exception]$Exception)

    $current = $Exception
    while ($null -ne $current) {
        if ($current -is [TimeoutException]) { return $true }
        if ($current -is [ComponentModel.Win32Exception] -and
            $current.NativeErrorCode -eq 121) {
            return $true
        }
        if ($current -is [IO.IOException]) {
            $nativeCode = $current.HResult -band 0xffff
            if ($nativeCode -eq 121 -or
                $current.Message -match '(?i)semaphore timeout|read.+timed out|write.+timed out') {
                return $true
            }
        }
        $current = $current.InnerException
    }
    return $false
}

function Test-PowerMeterOrdinaryReadTimeoutException {
    [CmdletBinding()]
    param([Parameter(Mandatory)][Exception]$Exception)

    $current = $Exception
    $ordinaryTimeout = $false
    while ($null -ne $current) {
        if ($current -is [IO.IOException] -or $current -is [ComponentModel.Win32Exception]) {
            return $false
        }
        if ($current -is [TimeoutException]) { $ordinaryTimeout = $true }
        $current = $current.InnerException
    }
    return $ordinaryTimeout
}

function Get-PowerMeterSerialTimeoutMessage {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Operation,
        [Parameter(Mandatory)][string]$Phase
    )
    return "Firmware is not servicing USB provisioning ($Phase timed out during '$Operation'). Close other serial monitors, keep the USB cable connected, press and release RESET once, wait for boot to finish, and retry. If it repeats, capture the serial boot log from reset through the timeout. Preserve the existing configuration and device identity; run Repair-PowerMeterSensor.ps1 -Action Status only after the device responds."
}

function Invoke-PowerMeterSerialWrite {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Serial,
        [Parameter(Mandatory)][string]$Line,
        [Parameter(Mandatory)][string]$Operation
    )
    try {
        $Serial.WriteLine($Line)
    } catch {
        if (Test-PowerMeterSerialTimeoutException -Exception $_.Exception) {
            throw [TimeoutException]::new(
                (Get-PowerMeterSerialTimeoutMessage -Operation $Operation -Phase 'serial write'),
                $_.Exception
            )
        }
        throw
    }
}

function Read-PowerMeterSerialLine {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Serial,
        [Parameter(Mandatory)][string]$Operation
    )
    try {
        return $Serial.ReadLine()
    } catch {
        if (Test-PowerMeterOrdinaryReadTimeoutException -Exception $_.Exception) {
            return $null
        }
        if (Test-PowerMeterSerialTimeoutException -Exception $_.Exception) {
            throw [TimeoutException]::new(
                (Get-PowerMeterSerialTimeoutMessage -Operation $Operation -Phase 'serial read'),
                $_.Exception
            )
        }
        throw
    }
}

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
    try {
        $serial.Open()
        Start-Sleep -Milliseconds 250
        $serial.DiscardInBuffer()
        return $serial
    } catch {
        $failure = $_.Exception
        $serial.Dispose()
        if (Test-PowerMeterSerialTimeoutException -Exception $failure) {
            throw [TimeoutException]::new(
                (Get-PowerMeterSerialTimeoutMessage -Operation 'open' -Phase 'serial port'),
                $failure
            )
        }
        throw
    }
}

function Invoke-PowerMeterRequestCore {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Serial,
        [Parameter(Mandatory)][string]$Operation,
        [hashtable]$Fields = @{},
        [DateTimeOffset]$Deadline = [DateTimeOffset]::UtcNow.AddSeconds(30)
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
    Invoke-PowerMeterSerialWrite -Serial $Serial -Line $line -Operation $Operation
    do {
        $responseLine = Read-PowerMeterSerialLine -Serial $Serial -Operation $Operation
        if ($null -eq $responseLine) { continue }
        $responseLine = $responseLine.Trim()
        if (-not $responseLine.StartsWith('{')) { continue }
        try { $response = $responseLine | ConvertFrom-Json }
        catch { continue }
        if ($response.protocol -ne 'pm-com/1.0.0' -or $response.id -ne $request.id) { continue }
        if (-not $response.ok) {
            $reason = if ($response.error) { $response.error } else { 'device_rejected_request' }
            throw "Device rejected $Operation`: $reason"
        }
        return $response
    } while ([DateTimeOffset]::UtcNow -lt $Deadline)
    throw (Get-PowerMeterSerialTimeoutMessage -Operation $Operation -Phase 'protocol response')
}

function Invoke-PowerMeterRequest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][System.IO.Ports.SerialPort]$Serial,
        [Parameter(Mandatory)][string]$Operation,
        [hashtable]$Fields = @{}
    )
    return Invoke-PowerMeterRequestCore -Serial $Serial -Operation $Operation -Fields $Fields
}

function Invoke-PowerMeterProvisioningTransactionCore {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Serial,
        [Parameter(Mandatory)][System.Collections.IDictionary]$Config,
        [Parameter(Mandatory)][string]$PortName,
        [ValidateRange(0,30)][double]$RequestTimeoutSeconds = 30
    )

    $commitAttempted = $false
    $commitConfirmed = $false
    try {
        [void](Invoke-PowerMeterRequestCore -Serial $Serial -Operation 'begin_config' `
            -Fields @{ config = $Config } `
            -Deadline ([DateTimeOffset]::UtcNow.AddSeconds($RequestTimeoutSeconds)))
        $tested = Invoke-PowerMeterRequestCore -Serial $Serial -Operation 'test_config' `
            -Deadline ([DateTimeOffset]::UtcNow.AddSeconds($RequestTimeoutSeconds))
        $commitAttempted = $true
        $committed = Invoke-PowerMeterRequestCore -Serial $Serial -Operation 'commit_config' `
            -Deadline ([DateTimeOffset]::UtcNow.AddSeconds($RequestTimeoutSeconds))
        $commitConfirmed = $true
        [void](Invoke-PowerMeterRequestCore -Serial $Serial -Operation 'safe_reboot' `
            -Deadline ([DateTimeOffset]::UtcNow.AddSeconds($RequestTimeoutSeconds)))
        return [pscustomobject]@{
            Tested = $tested
            Committed = $committed
        }
    } catch {
        if ($commitConfirmed) {
            $message = "Configuration is committed. Safe reboot was not performed or confirmed by this provisioning run. After firmware responds, run .\tools\Repair-PowerMeterSensor.ps1 -Port $PortName -Action SafeReboot. Do not rerun provisioning or roll back the committed configuration."
            throw [InvalidOperationException]::new($message, $_.Exception)
        }
        if ($commitAttempted) {
            $message = "The commit_config request was attempted, but its response was not confirmed. Configuration may already be committed. Do not roll back, reuse the enrollment token, or retry provisioning yet. After firmware responds, run .\tools\Repair-PowerMeterSensor.ps1 -Port $PortName -Action Status. If provisioned=true, run the same command with -Action SafeReboot. If provisioned=false, obtain a new enrollment token and reprovision."
            throw [InvalidOperationException]::new($message, $_.Exception)
        }
        try {
            [void](Invoke-PowerMeterRequestCore -Serial $Serial -Operation 'rollback_config' `
                -Deadline ([DateTimeOffset]::UtcNow.AddSeconds($RequestTimeoutSeconds)))
        } catch { }
        throw
    }
}

function Invoke-PowerMeterProvisioningTransaction {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][System.IO.Ports.SerialPort]$Serial,
        [Parameter(Mandatory)][System.Collections.IDictionary]$Config,
        [Parameter(Mandatory)][string]$PortName
    )
    return Invoke-PowerMeterProvisioningTransactionCore -Serial $Serial -Config $Config `
        -PortName $PortName
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

Export-ModuleMember -Function Get-PowerMeterPorts, ConvertFrom-SecureValue, ConvertTo-PowerMeterServerOrigin, Read-PowerMeterCaCertificate, Open-PowerMeterPort, Invoke-PowerMeterRequest, Invoke-PowerMeterProvisioningTransaction, Select-PowerMeterPort
