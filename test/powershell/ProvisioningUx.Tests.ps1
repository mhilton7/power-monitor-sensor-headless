[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repo = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$modulePath = Join-Path $repo 'tools\PowerMeterSerial.psm1'
$provisionPath = Join-Path $repo 'tools\Provision-PowerMeterSensor.ps1'
Import-Module $modulePath -Force
$serialModule = Get-Module PowerMeterSerial
$script:Passed = 0

function Assert-True {
    param([Parameter(Mandatory)][bool]$Condition, [Parameter(Mandatory)][string]$Message)
    if (-not $Condition) { throw $Message }
}

function Assert-Equal {
    param($Actual, $Expected, [Parameter(Mandatory)][string]$Message)
    if ($Actual -cne $Expected) { throw $Message }
}

function Assert-ThrowsLike {
    param(
        [Parameter(Mandatory)][scriptblock]$Action,
        [Parameter(Mandatory)][string]$Pattern,
        [string]$ForbiddenPattern
    )
    $failure = $null
    try { & $Action } catch { $failure = $_.Exception }
    if ($null -eq $failure) { throw 'Expected the operation to fail.' }
    if ($failure.Message -notmatch $Pattern) {
        throw 'The operation failed without the required diagnostic.'
    }
    if ($ForbiddenPattern -and $failure.Message -match $ForbiddenPattern) {
        throw 'The failure diagnostic disclosed forbidden request content.'
    }
    return $failure.Message
}

function Invoke-TestCase {
    param([Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][scriptblock]$Action)
    try {
        & $Action
        $script:Passed++
        Write-Host "PASS $Name"
    } catch {
        throw "FAIL $Name`: $($_.Exception.Message)"
    }
}

$temporaryRoot = Join-Path ([IO.Path]::GetTempPath()) (
    'power-meter-provisioning-tests-' + [guid]::NewGuid().ToString('N')
)
[void][IO.Directory]::CreateDirectory($temporaryRoot)
$certificate = $null
$rsa = $null
try {
    $rsa = [Security.Cryptography.RSA]::Create(2048)
    $request = [Security.Cryptography.X509Certificates.CertificateRequest]::new(
        'CN=PowerMeter provisioning test CA',
        $rsa,
        [Security.Cryptography.HashAlgorithmName]::SHA256,
        [Security.Cryptography.RSASignaturePadding]::Pkcs1
    )
    $request.CertificateExtensions.Add(
        [Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]::new(
            $true,
            $false,
            0,
            $true
        )
    )
    $certificate = $request.CreateSelfSigned(
        [DateTimeOffset]::UtcNow.AddMinutes(-1),
        [DateTimeOffset]::UtcNow.AddDays(1)
    )
    $der = $certificate.Export([Security.Cryptography.X509Certificates.X509ContentType]::Cert)
    $base64 = [Convert]::ToBase64String(
        $der,
        [Base64FormattingOptions]::InsertLineBreaks
    ).Replace("`r`n", "`n")
    $validPem = "-----BEGIN CERTIFICATE-----`n$base64`n-----END CERTIFICATE-----`n"
    $validCaPath = Join-Path $temporaryRoot 'tls-ca.crt'
    [IO.File]::WriteAllText($validCaPath, $validPem, [Text.UTF8Encoding]::new($false))

    Invoke-TestCase 'canonical origin accepts no slash and one trailing slash' {
        Assert-Equal `
            (ConvertTo-PowerMeterServerOrigin 'https://power-monitor.home.arpa:8443') `
            'https://power-monitor.home.arpa:8443' `
            'Origin without a slash changed unexpectedly.'
        Assert-Equal `
            (ConvertTo-PowerMeterServerOrigin 'https://POWER-monitor.home.arpa:8443/') `
            'https://power-monitor.home.arpa:8443' `
            'One trailing slash was not removed from the canonical origin.'
    }

    Invoke-TestCase 'origin rejects insecure or non-origin URL forms' {
        $invalidOrigins = @(
            '',
            'http://power-monitor.home.arpa:8443',
            'https://@power-monitor.home.arpa:8443',
            'https://operator@power-monitor.home.arpa:8443',
            'https://power-monitor.home.arpa:8443/api',
            'https://power-monitor.home.arpa:8443//',
            'https://power-monitor.home.arpa:8443/?mode=test',
            'https://power-monitor.home.arpa:8443/?',
            'https://power-monitor.home.arpa:8443/#fragment',
            'https://power-monitor.home.arpa:8443/#',
            'https://power-monitor.home.arpa:8443\api',
            ' https://power-monitor.home.arpa:8443'
        )
        foreach ($origin in $invalidOrigins) {
            [void](Assert-ThrowsLike {
                ConvertTo-PowerMeterServerOrigin $origin
            } 'HTTPS origin only')
        }
    }

    Invoke-TestCase 'local PEM certificate is accepted without modification' {
        $actual = Read-PowerMeterCaCertificate -Path $validCaPath
        Assert-Equal $actual $validPem 'The validated CA PEM changed unexpectedly.'
    }

    Invoke-TestCase 'CA path rejects missing, directory, URL, and network forms' {
        $invalidPaths = @(
            '',
            (Join-Path $temporaryRoot 'missing.crt'),
            $temporaryRoot,
            'https://power-monitor.home.arpa/tls-ca.crt',
            '\\server\share\tls-ca.crt'
        )
        foreach ($path in $invalidPaths) {
            [void](Assert-ThrowsLike {
                Read-PowerMeterCaCertificate -Path $path
            } 'readable existing local certificate file')
        }
    }

    Invoke-TestCase 'CA content rejects invalid PEM before serial access' {
        $invalidPemPath = Join-Path $temporaryRoot 'invalid.crt'
        [IO.File]::WriteAllText(
            $invalidPemPath,
            "-----BEGIN PUBLIC KEY-----`nZmFrZQ==`n-----END PUBLIC KEY-----`n",
            [Text.UTF8Encoding]::new($false)
        )
        [void](Assert-ThrowsLike {
            Read-PowerMeterCaCertificate -Path $invalidPemPath
        } 'PEM-encoded X\.509 certificates')
    }

    Invoke-TestCase 'CA content stays at or below the device limit' {
        $maximumAcceptedPath = Join-Path $temporaryRoot 'maximum-accepted.crt'
        $maximumAcceptedPem = $validPem + (' ' * (4096 - $validPem.Length))
        [IO.File]::WriteAllText(
            $maximumAcceptedPath,
            $maximumAcceptedPem,
            [Text.UTF8Encoding]::new($false)
        )
        Assert-Equal `
            (Read-PowerMeterCaCertificate -Path $maximumAcceptedPath) `
            $maximumAcceptedPem `
            'A valid 4096-byte CA bundle was rejected.'

        $characterLimitPath = Join-Path $temporaryRoot 'too-many-characters.crt'
        $characterLimitPem = $validPem + (' ' * (4097 - $validPem.Length))
        [IO.File]::WriteAllText(
            $characterLimitPath,
            $characterLimitPem,
            [Text.UTF8Encoding]::new($false)
        )
        [void](Assert-ThrowsLike {
            Read-PowerMeterCaCertificate -Path $characterLimitPath
        } 'must not exceed the device limit of 4096 UTF-8 bytes or characters.*maximum 4096')

        $byteLimitPath = Join-Path $temporaryRoot 'too-many-bytes.crt'
        [IO.File]::WriteAllText(
            $byteLimitPath,
            ([string][char]0x00e9 * 2049),
            [Text.UTF8Encoding]::new($false)
        )
        [void](Assert-ThrowsLike {
            Read-PowerMeterCaCertificate -Path $byteLimitPath
        } 'must not exceed the device limit of 4096 UTF-8 bytes or characters.*maximum 4096')
    }

    Invoke-TestCase 'Provision script validates trailing-slash origin and CA before COM' {
        $secureValue = ConvertTo-SecureString 'test-only-value' -AsPlainText -Force
        [void](Assert-ThrowsLike {
            & $provisionPath -Port 'COM_TEST_MUST_NOT_OPEN' -FriendlyName 'Test sensor' `
                -WifiSsid 'Test Wi-Fi' -WifiPassword $secureValue `
                -ServerOrigin 'https://power-monitor.home.arpa:8443/' `
                -CaCertificatePath (Join-Path $temporaryRoot 'missing-before-com.crt') `
                -EnrollmentToken $secureValue
        } 'readable existing local certificate file' 'test-only-value')
        [void](Assert-ThrowsLike {
            & $provisionPath -Port 'COM_TEST_MUST_NOT_OPEN' -FriendlyName 'Test sensor' `
                -WifiSsid 'Test Wi-Fi' -WifiPassword $secureValue `
                -ServerOrigin 'https://power-monitor.home.arpa:8443/' `
                -CaCertificatePath (Join-Path $temporaryRoot 'invalid.crt') `
                -EnrollmentToken $secureValue
        } 'PEM-encoded X\.509 certificates' 'test-only-value')
        [void](Assert-ThrowsLike {
            & $provisionPath -Port 'COM_TEST_MUST_NOT_OPEN' -FriendlyName 'Test sensor' `
                -WifiSsid 'Test Wi-Fi' -WifiPassword $secureValue `
                -ServerOrigin 'https://power-monitor.home.arpa:8443/' `
                -CaCertificatePath (Join-Path $temporaryRoot 'too-many-characters.crt') `
                -EnrollmentToken $secureValue
        } 'must not exceed the device limit of 4096 UTF-8 bytes or characters.*maximum 4096' `
            'test-only-value')
    }

    Invoke-TestCase 'serial timeout classifier covers ERROR_SEM_TIMEOUT and read/write timeout' {
        $semaphoreTimeout = [IO.IOException]::new(
            'localized Windows serial failure',
            [int]0x80070079
        )
        $win32Timeout = [ComponentModel.Win32Exception]::new(121)
        $ordinaryIo = [IO.IOException]::new('The port was disconnected.')
        $ordinaryReadTimeout = [TimeoutException]::new('normal read poll elapsed')
        Assert-True `
            (& $serialModule { param($failure) Test-PowerMeterSerialTimeoutException $failure } `
                $ordinaryReadTimeout) `
            'TimeoutException was not classified as a serial timeout.'
        Assert-True `
            (& $serialModule {
                param($failure) Test-PowerMeterOrdinaryReadTimeoutException $failure
            } $ordinaryReadTimeout) `
            'A plain read TimeoutException was not classified as an ordinary poll timeout.'
        Assert-True `
            (-not (& $serialModule {
                param($failure) Test-PowerMeterOrdinaryReadTimeoutException $failure
            } $semaphoreTimeout)) `
            'ERROR_SEM_TIMEOUT was incorrectly classified as an ordinary read poll.'
        Assert-True `
            (& $serialModule { param($failure) Test-PowerMeterSerialTimeoutException $failure } `
                $semaphoreTimeout) `
            'Windows ERROR_SEM_TIMEOUT was not classified as a serial timeout.'
        Assert-True `
            (& $serialModule { param($failure) Test-PowerMeterSerialTimeoutException $failure } `
                $win32Timeout) `
            'Win32 ERROR_SEM_TIMEOUT was not classified as a serial timeout.'
        Assert-True `
            (-not (& $serialModule {
                param($failure) Test-PowerMeterSerialTimeoutException $failure
            } $ordinaryIo)) `
            'An unrelated I/O exception was incorrectly classified as a timeout.'
    }

    Invoke-TestCase 'write timeout is actionable and redacted' {
        $fakeSerial = [pscustomobject]@{
            Failure = [IO.IOException]::new('write timeout', [int]0x80070079)
        }
        $fakeSerial | Add-Member ScriptMethod WriteLine { param($line) throw $this.Failure }
        $message = Assert-ThrowsLike {
            & $serialModule {
                param($serial)
                Invoke-PowerMeterSerialWrite -Serial $serial `
                    -Line '{"request_canary":"must-not-appear"}' -Operation 'begin_config'
            } $fakeSerial
        } 'Firmware is not servicing USB provisioning.*serial write.*RESET.*boot log.*Preserve' `
            'must-not-appear|NVS|factory reset'
        Assert-True ($message -match 'Repair-PowerMeterSensor\.ps1 -Action Status') `
            'Write-timeout guidance omitted the safe status-only recovery command.'
    }

    Invoke-TestCase 'ordinary read timeout polls for a delayed response' {
        $delayedSerial = [pscustomobject]@{
            RequestId = $null
            ReadCalls = 0
            WriteCalls = 0
        }
        $delayedSerial | Add-Member ScriptMethod WriteLine {
            param($line)
            $request = $line | ConvertFrom-Json
            $this.RequestId = $request.id
            $this.WriteCalls++
        }
        $delayedSerial | Add-Member ScriptMethod ReadLine {
            $this.ReadCalls++
            if ($this.ReadCalls -eq 1) {
                throw [TimeoutException]::new('normal five-second read poll elapsed')
            }
            return [ordered]@{
                protocol = 'pm-com/1.0.0'
                id = $this.RequestId
                ok = $true
                stage = 'delayed_response'
            } | ConvertTo-Json -Compress
        }
        $response = & $serialModule {
            param($serial)
            Invoke-PowerMeterRequestCore -Serial $serial -Operation 'test_config'
        } $delayedSerial
        Assert-Equal $delayedSerial.WriteCalls 1 'The delayed request was written more than once.'
        Assert-Equal $delayedSerial.ReadCalls 2 'The request did not poll after one read timeout.'
        Assert-Equal $response.stage 'delayed_response' 'The delayed response was not returned.'

        $failedSerial = [pscustomobject]@{
            Failure = [IO.IOException]::new('Windows semaphore failure', [int]0x80070079)
        }
        $failedSerial | Add-Member ScriptMethod ReadLine { throw $this.Failure }
        [void](Assert-ThrowsLike {
            & $serialModule {
                param($serial)
                Read-PowerMeterSerialLine -Serial $serial -Operation 'hello'
            } $failedSerial
        } 'Firmware is not servicing USB provisioning.*serial read.*RESET.*boot log.*Preserve' `
            'NVS|factory reset')

        $deadlineSerial = [pscustomobject]@{}
        $deadlineSerial | Add-Member ScriptMethod WriteLine { param($line) }
        $deadlineSerial | Add-Member ScriptMethod ReadLine {
            throw [TimeoutException]::new('normal five-second read poll elapsed')
        }
        [void](Assert-ThrowsLike {
            & $serialModule {
                param($serial)
                Invoke-PowerMeterRequestCore -Serial $serial -Operation 'test_config' `
                    -Fields @{ request_canary = 'deadline-must-not-appear' } `
                    -Deadline ([DateTimeOffset]::UtcNow.AddSeconds(-1))
            } $deadlineSerial
        } 'Firmware is not servicing USB provisioning.*protocol response.*RESET.*boot log.*Preserve' `
            'deadline-must-not-appear|NVS|factory reset')
    }

    Invoke-TestCase 'commit attempt and confirmation boundaries are fail-closed' {
        $postCommitSerial = [pscustomobject]@{
            Operations = @()
            PendingId = $null
            PendingOperation = $null
        }
        $postCommitSerial | Add-Member ScriptMethod WriteLine {
            param($line)
            $request = $line | ConvertFrom-Json
            $this.PendingId = $request.id
            $this.PendingOperation = $request.op
            $this.Operations = @($this.Operations) + $request.op
        }
        $postCommitSerial | Add-Member ScriptMethod ReadLine {
            if ($this.PendingOperation -eq 'safe_reboot') {
                throw [IO.IOException]::new('Windows semaphore failure', [int]0x80070079)
            }
            return [ordered]@{
                protocol = 'pm-com/1.0.0'
                id = $this.PendingId
                ok = $true
                stage = if ($this.PendingOperation -eq 'commit_config') {
                    'committed'
                } else {
                    'tested'
                }
            } | ConvertTo-Json -Compress
        }
        [void](Assert-ThrowsLike {
            & $serialModule {
                param($serial)
                Invoke-PowerMeterProvisioningTransactionCore -Serial $serial `
                    -Config ([ordered]@{ request_canary = 'post-commit-must-not-appear' }) `
                    -PortName 'COM9'
            } $postCommitSerial
        } 'Configuration is committed.*Safe reboot was not performed.*Repair-PowerMeterSensor\.ps1 -Port COM9 -Action SafeReboot.*Do not rerun provisioning' `
            'post-commit-must-not-appear|NVS|factory reset')
        Assert-Equal `
            ($postCommitSerial.Operations -join ',') `
            'begin_config,test_config,commit_config,safe_reboot' `
            'Post-commit reboot failure incorrectly invoked rollback_config.'

        $lostCommitSerial = [pscustomobject]@{
            Operations = @()
            PendingId = $null
            PendingOperation = $null
        }
        $lostCommitSerial | Add-Member ScriptMethod WriteLine {
            param($line)
            $request = $line | ConvertFrom-Json
            $this.PendingId = $request.id
            $this.PendingOperation = $request.op
            $this.Operations = @($this.Operations) + $request.op
        }
        $lostCommitSerial | Add-Member ScriptMethod ReadLine {
            if ($this.PendingOperation -eq 'commit_config') {
                throw [TimeoutException]::new('commit response was lost')
            }
            return [ordered]@{
                protocol = 'pm-com/1.0.0'
                id = $this.PendingId
                ok = $true
                stage = 'tested'
            } | ConvertTo-Json -Compress
        }
        [void](Assert-ThrowsLike {
            & $serialModule {
                param($serial)
                Invoke-PowerMeterProvisioningTransactionCore -Serial $serial `
                    -Config ([ordered]@{ request_canary = 'lost-commit-must-not-appear' }) `
                    -PortName 'COM9' -RequestTimeoutSeconds 0
            } $lostCommitSerial
        } 'commit_config request was attempted.*response was not confirmed.*may already be committed.*Do not roll back, reuse the enrollment token.*Repair-PowerMeterSensor\.ps1 -Port COM9 -Action Status.*provisioned=true.*SafeReboot.*provisioned=false.*new enrollment token.*reprovision' `
            'lost-commit-must-not-appear|NVS|factory reset')
        Assert-Equal `
            ($lostCommitSerial.Operations -join ',') `
            'begin_config,test_config,commit_config' `
            'A lost commit response incorrectly invoked rollback or safe reboot.'

        $preCommitSerial = [pscustomobject]@{
            Operations = @()
            PendingId = $null
            PendingOperation = $null
        }
        $preCommitSerial | Add-Member ScriptMethod WriteLine {
            param($line)
            $request = $line | ConvertFrom-Json
            $this.PendingId = $request.id
            $this.PendingOperation = $request.op
            $this.Operations = @($this.Operations) + $request.op
        }
        $preCommitSerial | Add-Member ScriptMethod ReadLine {
            return [ordered]@{
                protocol = 'pm-com/1.0.0'
                id = $this.PendingId
                ok = $this.PendingOperation -ne 'test_config'
                error = if ($this.PendingOperation -eq 'test_config') {
                    'simulated_precommit_failure'
                } else {
                    $null
                }
            } | ConvertTo-Json -Compress
        }
        [void](Assert-ThrowsLike {
            & $serialModule {
                param($serial)
                Invoke-PowerMeterProvisioningTransactionCore -Serial $serial `
                    -Config ([ordered]@{ request_canary = 'pre-commit-must-not-appear' }) `
                    -PortName 'COM9'
            } $preCommitSerial
        } 'Device rejected test_config: simulated_precommit_failure' `
            'pre-commit-must-not-appear')
        Assert-Equal `
            ($preCommitSerial.Operations -join ',') `
            'begin_config,test_config,rollback_config' `
            'A pre-commit failure did not invoke exactly one rollback_config.'
    }

    Write-Host "PowerMeter provisioning UX tests passed: $script:Passed"
} finally {
    if ($null -ne $certificate) { $certificate.Dispose() }
    if ($null -ne $rsa) { $rsa.Dispose() }
    if ([IO.Directory]::Exists($temporaryRoot)) {
        foreach ($file in [IO.Directory]::GetFiles($temporaryRoot)) {
            [IO.File]::Delete($file)
        }
        [IO.Directory]::Delete($temporaryRoot, $false)
    }
}
