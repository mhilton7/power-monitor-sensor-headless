# PowerShell provisioning

Provisioning uses USB Serial/JTAG JSON Lines `pm-com/1.0.0`; it never starts Wi-Fi AP provisioning or a sensor HTTP server. Hold the physical recovery input at boot only when repair is intended.

```powershell
$wifi = Read-Host 'Wi-Fi password' -AsSecureString
$token = Read-Host 'One-time enrollment token' -AsSecureString
.\tools\Provision-PowerMeterSensor.ps1 -Port COM7 -FriendlyName 'Main panel' `
  -WifiSsid 'Home-IoT' -WifiPassword $wifi `
  -ServerOrigin 'https://power-monitor.home.arpa:8443/' `
  -CaCertificatePath .\tls-ca.crt `
  -EnrollmentToken $token -Ipv4Mode DHCP -CtRatingA 100 `
  -PzemVariant pzem-004t-v4-classic -Timezone America/Los_Angeles
```

Copy the server's CA certificate to a local file named `tls-ca.crt` in the
current directory before running the command. `CaCertificatePath` accepts only
a readable local filesystem file, not a URL, UNC/network path, directory, or
PowerShell provider. The file must contain only PEM-encoded X.509 certificates
and must be no more than 4,096 characters or UTF-8 bytes. The firmware stores
that content in a 4,097-byte buffer including the terminating NUL. The script
validates
the origin and certificate before opening the COM port. `ServerOrigin` accepts
one optional trailing slash and removes it; it still rejects insecure HTTP,
paths, query strings, fragments, and user information.

Static mode additionally requires `-Ipv4Address`, `-Ipv4Gateway`, `-Ipv4Netmask`, and `-DnsPrimary`; `-DnsSecondary` is optional. The script discovers ports when `-Port` is omitted and displays only a SHA-256-derived device fingerprint, firmware version, provisioning state, and sequence floor.

The device writes the inactive config slot, reads and CRC-checks it, then tests association, IP, DNS/TLS chain and hostname, and one-time enrollment. Only after all stages pass does it atomically select that slot. A failed stage invokes rollback and preserves the prior committed slot. Wi-Fi password, token, device secret, directional HMAC keys, private keys, cookies, and administrator credentials are never echoed. Avoid PowerShell transcription while entering secrets.

Rollback is attempted only before `commit_config` is sent. If its response is
lost, configuration may already be committed: do not roll back, reuse the
enrollment token, or retry provisioning. After the device responds, run
`Repair-PowerMeterSensor.ps1 -Action Status`. If `provisioned=true`, run
`-Action SafeReboot`; if `provisioned=false`, obtain a new enrollment token and
reprovision. If commit was confirmed but the subsequent safe reboot fails, the
selected configuration remains committed and the tool likewise does not issue
`rollback_config`; retry only `-Action SafeReboot` after the device responds.

An ordinary five-second serial read timeout is a poll interval, not an immediate
failure; the tool continues waiting through the 30-second request deadline so
Wi-Fi, TLS, and enrollment tests can finish. A Windows semaphore or write I/O
timeout is surfaced immediately. If the final deadline expires, the tool
explains that firmware is not servicing USB provisioning. Close other serial
monitors, leave USB connected, press and release RESET once, wait for boot to
finish, and retry. If it repeats, capture the serial boot log from reset through
the timeout and preserve the existing configuration and device identity. Use
`.\tools\Repair-PowerMeterSensor.ps1 -Port COM7 -Action Status` only after the
device responds.
