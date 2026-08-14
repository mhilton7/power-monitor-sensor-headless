# PowerShell provisioning

Provisioning uses USB Serial/JTAG JSON Lines `pm-com/1.0.0`; it never starts Wi-Fi AP provisioning or a sensor HTTP server. Hold the physical recovery input at boot only when repair is intended.

```powershell
$wifi = Read-Host 'Wi-Fi password' -AsSecureString
$token = Read-Host 'One-time enrollment token' -AsSecureString
.\tools\Provision-PowerMeterSensor.ps1 -Port COM7 -FriendlyName 'Main panel' `
  -WifiSsid 'Home-IoT' -WifiPassword $wifi `
  -ServerOrigin 'https://power-monitor.home.arpa:8443' `
  -CaCertificatePath C:\Secure\power-monitor-root-ca.pem `
  -EnrollmentToken $token -Ipv4Mode DHCP -CtRatingA 100 `
  -PzemVariant pzem-004t-v4-classic -Timezone America/Los_Angeles
```

Static mode additionally requires `-Ipv4Address`, `-Ipv4Gateway`, `-Ipv4Netmask`, and `-DnsPrimary`; `-DnsSecondary` is optional. The script discovers ports when `-Port` is omitted and displays only a SHA-256-derived device fingerprint, firmware version, provisioning state, and sequence floor.

The device writes the inactive config slot, reads and CRC-checks it, then tests association, IP, DNS/TLS chain and hostname, and one-time enrollment. Only after all stages pass does it atomically select that slot. A failed stage invokes rollback and preserves the prior committed slot. Wi-Fi password, token, device secret, directional HMAC keys, private keys, cookies, and administrator credentials are never echoed. Avoid PowerShell transcription while entering secrets.
