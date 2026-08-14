# PowerMeter V2 headless sensor

Greenfield ESP-IDF firmware for an ESP32-S3 N16R8-class measurement agent. It samples one PZEM-004T channel, creates one-minute durable intervals, journals them to microSD, and communicates only through outbound authenticated HTTPS. It has no runtime web server, local UI, MQTT, relay, load control, remote shell, scripting engine, or third-party telemetry.

The sole authority for voltage, current, power, frequency, power factor, cumulative energy, interval energy, completeness, and upload history is an authenticated PZEM frame accepted by the selected meter driver. Missing evidence remains missing; a measured zero remains zero. Power integration is diagnostic only and is never substituted for a missing or suspect PZEM cumulative-energy delta. A one-CT unit is `energy_only` and must not be inferred to represent whole-home usage or solar export.

## Release status

`0.1.0-rc.1` is buildable and host-tested, but physical certification is pending. The selected `pzem-004t-v4-classic-candidate` request/register layout is disabled unless its marked unit has machine-readable evidence. Stable builds also require encrypted NVS. Simulation cannot open either gate; see [hardware identity](docs/HARDWARE_IDENTITY.md) and [hardware certification](docs/HARDWARE_CERTIFICATION.md).

## Build and test

```powershell
Set-Location E:\Documents\ChatGPT\PowerMonitorV2\power-monitor-sensor-headless
. C:\Espressif\tools\Microsoft.v6.0.2.PowerShell_profile.ps1
.\tools\Run-HostTests.ps1
idf.py -B build-rc -D 'SDKCONFIG=build-rc/sdkconfig' `
  -D 'SDKCONFIG_DEFAULTS=sdkconfig.defaults;sdkconfig.release-candidate' set-target esp32s3 build
```

Do not energize mains wiring until the marked hardware, isolation, level translation, enclosure, fusing, conductor ratings, and installation have been reviewed by a qualified person. Never connect an unverified 5 V PZEM TX directly to ESP32 GPIO. Detailed wiring and flash/provision commands are in [BUILD_AND_FLASH.md](docs/BUILD_AND_FLASH.md), [WIRING.md](docs/WIRING.md), and [POWERSHELL_PROVISIONING.md](docs/POWERSHELL_PROVISIONING.md).

Protocol: `pm-protocol/1.0.0`. USB recovery protocol: `pm-com/1.0.0`. License: MIT.
