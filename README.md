# PowerMeter V2 headless sensor

Greenfield ESP-IDF firmware for an ESP32-S3 N16R8-class measurement agent. It samples one PZEM-004T channel and sends independent latest-value telemetry through outbound authenticated HTTPS. The central server is the sole durable History owner; firmware has no persistent measurement queue and never mounts, reads, writes, or formats microSD. It has no runtime web server, local UI, MQTT, relay, load control, remote shell, scripting engine, or third-party telemetry.

The sole sensor authority for voltage, current, power, frequency, power factor, and cumulative energy is an authenticated PZEM frame accepted by the selected meter driver. Missing evidence remains missing; a measured zero remains zero. Server-side History may safely use monotonic PZEM cumulative-energy deltas across connection gaps, but never invents a missing power curve. A one-CT unit is `energy_only` and must not be inferred to represent whole-home usage or solar export.

## Release status

`0.1.0-rc.21` is the fixed-cadence telemetry repair for PowerMeter V2 server `v0.1.0-rc.21`. Successful HTTPS delivery advances from the prior scheduled deadline, so request latency no longer stretches the configured interval or creates artificial missing samples. It uses `pm-telemetry/2.0.0`, preserves `pm-protocol/1.0.0` for control/authentication/OTA, and binds the generated server OpenAPI SHA-256 `6d276b738467c867d062ab78b6cdc76d246f15d5aca7e2c505cddabf9b6f2c24`. RC17 remains immutable failed-candidate evidence, and RC18 through RC20 remain immutable public evidence. The active build excludes SD, backlog, missing-prefix, and contiguous-acknowledgement components. `CONFIG_PM_HARDWARE_IDENTITY_VERIFIED` remains disabled, release artifacts remain `hardware_certification: pending`, and stable promotion still requires exact marked-unit evidence, electrical validation, and the 72-hour suite; see [hardware identity](docs/HARDWARE_IDENTITY.md) and [hardware certification](docs/HARDWARE_CERTIFICATION.md).

## Build and test

```powershell
Set-Location E:\Documents\ChatGPT\PowerMonitorV2\power-monitor-sensor-headless
. C:\Espressif\tools\Microsoft.v6.0.2.PowerShell_profile.ps1
.\tools\Run-HostTests.ps1
idf.py -B build-rc -D 'SDKCONFIG=build-rc/sdkconfig' `
  -D 'SDKCONFIG_DEFAULTS=sdkconfig.defaults;sdkconfig.release-candidate' set-target esp32s3 build
```

Do not energize mains wiring until the marked hardware, isolation, level translation, enclosure, fusing, conductor ratings, and installation have been reviewed by a qualified person. Never connect an unverified 5 V PZEM TX directly to ESP32 GPIO. Detailed wiring and flash/provision commands are in [BUILD_AND_FLASH.md](docs/BUILD_AND_FLASH.md), [WIRING.md](docs/WIRING.md), and [POWERSHELL_PROVISIONING.md](docs/POWERSHELL_PROVISIONING.md).

Telemetry: `pm-telemetry/2.0.0`. Control/authentication/OTA: `pm-protocol/1.0.0`. USB recovery: `pm-com/1.0.0`. License: MIT.
