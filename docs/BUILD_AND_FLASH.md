# Build and flash

Required toolchain: ESP-IDF `v6.0.2`, target `esp32s3`, Python 3.11, CMake/Ninja supplied by Espressif. The only managed component is exactly `espressif/cjson==1.7.19~2` in `dependencies.lock`.

```powershell
Set-Location E:\Documents\ChatGPT\PowerMonitorV2\power-monitor-sensor-headless
. C:\Espressif\tools\Microsoft.v6.0.2.PowerShell_profile.ps1
git -C $env:IDF_PATH describe --tags --exact-match
.\tools\Run-HostTests.ps1
idf.py -B build-rc -D 'SDKCONFIG=build-rc/sdkconfig' `
  -D 'SDKCONFIG_DEFAULTS=sdkconfig.defaults;sdkconfig.release-candidate' set-target esp32s3 build
```

The version check must print `v6.0.2`. Debug/test/simulated overlays exist for their named purposes; a simulated-meter image must never be installed as production. Stable `sdkconfig.release` requires both marked-unit evidence and NVS encryption and is intentionally blocked while certification is pending.

To assemble the local RC artifact pack:

```powershell
.\tools\Build-Release.ps1 -Version 0.1.0-rc.1 -BuildNumber 1
.\tools\Flash-PowerMeterSensor.ps1 -Port COM7 -ArtifactDirectory .\release\out\0.1.0-rc.1
```

The flash utility verifies every SHA-256 in `flash_args.json`, then writes bootloader at `0x0`, partition table at `0x8000`, OTA data at `0x2D000`, and app at `0x40000`. It does not erase the 136 KiB NVS partition. `merged-flash.bin` is an offline recovery image; use the verified per-image script for normal flashing.

The 16 MB partition table provides NVS, NVS keys, OTA metadata, a bounded coredump partition, and two equal 0x780000-byte OTA slots. It reserves no flash history database.
