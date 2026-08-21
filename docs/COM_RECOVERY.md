# COM recovery

USB recovery is entered only when configuration is missing or a configured unit receives the debounced physical GPIO0 recovery request during the three-second application window. An ordinary AP, DNS, TLS, or server outage remains in headless retry and does not enter recovery.

For a configured unit, reset with BOOT/GPIO0 released so the installed application starts. During the logged three-second recovery window, press and hold BOOT until the application confirms the request, then release it. Holding BOOT during reset selects the ROM download strap instead of application recovery.

```powershell
.\tools\Repair-PowerMeterSensor.ps1 -Port COM7 -Action Status
.\tools\Repair-PowerMeterSensor.ps1 -Port COM7 -Action RollbackConfiguration
.\tools\Repair-PowerMeterSensor.ps1 -Port COM7 -Action SafeReboot
```

Recovery exposes only redacted status and permits rollback of an uncommitted candidate or a safe reboot. The active stateless image does not offer SD operations, backlog synchronization, sensor-side History deletion, or a configuration factory-reset action in the repair tool. Its safe-reboot barrier has no telemetry writer to drain; it clears candidate state, completes the USB response, drains USB TX, and then reboots.

Normal meter, measurement, command, network, and OTA tasks do not start in the isolated maintenance boot. Candidate rollback never erases the committed slot, immutable identity, enrollment credentials, or OTA checkpoint.

For a Windows semaphore/write failure or request timeout, close other serial monitors, keep USB connected, press and release RESET once, and capture the boot log if it repeats. If `commit_config` may have succeeded before the response was lost, do not reuse the enrollment token. Wait for the device, run `Status`, and use `SafeReboot` when `provisioned=true`; obtain a new token only when the device confirms it remains unprovisioned.
