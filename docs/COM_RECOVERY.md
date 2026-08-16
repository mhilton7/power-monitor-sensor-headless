# COM recovery

`RECOVERY_COM` is entered for missing/invalid configuration, repeated failure of a never-valid candidate, physical GPIO0 recovery request, incompatible rollback configuration, or a boot-loop threshold. A temporary server/AP outage is not a recovery trigger.

For a configured unit, reset with BOOT/GPIO0 released so the ROM starts the
installed firmware. When the boot log announces the three-second physical
recovery window, press and hold BOOT until the log confirms the debounced
request, then release it. Normal configured boots deliberately wait for this
bounded three-second window; holding BOOT during reset instead enters the ROM
download strap and does not request application recovery.

```powershell
.\tools\Repair-PowerMeterSensor.ps1 -Port COM7 -Action Status
.\tools\Repair-PowerMeterSensor.ps1 -Port COM7 -Action RollbackConfiguration
.\tools\Repair-PowerMeterSensor.ps1 -Port COM7 -Action SafeReboot
```

Recovery exposes only a redacted fingerprint/status. Recovery is an isolated
maintenance boot: the normal meter, measurement, journaling producer, command,
network, and OTA tasks are not started while candidate Wi-Fi/configuration is
being tested. Candidate rollback does not erase the committed slot, and the
prior committed configuration is used again after reboot. Safe reboot drains
the storage worker before its acknowledgement is transmitted, drains USB TX,
and then restarts into the normal runtime.

For a surfaced Windows semaphore/write failure or final request timeout, close
other serial monitors, keep USB connected, press and release RESET once, and
capture the boot log from reset through the timeout if the problem repeats.
Preserve the existing configuration and device identity. Run the status-only
command above only after firmware resumes servicing USB provisioning.

If provisioning reports an unconfirmed `commit_config` response, configuration
may already be committed. Do not roll back, reuse the enrollment token, or
repeat provisioning. After the device responds, run `Status`: when
`provisioned=true`, run `SafeReboot`; when `provisioned=false`, obtain a new
enrollment token and reprovision. If provisioning instead confirms that
configuration is committed but safe reboot was not performed or confirmed,
run only `SafeReboot` after the device responds.

A configuration factory reset additionally requires the physical input, a 60-second device-generated token, `-WhatIf`/ShouldProcess confirmation, and typed text `RESET <device-fingerprint>`. It is distinct from server reading deletion, SD format, log clearing, or server unclaim. It does not silently reset lifetime sequence identity.
