# COM recovery

`RECOVERY_COM` is entered for missing/invalid configuration, repeated failure of a never-valid candidate, physical GPIO0 recovery request, incompatible rollback configuration, or a boot-loop threshold. A temporary server/AP outage is not a recovery trigger.

```powershell
.\tools\Repair-PowerMeterSensor.ps1 -Port COM7 -Action Status
.\tools\Repair-PowerMeterSensor.ps1 -Port COM7 -Action RollbackConfiguration
.\tools\Repair-PowerMeterSensor.ps1 -Port COM7 -Action SafeReboot
```

Recovery exposes only a redacted fingerprint/status. When meter/storage remain valid, measurement and journaling continue. Candidate rollback does not erase the committed slot. Safe reboot checkpoints/flushes before restart.

A configuration factory reset additionally requires the physical input, a 60-second device-generated token, `-WhatIf`/ShouldProcess confirmation, and typed text `RESET <device-fingerprint>`. It is distinct from server reading deletion, SD format, log clearing, or server unclaim. It does not silently reset lifetime sequence identity.
