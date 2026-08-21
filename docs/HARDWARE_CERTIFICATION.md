# Hardware certification

Status: **pending**. `release/hardware-certification-status.json` is machine-readable status only and cannot promote a stable image.

The stateless physical suite uses `pm-hardware-certification/2.0.0`. It binds the exact repository commit and firmware SHA-256, pinned ESP-IDF v6.0.2, ESP32-S3 target, board profile, `pm-protocol/1.0.0`, and `pm-telemetry/2.0.0`. It records exact ESP32-S3, PZEM, CT, connector, and revision markings; hashed photographs; isolated UART electrical measurements; and independent operator/reviewer signoff.

Required marked-unit cases cover authenticated PZEM readings and CRC/wrong-slave rejection; proof of no SD runtime access and no telemetry NVS writes; independent acceptance of a later sample after a gap; newest-value recovery; Wi-Fi/server recovery; identity and configuration preservation; TLS chain/hostname and HMAC replay rejection; secure OTA success, rollback, and same-identity version confirmation; COM recovery; and watchdog recovery. Stress cases cover AP reboot, server restart, DNS outage, physical power cycle, and repeated-outage memory stability.

The 72-hour soak must report positive authenticated samples, zero unexplained reboots, zero identity changes, zero configuration losses, and no more than two resident telemetry samples. Connection gaps may exist and must remain visible; they are not treated as a failed backlog.

Setting the compile-time hardware flag only permits the candidate driver to participate. It is not certification. The evidence must validate against `release/hardware-certification.schema.json`, match the exact image reproduced by release automation, and pass `test/hardware/verify_evidence.py`. A seller page, PDF, simulation, manually edited status, or another physical unit is insufficient.

Certification remains detached: a signed annotated tag `hardware-certification-<commit>` points to the exact source commit and its annotation binds the canonical evidence SHA-256. No secret fixture token or certification evidence containing installation details is committed to this repository.
