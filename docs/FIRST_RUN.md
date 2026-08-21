# First run

1. With mains disconnected, verify the exact PZEM/CT installation and UART level translation against `docs/WIRING.md`. No microSD card is required or used.
2. Flash the checksum-verified release-candidate image. Do not erase NVS when updating an already provisioned sensor.
3. Connect USB and run `tools/Provision-PowerMeterSensor.ps1` only for a new/unprovisioned unit. Verify the displayed device fingerprint against the server enrollment event.
4. The firmware validates the A/B configuration, immutable identity, command ledger, OTA checkpoint, PZEM profile, and runtime task set. It does not mount or inspect an inserted card.
5. Confirm that signed `pm-telemetry/2.0.0` samples arrive with the same sensor identity. The latest live PZEM values should continue after Wi-Fi or server recovery; connection gaps remain visible.
6. Confirm the server assigns each one-CT sensor to the intended explicit service branch. Do not infer whole-home scope or add a new sensor to an aggregate automatically.

Before UTC is trusted, `sampled_at` is null and `time_status` is `untrusted`; the server uses its authenticated receive time. A missing or unverified PZEM produces null measurement fields and an explicit status, never simulated production readings or fabricated zeroes.

An inserted microSD card is electrically and logically ignored by the active image. Do not format it as part of installation or recovery.
