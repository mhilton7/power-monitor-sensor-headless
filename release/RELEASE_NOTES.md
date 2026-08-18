# PowerMeter Sensor Headless 0.1.0-rc.17

RC17 is the coordinated stateless-telemetry firmware for PowerMeter V2 server `v0.1.0-rc.17` (firmware build 20). It adds the independent sensor transport `pm-telemetry/2.0.0` while preserving the shared authenticated control, enrollment, provisioning, and OTA protocol `pm-protocol/1.0.0`. The final generated server OpenAPI document is bound by SHA-256 `c2aaa98fc0d31402eac7bd38495838ce830cd21242bc1b32a2929ed7da712e41`.

Production firmware no longer links or starts the microSD storage, interval, backlog, adaptive-batch, contiguous-acknowledgement, or missing-prefix components. It never mounts, reads, writes, repairs, verifies, erases, or formats an inserted card. Existing accepted server History is not changed, and legacy firmware source remains only as unbuilt audit history. Public RC15 and RC16 remain immutable and installable.

Each validated PZEM sample is independently identified by immutable sensor ID, a random per-boot UUID, and a RAM-only monotonically increasing sample sequence. Runtime memory holds at most one in-flight sample and the newest pending sample. A newer pending sample replaces an older unsent sample; a failed request is not persisted and cannot block a later reading. Missing readings therefore remain honest connection gaps.

Wi-Fi and server failures use separate bounded exponential backoff with jitter and a 60-second maximum. PZEM measurement and watchdog servicing continue while offline. Recovery immediately makes the newest reading eligible for delivery, and an ordinary Wi-Fi, DNS, TLS, timeout, authentication, or server outage does not erase configuration, factory-reset, or reboot the device.

The telemetry body reports PZEM cumulative watt-hours when valid. The server may use a monotonic counter difference to recover total outage energy without inventing a power curve; counter decreases remain explicit resets. All missing measurement fields remain null, while measured zero remains zero.

Sensor identity, Wi-Fi/static-IP/DNS settings, server origin, CA, enrolled directional keys, PZEM configuration, USB provisioning/recovery, signed digest-verified inactive-slot OTA, and CRC-protected OTA/command recovery remain preserved in NVS. Telemetry samples, delivery state, and sample acknowledgements are never written to NVS. Firmware never calls `nvs_flash_erase`.

The ESP-IDF post-boot rollback check proves only that configuration, required tasks, watchdogs, stateless telemetry runtime, and bounded network retry capability were created. That local validation does not complete the server-side OTA deployment. The server must keep the deployment pending until the same authenticated sensor later reports the expected semantic version and complete 64-character lowercase ELF build identifier.

RC17 remains a release candidate: `CONFIG_PM_HARDWARE_IDENTITY_VERIFIED=n`, hardware certification is pending, and no physical sensor migration or OTA success is claimed by this release build. Stable promotion still requires exact marked-unit electrical, rollback, recovery, and soak evidence.
