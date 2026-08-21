# PowerMeter Sensor Headless 0.1.0-rc.25

RC25 is the metadata-only coordinated firmware candidate for repaired PowerMeter V2 server `v0.1.0-rc.25` (deterministic firmware build 28). Runtime sources, partition layout, sdkconfig profiles, and dependency locks remain byte-identical to public firmware RC24. The image is rebuilt under the new immutable semantic version, so its embedded ESP-IDF application descriptor, ELF build identifier, and image digest must be independently verified and must not reuse RC24 values. It retains `pm-telemetry/2.0.0` plus authenticated control, enrollment, provisioning, and OTA under `pm-protocol/1.0.0`. The generated server OpenAPI document is bound by the exact SHA-256 recorded in `test/vectors/server-contract.json` and the release compatibility asset.

RC17 remains immutable failed-candidate evidence. RC18 through RC21 remain immutable public evidence and are never moved, rewritten, or relabeled. Firmware RC22 remains immutable public evidence; its signed tag and release assets are not moved or reused after the coordinated server RC22 deployment smoke failed before server release publication.

Production firmware no longer links or starts the microSD storage, interval, backlog, adaptive-batch, contiguous-acknowledgement, or missing-prefix components. It never mounts, reads, writes, repairs, verifies, erases, or formats an inserted card. Existing accepted server History is not changed, and legacy firmware source remains only as unbuilt audit history. Public RC15 and RC16 remain immutable and installable.

Each validated PZEM sample is independently identified by immutable sensor ID, a random per-boot UUID, and a RAM-only monotonically increasing sample sequence. Runtime memory holds at most one in-flight sample and the newest pending sample. A newer pending sample replaces an older unsent sample; a failed request is not persisted and cannot block a later reading. Missing readings therefore remain honest connection gaps.

Wi-Fi and server failures use separate bounded exponential backoff with jitter and a 60-second maximum. PZEM measurement and watchdog servicing continue while offline. Recovery immediately makes the newest reading eligible for delivery, and an ordinary Wi-Fi, DNS, TLS, timeout, authentication, or server outage does not erase configuration, factory-reset, or reboot the device.

The telemetry body reports PZEM cumulative watt-hours when valid. The server may use a monotonic counter difference to recover total outage energy without inventing a power curve; counter decreases remain explicit resets. All missing measurement fields remain null, while measured zero remains zero.

Sensor identity, Wi-Fi/static-IP/DNS settings, server origin, CA, enrolled directional keys, PZEM configuration, USB provisioning/recovery, signed digest-verified inactive-slot OTA, and CRC-protected OTA/command recovery remain preserved in NVS. Telemetry samples, delivery state, and sample acknowledgements are never written to NVS. Firmware never calls `nvs_flash_erase`.

The ESP-IDF post-boot rollback check proves only that configuration, required tasks, watchdogs, stateless telemetry runtime, and bounded network retry capability were created. That local validation does not complete the server-side OTA deployment. The server must keep the deployment pending until the same authenticated sensor later reports the expected semantic version and complete 64-character lowercase ELF build identifier.

RC25 remains a release candidate: `CONFIG_PM_HARDWARE_IDENTITY_VERIFIED=n`, hardware certification is pending, and no physical sensor migration or OTA success is claimed by this release build. Stable promotion still requires exact marked-unit electrical, rollback, recovery, and soak evidence.
