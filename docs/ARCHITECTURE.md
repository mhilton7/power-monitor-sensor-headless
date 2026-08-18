# Architecture

The firmware is deliberately headless. Browser traffic terminates at the central server, and normal device traffic is outbound authenticated HTTPS. The sensor keeps configuration, identity, command recovery, and OTA recovery in transactional NVS, but the central server is the sole durable owner of measurements and History.

```text
UART1/PZEM -> measurement task -> latest-value slot -> network task -> telemetry/v2
                                   (one in-flight + newest pending)
server commands <- signed telemetry response <- network <- reboot/OTA/control task
USB Serial/JTAG -> provisioning/recovery -> preserved A/B configuration
supervisor -> task watchdog, time observation, bounded health diagnostics
```

The active component graph contains `pm_meter`, `pm_telemetry`, `pm_network`, `pm_protocol`, `pm_commands`, `pm_ota`, `pm_provisioning`, `pm_config`, and `pm_diagnostics`. It does not contain `pm_storage`, `pm_measurement`, FATFS, or SDMMC. The firmware has no SD pin definitions and never mounts, reads, writes, repairs, erases, or formats a card.

Measurement never performs network I/O. It offers a validated PZEM sample to a fixed-size RAM slot once per second. The slot permits one in-flight and one newest pending sample; replacing a pending sample is intentional and cannot grow memory. Each offer receives a sequence scoped only to a random per-boot UUID. Sequences are not persisted and do not form an acknowledgement cursor.

The network task owns Wi-Fi, DNS, TLS, signed HTTP, response verification, and server-provided telemetry cadence. Wi-Fi and server retries have separate exponential backoff state, bounded jitter, and a 60-second maximum. An outage drops failed samples, keeps measurement/watchdogs alive, and makes the newest reading eligible immediately after recovery. It does not reboot or reset configuration.

USB recovery is an isolated maintenance boot enabled only when unprovisioned or physically requested. Required runtime tasks start behind a common gate. The local OTA rollback gate runs before the network task is released and proves task/configuration/retry readiness only; server-side OTA completion requires a later authenticated v2 sample with the expected firmware version and full ELF build ID.

Every first-party object is compiled with a 3,072-byte frame limit and independently audited from the pinned ESP-IDF build inventory. Physical high-water, electrical, and long-duration evidence remains a separate hardware-in-loop gate.
