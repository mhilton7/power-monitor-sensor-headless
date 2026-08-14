# Architecture

The firmware is deliberately headless. Browser traffic terminates at the central server; normal device traffic is outbound HTTPS. Configuration and secrets use transactional NVS, outage history uses microSD, and internal flash never becomes a readings database.

```text
UART1/PZEM -> measurement(12) -> fixed sample queue -> interval(9)
                                                    -> storage queue -> storage(8) -> FAT32 journal
latest validated sample --------------------------> network(7) -> HTTPS heartbeat/batches
server commands -> network -> control(6) -> storage/OTA/safe reboot
USB Serial/JTAG -> provisioning(6; recovery only) -> A/B config transaction
supervisor(5) -> task watchdog, health flags, stack/heap diagnostics
```

All queues are static and bounded. Measurement never performs network I/O and waits only for a bounded queue operation. Storage is the sole card owner and never performs DNS/TLS. Network is the normal Wi-Fi/DNS/TLS/HTTP owner and gives heartbeat precedence over backlog. OTA runs in an ephemeral 12,288-byte task; USB recovery is enabled only when unprovisioned or physically requested. Tasks use finite waits and the application watchdog; high-water marks are reported in hardware evidence.

The deterministic states are `BOOT`, `SELF_TEST`, `UNPROVISIONED_COM`, `CONNECTING_WIFI`, `ENROLLING`, `RUNNING`, `DEGRADED_NETWORK`, `DEGRADED_SERVER`, `DEGRADED_METER`, `DEGRADED_STORAGE`, `OTA_PENDING`, `OTA_INSTALLING`, `MAINTENANCE_SLEEP`, `RECOVERY_COM`, and `SAFE_REBOOT`. Typed health flags may coexist with the primary state. A server outage degrades connectivity but does not invoke COM recovery or stop measurement/storage.

Components own one concern each: `pm_config` board/config/state; `pm_meter` versioned PZEM transport; `pm_measurement` fixed-point aggregation; `pm_storage` binary journal and sequence/ack state; `pm_protocol` SHA-256/HMAC/HKDF/canonicalization/time; `pm_network` Wi-Fi and outbound HTTP; `pm_commands` durable idempotency ledger; `pm_ota` inactive-slot OTA; `pm_provisioning` JSONL repair; `pm_diagnostics` bounded redacted health.
