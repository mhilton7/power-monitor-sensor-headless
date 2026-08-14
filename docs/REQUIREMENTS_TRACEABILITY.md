# Firmware requirements traceability

| Master section | Implementation/evidence | Status |
|---|---|---|
| 4 hardware/wiring | authoritative `pm_board.h`; candidate gated driver; HARDWARE_IDENTITY/REFERENCES/WIRING; HIL schema | RC complete; physical identity pending |
| 5 repository/toolchain | independent components; ESP-IDF 6.0.2/cJSON pins; configs/partitions; warnings-as-errors | automated |
| 6 states/tasks | `pm_state`; static queues; measurement/interval/storage/network/control/supervisor/ephemeral OTA/USB ownership | automated plus HIL stack margin pending |
| 7 COM provisioning | `pm-com/1.0.0`; A/B begin/test/commit/rollback; three PowerShell tools; redaction/physical reset | host-tested; physical USB pending |
| 8 PZEM | Modbus CRC/parser/status/ranges; fixed point; cumulative delta only; missing/zero/reset/rollover/CT flags | parser host-tested; marked hardware pending |
| 9 trusted time | redundant checkpoint; monotonic progression; SNTP/server sources; untrusted records never fabricated | host/fault simulation |
| 10 microSD | deterministic CRC journal/decoder; NVS sequence blocks/ack; recovery/quarantine/index; explicit format | host/fault simulation; physical endurance pending |
| 11 network/TLS | event Wi-Fi/backoff; one TLS owner; CA/hostname; bounded requests; heartbeat-first batching | simulation; physical recovery timing pending |
| 12 authentication | protocol 1.0.0; exact shared HKDF/base64 HMAC vectors; authenticated response hash/signature/timestamp/replay verification; exact enroll/heartbeat/readings/permanent-loss schemas/routes; immutable retry/ack | locked fixtures and live cross-repository schema/OpenAPI gate |
| 13 commands | A/B CRC ledger/all required types/states/idempotency/expiry/progress; token-zeroized destructive intent; restartable destructive and credential-rotation phase journals; old-to-new directional-key cutover; authenticated-result-ack cleanup | exhaustive crash-at-every-phase host models plus ESP-IDF build; physical power-cut HIL pending |
| 14 OTA | HMAC per-device manifest; inactive slot/stream hash/metadata/checkpoint/postboot rollback | host/fault plus build; physical success/rollback pending |
| 26 supply chain | CI/build/security/dependency/SBOM/provenance/release workflows; exact action/toolchain pins | local/workflow evidence; remote publication owned by release parent |
| 27 tests | host C/Python including credential-rotation reboot/expiry/key-cutover, 36 faults, 120-day simulator, physical HIL runner/verifier/schema | automated pass; HIL pending |
| 28 reliability | isolation/heartbeat/recovery/data/storage/OTA assertions and measured release reports | simulation pass; heap/stack/physical timing pending |
| 29 docs | every named firmware document plus security/traceability/migration/release notes | complete |
| 30 artifacts | assembler creates binaries/merged image/flash args/manifest/checksums/SBOM/provenance/reports/scripts | local RC artifact evidence |
| 31 Git discipline | checkpoint plus logical commits on feature branch; workflow prevents failed stable promotion | complete locally; no remote publication in delegated scope |

Cross-cutting invariant: firmware has no utility-bill input. Every durable usage/History value is created only from authenticated PZEM evidence. One-CT default scope remains `energy_only`.
