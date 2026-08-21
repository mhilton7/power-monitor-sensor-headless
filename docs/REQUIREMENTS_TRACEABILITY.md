# Stateless firmware traceability

The active build is `main/app_main_stateless.c` plus the component dependencies reachable from `main/CMakeLists.txt`. Legacy storage, interval, backlog, and heartbeat source is retained only as unbuilt audit history.

| Required firmware proof | Production evidence | Automated evidence | Physical status |
|---|---|---|---|
| 1–3: build without SD; never mount/write SD | active graph excludes `pm_storage`, FATFS, SDMMC and all SD pins | `test_stateless_telemetry.py` active-graph/source scan | HIL `no_sd_runtime_access` pending |
| 4: no telemetry NVS | telemetry slot/backoff are fixed RAM structs; config/command/OTA recovery only use NVS | active telemetry source rejects NVS APIs | HIL `no_telemetry_nvs_writes` pending |
| 5–6: independent samples; 10 does not block 11 | `(sensor_id, boot_id, sample_sequence)` with RAM-only per-boot sequence | `test_pm_telemetry.c`, mirrored schemas/vectors | HIL independent/gap cases pending |
| 7–8: no persistent queue; newest pending replaces older | one in-flight plus newest pending; failed sample cleared | 100,000-offer bound and replacement assertions | HIL latest-value outage case pending |
| 9–10: outages never factory-reset | ordinary retry path has no restart, erase, or config mutation | active-source scan and bounded retry tests | Wi-Fi/server recovery HIL pending |
| 11–12: recovery resumes telemetry | Wi-Fi success resets both backoffs and makes telemetry due now; server success resets server backoff | scheduler/backoff tests and source-order assertions | recovery HIL pending |
| 13–15: identity, Wi-Fi, OTA survive reboot | immutable identity NVS, A/B config, CRC OTA/command checkpoints remain | config/command/OTA recovery regressions and active-source checks | preservation HIL pending |
| 16: watchdog safety | required runtime tasks register and reset watchdogs | startup/source tests and stack-frame audit | watchdog HIL pending |
| 17: stable memory during outage | fixed telemetry structs; one bounded network workspace; no growing queue | 100,000-offer test and resident-count bound | repeated-outage/72-hour HIL pending |
| 18–19: no SD format or NVS erase | no active format command and no `nvs_flash_erase`/`nvs_erase_all` in runtime graph | active-source and command-map scans | no-SD HIL pending |
| 20: OTA version confirmation | reports SemVer and 64-char ELF build ID after local boot validation | contract/build-ID/OTA ordering tests | server confirmation and OTA HIL pending |

Control/authentication/OTA remain `pm-protocol/1.0.0`; independent telemetry is the additive `pm-telemetry/2.0.0` contract. No physical certification or successful sensor deployment is inferred from host/build evidence.
