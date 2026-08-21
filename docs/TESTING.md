# Testing

Run the current host evidence from the repository root:

```powershell
.\tools\Run-HostTests.ps1
```

The runner checks its selected Python interpreter before starting and fails with an actionable dependency message; it never installs floating packages. Use `-PythonPath <path>` for an existing environment populated from the fully hashed `test/host/requirements.txt` lock.

The stateless-focused suites validate the mirrored telemetry-v2 contract, independent acceptance identity, missing-sample 10 followed by sample 11, latest-value replacement, a strict two-sample RAM bound, 100,000 repeated offers, bounded Wi-Fi/server backoff, fixed cadence, no active SD/FATFS/storage graph, no telemetry NVS calls, no flash erase, preserved configuration/identity/OTA paths, exact build ID, command-result commit semantics, and release/HIL evidence shape.

The repository also retains tests for unbuilt legacy storage/backlog source as historical regression evidence. Their pass result does not mean that storage, backlog, contiguous acknowledgement, destructive storage commands, or legacy heartbeat synchronization is linked into the production image. CI labels those steps as legacy audit evidence and separately builds the active stateless graph.

CI uses pinned ESP-IDF v6.0.2, builds the release-candidate profile, verifies the active component inventory and PZEM cadence, enforces the OTA slot limit, and audits first-party stack frames. Native pure-C tests compile with warnings as errors; supported CI runners repeat suitable legacy audit parsers under sanitizers.

Physical certification uses `pm-hardware-certification/2.0.0`. It requires the marked ESP32-S3/PZEM/CT, isolated electrical measurements, proof that no SD or telemetry-NVS runtime access occurs, independent/later-sample acceptance, latest-value outage recovery, identity/config preservation, Wi-Fi/server recovery, TLS/HMAC rejection, OTA success/rollback/identity confirmation, COM recovery, watchdog recovery, bounded resident telemetry memory, and a continuous 72-hour soak. No physical pass is claimed in this repository.
