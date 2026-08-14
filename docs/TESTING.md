# Testing

Run all host evidence from the repository root:

```powershell
.\tools\Run-HostTests.ps1
```

The runner executes 55 Python unit/model tests, the named 36-case power/config/format/OTA/SD/PZEM/network/server/command fault matrix, and an accelerated 120-day integration. The integration covers 10,368,000 one-second samples, 172,800 durable intervals, randomized outages/restarts/corruption, backlog/ack, commands, OTA, and time trust. CI additionally compiles and runs 63 pure production C parser/aggregation/journal assertions with `-Wall -Wextra -Werror`, repeats them under ASan/UBSan, and builds the entire ESP-IDF image.

Assertions include PZEM request/CRC/ranges; energy reset/rollover; missing-vs-zero; deterministic record/CRC; trailing recovery/index/retention; A/B config and sequence reservation; ack monotonicity/card replacement; state/backoff/heartbeat priority; TLS classification; HMAC canonicalization/HKDF/replay; command expiry/idempotency/prepare; credential-rotation crashes at every durable boundary, old/new key transition, expiry/cancel/zeroization; OTA hash/compatibility/rollback; COM transaction/redaction; no old-data replay; and no deadlock/permanent latch.

Physical HIL requires an isolated fixture, actual marked unit, Python dependencies in `test/hardware/requirements.txt`, a controller token supplied only as `PM_HIL_FIXTURE_TOKEN`, and at least 72 hours:

```powershell
python -m pip install --require-hashes -r .\test\hardware\requirements.txt
idf.py -B build-certification `
  -D 'SDKCONFIG=build-certification/sdkconfig' `
  -D 'SDKCONFIG_DEFAULTS=sdkconfig.defaults;sdkconfig.release' `
  -D 'PM_FIRMWARE_VERSION=0.1.0' set-target esp32s3 build
.\tools\Run-HardwareCertification.ps1 -Port COM7 -Fixture C:\Secure\marked-unit-fixture.json `
  -FirmwareBin .\build-certification\power-monitor-sensor-headless.bin -Version 0.1.0 `
  -DurationHours 72 -Output C:\Secure\hardware-certification.json
```

The wrapper converts the interactive secure token only for the child process and clears it immediately; do not put it in command history or source control. Hardware was unavailable for this RC, so no physical pass is claimed.
