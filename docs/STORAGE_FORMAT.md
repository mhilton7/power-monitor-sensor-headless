# Retired microSD journal format

This document describes unbuilt legacy evidence only. The active stateless production graph does not include the storage component, FATFS, SDMMC, an SD mount point, SD GPIO definitions, journal serialization, sequence reservation, backlog upload, or formatting. An inserted card is ignored.

Historical source under `components/pm_storage` and the read-only `tools/decode_journal.py` decoder remain available for forensic review of an old card copy. They must not be linked into a current firmware image or used to translate card records into current telemetry. The central server's already accepted History remains authoritative and must not be deleted or rewritten during migration.

If an operator needs to inspect retired evidence, first make a read-only forensic copy outside the repository. Never run a write, repair, erase, or format operation against either physical sensor card. The decoder accepts only an explicit copied segment path:

```powershell
python .\tools\decode_journal.py E:\forensic-copy\powermeter\seg_1_100.bin
```

Decoder output is diagnostic historical evidence, not a valid `pm-telemetry/2.0.0` request and not authorization to import readings.
