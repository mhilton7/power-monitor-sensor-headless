# microSD journal format

FAT32 directory `/sd/powermeter` contains append-only version-1 segments. `current.tmp` rotates atomically to `seg_<first>_<last>.bin` at a bounded size. The card UUID is independent of device identity; replacing/formatting a card cannot reset lifetime sequence state. Index data is only a rebuildable cache.

All integers are deterministic little-endian. A 96-byte `PMSG` header stores: magic/version/length at 0–7; device UUID 8–23; card UUID 24–39; segment UUID 40–55; first sequence 56–63; created UTC ms 64–71; created monotonic µs 72–79; time-trusted byte 80; reserved zero bytes 81–91; IEEE CRC32 over bytes 0–91 at 92–95.

Each 128-byte `PMRD` record stores: magic/version/length 0–7; device UUID 8–23; sequence 24–31; reset generation 32–35; flags 36–39; interval UTC start/end 40–55; monotonic start/end 56–71; valid/expected counts 72–79; completeness permille 80–81; selected source 82–83; fixed-point voltage/current/power/frequency/PF 84–103; PZEM start/end Wh 104–119; selected energy mWh 120–123; CRC32 over bytes 0–123 at 124–127.

Sequences reserve blocks of 64 transactionally in redundant NVS slots before use. Reboot may create a reported gap but never reuse a number. Maximum seen, ack, reset generation, and floor survive card replacement. Ack only moves forward and unacknowledged data is ineligible for ordinary reclamation.

Decode without modifying a card image:

```powershell
python .\tools\decode_journal.py E:\card-copy\powermeter\seg_1_100.bin
python .\tools\decode_journal.py --skip-corrupt E:\card-copy\powermeter\seg_1_100.bin
```
