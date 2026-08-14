# Hardware certification

Status: **pending**. `release/hardware-certification-status.json` is the machine-readable RC status. It is not pass evidence and cannot promote a stable tag.

The physical suite covers marked-unit PZEM frames and CRC/wrong-slave rejection; SD write/recovery; sequence/ack replay; valid and invalid TLS; HMAC replay; AP/server/DNS outages; physical power cycling; USB recovery; OTA success and forced rollback; watchdog recovery; and a continuous minimum 72-hour soak. It records attempted/authenticated samples, explained/unexplained reboots, gaps, and sequence regressions.

The operator builds the certification candidate from `sdkconfig.defaults;sdkconfig.release` with the intended stable SemVer, provisions the required NVS-encryption HMAC key on the marked unit, and flashes that exact reproducible binary before running HIL. Setting the compile-time hardware flag merely permits the candidate driver to participate in this test; it is not certification evidence and cannot publish a stable release. The resulting evidence records that binary's SHA-256, and stable automation must reproduce the same image byte-for-byte before promotion.

Passing evidence uses `pm-hardware-certification/1.0.0`, validates against `release/hardware-certification.schema.json`, names the exact Git repository/commit/image SHA, includes hashed physical photos/markings and measured UART electrical behavior, and has different, independent operator/reviewer signoffs. `signoff.record_sha256` is SHA-256 of UTF-8 JSON after removing only that field, recursively sorting keys, using separators `(',', ':')`, `ensure_ascii=false`, `allow_nan=false`, preserving array order, and adding no newline.

Certification is detached so it never has to contain the hash of the commit that adds itself. For source commit `<commit>`, the operator creates a signed annotated tag `hardware-certification-<commit>` pointing to that exact commit. Its annotation contains exactly `hardware-certification-sha256: <sha256>` for the canonical evidence file, and the GitHub Release for that tag carries `hardware-certification.json`. Stable automation verifies the tag's cryptographic signature through GitHub, the signed annotation-to-asset digest, the JSON Schema and semantic rules, the source commit, and the rebuilt production image SHA. The evidence file is never committed to the source tree.

Stable semantic gate:

```powershell
python .\test\hardware\verify_evidence.py C:\Secure\hardware-certification.json `
  --firmware-commit (git rev-parse HEAD) --firmware-sha256 (Get-FileHash .\firmware.bin -Algorithm SHA256).Hash.ToLowerInvariant()
```

Every test boolean must be true; authenticated samples must be positive and no greater than attempts; duration and timestamps must cover at least 72 hours; unexplained reboots and sequence regressions must be zero. Simulation, seller text, another unit, or manually edited status cannot substitute.
