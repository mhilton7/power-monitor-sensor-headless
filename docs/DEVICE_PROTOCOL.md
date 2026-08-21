# Device protocol

Authentication, enrollment, command envelopes, provisioning, and OTA retain shared identifier `pm-protocol/1.0.0`. Stateless measurements use the additive transport identifier `pm-telemetry/2.0.0` on:

```text
POST /api/v1/device/telemetry/v2
```

Every device request carries `X-PM-Protocol: pm-protocol/1.0.0`, device ID, Unix-second timestamp, a random 16-byte lowercase-hex nonce, lowercase SHA-256 of the exact body, and a base64 HMAC-SHA256 signature. Canonical form is:

```text
PM-HMAC-SHA256-V1
UPPERCASE_METHOD
/path?key=percent-encoded-value&sorted=lexically
timestamp
nonce_hex
content_sha256_hex
```

TLS chain and hostname verification remain mandatory. Direction-separated 32-byte keys are derived with HKDF-SHA256 from the enrolled secret, `pm-protocol/1.0.0`, and the canonical device UUID. Response body hash, signature, timestamp window, and nonce replay are verified before any response content is applied.

Each telemetry request identifies one independently acceptable sample by `(sensor_id, boot_id, sample_sequence)`. `boot_id` is a random UUID generated on every boot and `sample_sequence` is RAM-only and monotonic within that boot. Neither value is a persistent acknowledgement cursor. A missing sequence never blocks a later sample.

The request includes nullable PZEM values, cumulative PZEM watt-hours, PZEM status, sampling time/trust state, uptime, RSSI, firmware version, the exact 64-character lowercase ELF build ID, and bounded command results. Missing values are JSON `null`; a measured zero remains zero. The server may use a monotonic cumulative-energy difference to account for outage energy, but it must not invent the missing power curve.

A signed success response contains `accepted` or `duplicate`, the exact sample identity, server receive time, timestamp source, versioned telemetry cadence, and bounded command envelopes. Authentication, schema, identity, and semantic failures use ordinary signed/controlled HTTP problem responses; no contiguous acknowledgement, gap request, backlog cursor, or missing-prefix response exists in telemetry v2.

The canonical request/response schemas and HMAC vector are mirrored byte-for-byte in `test/contracts/device-stateless-telemetry-v2.schema.json`, `test/contracts/server-stateless-telemetry-v2-response.schema.json`, and `test/vectors/stateless-telemetry-v2.json`.

USB repair is the separate `pm-com/1.0.0` newline-delimited JSON protocol. Browser code communicates only with the central server and never receives device keys.
