# Device protocol

Normal API identifier is `pm-protocol/1.0.0`. Enrollment returns a random device UUID and secret once over verified TLS. HKDF-SHA256 uses the UTF-8 bytes of `pm-protocol/1.0.0`, a NUL byte, and the canonical hyphenated device UUID as salt. Its exact info bytes are `PowerMeter V2`, a NUL byte, then either `device-to-server` or `server-to-device`, producing direction-separated 32-byte keys.

Every device request includes protocol, device ID, Unix-second timestamp, 16-byte random nonce as lowercase hex, lowercase SHA-256 of the exact body, and a base64-encoded HMAC-SHA256 signature. Canonical form is:

```text
PM-HMAC-SHA256-V1
UPPERCASE_METHOD
/path?key=percent-encoded-value&sorted=lexically
timestamp
nonce_hex
content_sha256_hex
```

Percent escapes are uppercased, query parts sort lexically, and malformed/control/fragment/plus input is rejected. Comparisons are constant-time. The server durably rejects request nonce replay. Firmware verifies the exact response body hash and a `RESPONSE` canonical signature with the server-to-device key, enforces the five-minute timestamp window, and rejects response nonce replay through a bounded cache. TLS chain/hostname verification remains mandatory even with HMAC.

The exact outbound POST endpoints and locked representative bodies are declared in `test/vectors/server-contract.json`:

```text
/api/v1/devices/enroll
/api/v1/device/heartbeat
/api/v1/device/readings
/api/v1/device/permanent-loss
```

Heartbeats carry live validated PZEM status, storage/time diagnostics, an array of command results, and stable health strings. Required alert strings emitted when their evidence is present are `pzem_unavailable`, `microsd_missing`, `microsd_read_only`, `microsd_nearly_full`, `microsd_full`, `microsd_corrupt_segment`, `time_untrusted`, `backlog_present`, `tls_validation_failure`, `wifi_repeated_failure`, `ota_failed`, and `ota_rolled_back`. Batch sync sends immutable records with identical content for a retry. Firmware never selects diagnostic power integration as authoritative energy. The server deduplicates `(device_id, sequence)`, acknowledges only after commit, and returns the highest contiguous ack/gaps. Firmware rejects ack regression, reports deterministic permanent-loss ranges, and never deletes data above verified ack. Browser code never receives device keys or talks to the sensor.

The command contract also locks credential rotation. Prepare and cancel results use the currently active old device-to-server key. Commit arrives under the old server-to-device key; only after its durable intent is recorded does firmware activate the staged candidate and send the exact commit result under the new device-to-server key. The server must retain overlap acceptance through that authenticated result. No response, diagnostic, browser payload, or log contains the candidate secret.

USB repair is a distinct `pm-com/1.0.0` newline-delimited JSON protocol documented separately; it is not exposed over Wi-Fi.
