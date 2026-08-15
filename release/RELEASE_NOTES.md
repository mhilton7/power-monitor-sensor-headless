# PowerMeter Sensor Headless 0.1.0-rc.3

This release candidate carries forward the ESP32-S3 headless measurement agent, authenticated outbound protocol, append-only microSD outage journal, USB/COM provisioning and repair, durable commands, and dual-slot OTA rollback. RC3 corrects only immutable cross-repository OpenAPI traceability and version coordination after the server RC2 publication gate rejected firmware RC2's stale full-byte OpenAPI hash. Firmware runtime behavior, device protocol, schemas, configuration, and hardware-certification status remain unchanged from RC2.

Its exact enrollment, heartbeat, reading-batch, permanent-loss, OTA-download, destructive-command, credential-rotation, HKDF, and base64 HMAC contracts are locked by cross-repository vectors and validated against the compatible PowerMeter V2 server `v0.1.0-rc.3`. Firmware also authenticates server response bytes, timestamps, and nonces before applying acknowledgements or commands.

Credential rotation stages the server-generated candidate in an inactive CRC/read-back-verified config slot, commits under the old directional key, reports activation under the new key, and retains a byte-stable result until authenticated acknowledgement. The A/B rotation and destructive-operation journals resume after power loss at each durable boundary; secret-bearing temporary buffers and consumed tokens are explicitly zeroized.

The PZEM-004T V4-classic register layout remains a candidate driver. Stable production promotion is blocked until the exact marked unit, TTL electrical behavior, register map, OTA rollback, and 72-hour soak pass the machine-readable hardware certification gate. The release-candidate build therefore refuses to present simulated samples as production evidence.

All energy, interval, completeness, and uploaded history evidence originates only from validated PZEM frames. Utility-bill content is outside this firmware and cannot enter its measurement or storage path.
