# PowerMeter Sensor Headless 0.1.0-rc.4

This release candidate carries forward the ESP32-S3 headless measurement agent, authenticated outbound protocol, append-only microSD outage journal, USB/COM provisioning and repair, durable commands, and dual-slot OTA rollback. RC4 updates only release identity and immutable cross-repository traceability for the audited server RC4 contract. Firmware runtime behavior, device protocol, schemas, configuration, and hardware-certification status remain unchanged from public RC3.

Its exact enrollment, heartbeat, reading-batch, permanent-loss, OTA-download, destructive-command, credential-rotation, HKDF, and base64 HMAC contracts are locked by cross-repository vectors and validated against the compatible PowerMeter V2 server `v0.1.0-rc.4`. The complete generated server OpenAPI document is bound by SHA-256 `f9b936468f5a696a0bee3e04edda021c12ab81dddc091cbb307face0be1de7b1`. Firmware also authenticates server response bytes, timestamps, and nonces before applying acknowledgements or commands.

Credential rotation stages the server-generated candidate in an inactive CRC/read-back-verified config slot, commits under the old directional key, reports activation under the new key, and retains a byte-stable result until authenticated acknowledgement. The A/B rotation and destructive-operation journals resume after power loss at each durable boundary; secret-bearing temporary buffers and consumed tokens are explicitly zeroized.

The PZEM-004T V4-classic register layout remains a candidate driver. Stable production promotion is blocked until the exact marked unit, TTL electrical behavior, register map, OTA rollback, and 72-hour soak pass the machine-readable hardware certification gate. The release-candidate build therefore refuses to present simulated samples as production evidence.

All energy, interval, completeness, and uploaded history evidence originates only from validated PZEM frames. Utility-bill content is outside this firmware and cannot enter its measurement or storage path.
