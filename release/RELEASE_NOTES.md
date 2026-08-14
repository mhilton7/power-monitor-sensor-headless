# PowerMeter Sensor Headless 0.1.0-rc.1

This first greenfield release candidate implements the ESP32-S3 headless measurement agent, authenticated outbound protocol, append-only microSD outage journal, USB/COM provisioning and repair, durable commands, and dual-slot OTA rollback.

Its exact enrollment, heartbeat, reading-batch, permanent-loss, HKDF, and base64 HMAC contracts were validated against the compatible PowerMeter V2 server `v0.1.0-rc.1`. Firmware also authenticates server response bytes, timestamps, and nonces before applying acknowledgements or commands.

The PZEM-004T V4-classic register layout remains a candidate driver. Stable production promotion is blocked until the exact marked unit, TTL electrical behavior, register map, OTA rollback, and 72-hour soak pass the machine-readable hardware certification gate. The release-candidate build therefore refuses to present simulated samples as production evidence.

All energy, interval, completeness, and uploaded history evidence originates only from validated PZEM frames. Utility-bill content is outside this firmware and cannot enter its measurement or storage path.
