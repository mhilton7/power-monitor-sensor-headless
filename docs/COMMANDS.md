# Outbound commands

Commands arrive only in a signed, authenticated response to the sensor's outbound `POST /api/v1/device/telemetry/v2` request. The server never opens an inbound connection to the ESP32, and the firmware exposes no Wi-Fi web server, shell, or arbitrary execution surface.

The active stateless image accepts only:

- `reboot`
- `diagnostics_snapshot`
- `network_self_test`
- `meter_self_test`
- `ota_install`

The bounded CRC-protected NVS command ledger retains at most eight command identities and their recovery state. This is low-frequency command/OTA recovery metadata, not telemetry storage. It cannot contain measurement History, a delivery cursor, or a sample queue. Diagnostic and self-test commands may be safely requeued after an interrupted boot. Reboot and OTA use explicit post-boot reconciliation; an interrupted unsupported one-shot effect fails closed.

Command results are included in a telemetry-v2 request. A verified signed 2xx response means the server atomically committed that request, including its command results, so only those exact reported results are removed from the ledger. If the response is lost, the result remains and is resent idempotently. Authentication, schema, or semantic rejection never acknowledges a result.

`sync_now`, all storage check/repair/format commands, maintenance sleep, remote configuration mutation, credential rotation, and sensor-side data reset are not accepted by the active command mapping. Historical source and vectors for those retired commands remain unbuilt audit evidence only.

OTA remains sensor-initiated, TLS-verified, device-targeted, digest-checked, signature-checked, and written to the inactive application slot. Local post-boot validation proves only that configuration, required tasks, watchdog servicing, and bounded retry capability started. The server must keep the deployment pending until the same authenticated sensor reports the expected semantic version and full 64-character lowercase ELF build identifier.

The server-supplied telemetry configuration contains a version and one allowed RAM-only cadence: 2, 5, 10, 15, 30, or 60 seconds. Wi-Fi, TLS, identity, and enrollment configuration remain transactionally managed through physical USB provisioning/recovery and are never replaced by an arbitrary remote command.
