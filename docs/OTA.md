# OTA and rollback

The server sends `ota_install` as the flat 17-field payload defined by `release/ota-device-manifest.schema.json`. It binds the device, deployment, release, semantic version and numeric build, project `power-monitor-sensor-headless`, target `esp32s3`, board `esp32-s3-devkitc-n16r8-reference/1`, minimum boot/config/protocol, exact size/SHA-256, same-origin download path, and fresh nonce. `signature` is padded standard Base64 for the 32-byte HMAC-SHA256 result. The signing key is the enrolled device's HKDF `server-to-device` key, never a release-global key.

The canonical bytes are UTF-8, contain no trailing newline, and are exactly:

```text
PM-OTA-MANIFEST-V1
schema
device_id
deployment_id
release_id
semantic_version
build_number
project_name
target_chip
board_profile
minimum_boot_version
minimum_config_version
minimum_protocol
image_size
sha256
download_path
manifest_nonce
```

Firmware verifies the manifest compatibility and HMAC before opening the download. It derives the absolute URL only by joining the configured verified-HTTPS server origin to the signed same-origin path. The GET body is empty and the request carries all six `PM-HMAC-SHA256-V1` headers signed with the device-to-server key. Redirects are disabled. The only accepted response is HTTP 200 with the exact content length, ETag equal to the quoted manifest digest, and all six response-authentication headers. The complete response body SHA-256 and the server-to-device response HMAC are verified before the OTA image is finalized or selected.

Range resume is deliberately not used in version 1: interruption safely restarts from byte zero, `esp_ota_begin` erases the inactive range, and no prior partial bytes are trusted. Bytes stream only into the inactive 0x780000 OTA slot while PSA SHA-256 is computed. A mismatch, incomplete body, bad response signature, or transport error aborts the OTA handle; no partial image is selected. Project/version metadata is read from the written partition before the boot partition changes.

CRC-protected A/B OTA checkpoints record manifest verification, bytes, hash, image verification, boot selection, validation, rollback, or error. Progress is real and monotonic. On the next boot, validation checks project/target by the bootloader/app metadata, readable config, running scheduler/watchdog, storage initialized or typed degraded, and network retry capability. It must not fail solely because Wi-Fi, server, SD, PZEM, or an external site is temporarily unavailable. Only then is the image marked valid; otherwise ESP-IDF rollback remains active.

The release `manifest.json` is compatibility metadata validated by `release/manifest.schema.json` and explicitly requires the server to add per-device nonce/signature; firmware never accepts it directly. The resulting authenticated runtime shape is documented separately by `release/ota-device-manifest.schema.json`.
