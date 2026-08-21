# Migration to stateless sensor firmware

Deploy server support for `pm-telemetry/2.0.0` before installing this firmware. Confirm independent sample acceptance, live-state updates, History bucketing, and continued legacy-firmware service during the transition.

For each existing sensor:

1. Record its immutable sensor ID, display name, reported version/build ID, and the presence—not the values—of Wi-Fi/TLS/enrollment configuration.
2. Install the signed, digest-verified OTA image without erasing NVS and without formatting or inspecting the microSD card.
3. Keep deployment pending while the sensor reboots. Local ESP-IDF post-boot validation is not server confirmation.
4. Require a later authenticated telemetry-v2 sample from the same sensor ID with the expected semantic version and complete 64-character lowercase ELF build ID.
5. Verify current telemetry, visible connection gaps, Wi-Fi recovery, server recovery, identity preservation, and configuration preservation.
6. Migrate the second sensor only after the first remains healthy.

After both sensors report telemetry v2, disable active legacy backlog processing on the server, remove SD/backlog controls from the browser, and retain accepted server History and legacy synchronization records as read-only evidence. Never translate a card journal into current telemetry, wait for a contiguous acknowledgement, erase NVS, or format either physical card.

Do not automatically flash or deploy a physical sensor from tests or release automation. Stable installation remains blocked until the exact marked-unit `pm-hardware-certification/2.0.0` evidence passes.
