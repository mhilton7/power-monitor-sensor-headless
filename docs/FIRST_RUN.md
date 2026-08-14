# First run

1. Complete the physical wiring review with mains disconnected. Insert a FAT32 high-endurance card.
2. Flash the checksum-verified release candidate.
3. With USB connected, run the provisioning script and verify its device fingerprint against the server enrollment event.
4. The firmware checks config A/B slots, sequence/ack state, command ledger, OTA checkpoint, card mount/self-test, and meter identity gate.
5. It samples and journals during ordinary Wi-Fi/server outages. The first healthy authenticated heartbeat reports firmware, state, live PZEM status, storage range, ack, and diagnostics.
6. Confirm the server treats the one-CT sensor as `energy_only`, then observe authenticated intervals and an acknowledgement that never regresses.

Before trusted UTC, records retain monotonic and sequence evidence with `time_untrusted`; they are not fabricated into dated History. A missing/unverified PZEM yields missing data, not zero or simulated production readings. A missing/corrupt SD leaves live measurement/heartbeat available in typed degraded storage.
