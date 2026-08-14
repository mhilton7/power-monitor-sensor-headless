# Migration from the reference sensor

This repository is a clean implementation. It does not import the reference firmware's configuration, sequence state, microSD files, credentials, or application code.

Migration is a controlled replacement:

1. Export no secrets or readings from the legacy sensor.
2. Build and flash this release candidate to a separately identified ESP32-S3 test unit.
3. Provision it with a new one-time server enrollment token and verify the displayed device fingerprint.
4. Complete the marked-unit hardware certification before stable deployment.
5. Run both sensors only if their CT placement and server scopes avoid double counting.
6. Retire or unclaim the old device through the server only after the new device has healthy authenticated heartbeats and readings.

Legacy microSD records are not accepted or translated because their identity, sequence, and evidence semantics are not this protocol's immutable journal format.
