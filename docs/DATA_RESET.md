# Server data reset after stateless cutover

The active stateless image has no sensor-side History store and accepts no Format SD, Sync Backlog, Repair Storage, Verify Storage, or data-reset command. The sensor cannot delete server History and never mounts or formats an inserted microSD card.

Any authorized deletion of accepted History is a server-only operation scoped by the central application's permissions, home, sensor or service branch, and audit policy. It must not be represented as a sensor command, and it must not alter immutable sensor identity, enrollment credentials, Wi-Fi/static-IP/DNS settings, server origin or CA, PZEM configuration, provisioning state, or OTA recovery metadata.

The low-frequency configuration record retains its existing binary schema so deployed NVS remains readable across the RC16-to-RC17 update. Legacy sequence/reset fields in that record are compatibility padding only: the stateless runtime never reads or advances them as telemetry state and never writes NVS on a sample or delivery cycle.

Factory reset, unclaim/revocation, server History deletion, rate deletion, and log retention remain separate administrative actions. None is part of the RC17 telemetry or OTA workflow.
