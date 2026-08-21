# Retired storage recovery

There is no storage-recovery path in the active stateless image. The firmware never mounts, reads, writes, checks capacity, repairs, erases, or formats a microSD card, and it never redirects telemetry into flash/NVS. Missing, blank, full, read-only, or corrupt card state therefore cannot affect PZEM sampling, telemetry, commands, provisioning, or OTA.

Do not issue a storage command: the active command mapping rejects storage self-test, sync, repair, verify, and format operations. The browser/server must not offer those controls to a stateless sensor.

During migration, leave both physical cards untouched. Preserve already accepted server History and treat any legacy backlog metadata as read-only audit evidence. A network gap is recovered by resuming with the newest RAM measurement; there is intentionally no card replay, missing-prefix recovery, contiguous acknowledgement, or capacity status.

Historical storage implementation and recovery tests remain in the source tree only to explain older evidence. Their presence or test pass does not make them part of the production component graph.
