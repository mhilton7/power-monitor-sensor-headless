# Security policy

Report vulnerabilities privately to the repository owner; do not place exploit details or device credentials in a public issue.

Security invariants include verified TLS chain/hostname with no fallback, direction-separated HMAC keys and nonce replay defense, bounded parsers/queues/bodies, transactional encrypted production NVS, physical authorization plus typed confirmation for factory reset, immutable sequence/content semantics, OTA hash/metadata/rollback, and fail-closed hardware identity. Logs and COM responses redact secrets.

Never commit Wi-Fi credentials, enrollment/device/fixture tokens, HMAC keys, CA private keys, certificates provisioned to a unit, NVS/SD dumps, crash dumps containing user data, build output, or hardware photos with sensitive installation details. Revoke/rotate affected enrollment immediately if exposure is suspected.
