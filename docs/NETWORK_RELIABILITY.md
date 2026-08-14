# Network reliability

The event-driven station uses finite association waits and exponential backoff with jitter (approximately 0.875–1.125 of 1, 2, 4, 8, 16, 32, then 60 seconds). AP disconnect, DHCP/static validation, DNS/TLS, HTTP status, timeout, and reset errors are typed. Ordinary outage does not reboot or write NVS repeatedly; measurement and SD logging remain independent.

One task owns normal Wi-Fi/DNS/TLS/HTTP state. Requests use the configured CA PEM, HTTPS URL, built-in hostname verification, redirects disabled, bounded 8 KiB request/4 KiB response limits, and 12-second deadline. There is no insecure fallback. Cleanup closes the client on every path.

Heartbeat defaults to 15 seconds. A backlog batch starts only if its worst-case request can finish at least five seconds before the next heartbeat; a batch contains at most 16 records here, below the protocol ceiling of 500. Reconnect attempts resume automatically. Simulation asserts heartbeat priority during a large backlog, sequence/ack monotonicity, and no permanent request latch; physical LAN recovery timing and heap/TLS margins remain HIL evidence.
