# Network reliability

The stateless runtime separates Wi-Fi association/IP recovery from server request recovery. Both use exponential backoff with bounded jitter, starting near one second and capped at 60 seconds. A 100 ms control loop prevents tight retry spinning, association waits are finite, HTTPS requests have a 12-second deadline, and measurement/control/supervisor watchdogs continue to run.

AP disconnect, missing IP, DNS/TLS failure, HTTP rejection, timeout, reset, and response-limit failure do not reboot the device, erase NVS, reset configuration, or create a persistent queue. The measurement task continues to replace the newest pending RAM sample. When Wi-Fi returns, server backoff resets and the newest reading is immediately eligible. When only the server is unavailable, Wi-Fi remains up and server retry continues independently.

One task owns normal Wi-Fi, DNS, TLS, signed HTTP, and response verification. It uses the configured CA PEM and HTTPS origin, built-in hostname verification, redirects disabled, an 8 KiB request limit, a 4 KiB response limit, and no insecure fallback.

The normal cadence is server-selected from 2, 5, 10, 15, 30, or 60 seconds. A successful request advances from the prior scheduled deadline, skipping only elapsed slots; request latency does not accumulate into cadence drift. A failed in-flight sample is dropped. At most the newest pending sample remains, so recovery never waits for an old gap or backlog.

Host tests prove the fixed-size slot, independent sample 10/11 behavior, pending replacement, 100,000-offer memory bound, retry cap/reset, and fixed-deadline scheduling. Physical access-point, DNS, server restart, TLS, memory, watchdog, and 72-hour recovery evidence remains pending HIL certification.
