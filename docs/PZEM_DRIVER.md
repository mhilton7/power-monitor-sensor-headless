# PZEM driver

`pm_meter_driver_t` is a versioned interface. The physical implementation is explicitly named `pzem-004t-v4-classic-candidate`; no generic V3 library or Arduino runtime is present. Production compilation fails unless a variant and marked-unit evidence are selected.

Candidate transaction: UART1 GPIO17/18, 9600 8N1, slave 1. The eight-byte request is `01 04 00 00 00 0A` plus little-endian Modbus CRC16. The response must be exactly 25 bytes, matching slave/function and CRC. It decodes voltage (0.1 V), current (32-bit low/high, 0.001 A), active power (32-bit low/high, 0.1 W), cumulative energy (32-bit low/high, Wh), frequency (0.1 Hz), and power factor (0.01). Frames are rejected for timeout, short length, CRC, wrong slave/function, or bounded range failure.

The one-second sampler retains UTC trust and monotonic time. One-minute aggregation uses fixed-point units. Validated cumulative PZEM energy deltas are the only selected energy source. Backward motion, reset, rollover, or implausible jump is flagged and left missing unless a trustworthy delta exists. Trapezoidal power integration is stored only as diagnostic evidence. Current warnings occur at 80%/90% of the configured CT rating. Routine reboot, data reset, SD format, and OTA never reset the PZEM counter.

Exact physical register/scaling/counter behavior remains pending per `HARDWARE_IDENTITY.md`.
