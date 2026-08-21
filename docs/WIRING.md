# Reference wiring and electrical safety

The only authoritative pin map is `components/pm_config/include/pm_board.h`, profile `esp32-s3-devkitc-n16r8-reference/1`.

| Function | ESP32-S3 pin | Connection |
|---|---:|---|
| PZEM UART1 TX | GPIO17 | through a verified push-pull UART level translator to PZEM RX |
| PZEM UART1 RX | GPIO18 | through a verified level translator from PZEM TX |
| physical recovery | GPIO0 | hold low at boot; do not repurpose without board review |

Use the translator's logic side at 3.3 V and its PZEM side at the measured/verified interface reference. Join low-voltage grounds only as required by the exact isolated interface design. A typical passive bidirectional MOSFET board intended for open-drain I²C is not automatically suitable for push-pull UART edges. Never connect an unverified 5 V output to an ESP32 GPIO.

The supplied PZEM-004T-100A-D-P specification describes its TTL connector as passive and requires all four communication connections: external 5 V, GND, RX, and TX. `CF` is not used by this firmware. The PZEM-side 5 V supply is not ESP32 `3V3`; route RX/TX through the verified push-pull translator shown above. Confirm the actual delivered connector labels and idle/high voltages before connection.

The stateless production profile defines no microSD pins and never accesses an inserted card. A previously connected SD module is not required; disconnect it only while the entire installation is safely de-energized. Never format a card as part of firmware installation or recovery.

The PZEM voltage terminals and CT installation involve hazardous energy. Disconnect and verify de-energization, use an appropriate enclosure/fusing/conductor rating, preserve creepage/clearance and isolation, and have a qualified person approve the exact installation. This document is not authorization to work live.
