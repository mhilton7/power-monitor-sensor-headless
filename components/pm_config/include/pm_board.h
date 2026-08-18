#pragma once

/* ESP32-S3 DevKitC-style N16R8 reference profile. This is the only GPIO map. */
#define PM_BOARD_PROFILE "esp32-s3-devkitc-n16r8-reference/1"

#define PM_PZEM_UART_PORT 1
#define PM_PZEM_UART_TX 17
#define PM_PZEM_UART_RX 18
#define PM_PZEM_BAUD 9600
#define PM_PZEM_SLAVE_ADDRESS 0x01U

#define PM_USB_RECOVERY_BUTTON 0

_Static_assert(PM_PZEM_UART_TX != PM_PZEM_UART_RX, "UART pins must differ");
