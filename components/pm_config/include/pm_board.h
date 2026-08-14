#pragma once

/* ESP32-S3 DevKitC-style N16R8 reference profile. This is the only GPIO map. */
#define PM_BOARD_PROFILE "esp32-s3-devkitc-n16r8-reference/1"

#define PM_PZEM_UART_PORT 1
#define PM_PZEM_UART_TX 17
#define PM_PZEM_UART_RX 18
#define PM_PZEM_BAUD 9600
#define PM_PZEM_SLAVE_ADDRESS 0x01U

#define PM_SD_SPI_HOST SPI2_HOST
#define PM_SD_CS 10
#define PM_SD_MOSI 11
#define PM_SD_SCK 12
#define PM_SD_MISO 13
#define PM_SD_MOUNT_POINT "/sd"

#define PM_USB_RECOVERY_BUTTON 0

_Static_assert(PM_PZEM_UART_TX != PM_PZEM_UART_RX, "UART pins must differ");
_Static_assert(PM_SD_CS != PM_SD_MOSI && PM_SD_CS != PM_SD_SCK && PM_SD_CS != PM_SD_MISO,
               "SD chip-select must be unique");
