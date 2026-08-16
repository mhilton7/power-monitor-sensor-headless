#pragma once

#include <stddef.h>
#include <stdint.h>

#include "esp_err.h"
#include "freertos/FreeRTOS.h"

typedef struct {
    size_t tx_buffer_size;
    size_t rx_buffer_size;
} usb_serial_jtag_driver_config_t;

esp_err_t usb_serial_jtag_driver_install(usb_serial_jtag_driver_config_t *config);
esp_err_t usb_serial_jtag_driver_uninstall(void);
int usb_serial_jtag_read_bytes(void *buffer, uint32_t length, TickType_t timeout);
int usb_serial_jtag_write_bytes(const void *buffer, size_t length, TickType_t timeout);
esp_err_t usb_serial_jtag_wait_tx_done(TickType_t timeout);
