#pragma once

#include <stddef.h>
#include <stdint.h>

#include "esp_err.h"

typedef int uart_port_t;
typedef uint32_t TickType_t;

typedef struct {
    int baud_rate;
    int data_bits;
    int parity;
    int stop_bits;
    int flow_ctrl;
    int source_clk;
    struct {
        unsigned value;
    } flags;
} uart_config_t;

#define UART_DATA_8_BITS 8
#define UART_PARITY_DISABLE 0
#define UART_STOP_BITS_1 1
#define UART_HW_FLOWCTRL_DISABLE 0
#define UART_SCLK_DEFAULT 0
#define UART_PIN_NO_CHANGE (-1)
#define pdMS_TO_TICKS(value) ((TickType_t)(value))

esp_err_t uart_driver_install(uart_port_t port, int rx_buffer_size, int tx_buffer_size,
                              int queue_size, void *uart_queue, int interrupt_flags);
esp_err_t uart_param_config(uart_port_t port, const uart_config_t *config);
esp_err_t uart_set_pin(uart_port_t port, int tx_pin, int rx_pin, int rts_pin, int cts_pin);
esp_err_t uart_flush_input(uart_port_t port);
int uart_write_bytes(uart_port_t port, const void *source, size_t size);
int uart_read_bytes(uart_port_t port, void *destination, uint32_t size, TickType_t timeout_ticks);
