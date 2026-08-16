#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "driver/uart.h"
#include "pm_board.h"
#include "pm_meter.h"

#define CHECK(condition) do { if (!(condition)) { \
    fprintf(stderr, "CHECK failed at %s:%d: %s\n", __FILE__, __LINE__, #condition); return 1; \
} } while (0)

static unsigned s_install_calls;
static unsigned s_config_calls;
static unsigned s_pin_calls;
static unsigned s_flush_calls;
static unsigned s_write_calls;
static unsigned s_read_calls;
static uart_port_t s_port;
static int s_rx_buffer_size;
static int s_tx_buffer_size;
static int s_queue_size;
static uart_config_t s_uart_config;
static int s_tx_pin;
static int s_rx_pin;
static uint8_t s_written[PM_PZEM_REQUEST_SIZE];
static size_t s_written_size;
static uint8_t s_response[PM_PZEM_RESPONSE_SIZE];
static int s_read_result;
static int s_write_result = PM_PZEM_REQUEST_SIZE;
static TickType_t s_timeout_ticks;
static int64_t s_now_us = 1234567;

static void reset_uart(void)
{
    s_install_calls = 0U;
    s_config_calls = 0U;
    s_pin_calls = 0U;
    s_flush_calls = 0U;
    s_write_calls = 0U;
    s_read_calls = 0U;
    s_port = -1;
    s_rx_buffer_size = 0;
    s_tx_buffer_size = 0;
    s_queue_size = 0;
    memset(&s_uart_config, 0, sizeof(s_uart_config));
    s_tx_pin = -1;
    s_rx_pin = -1;
    memset(s_written, 0, sizeof(s_written));
    s_written_size = 0U;
    memset(s_response, 0, sizeof(s_response));
    s_read_result = 0;
    s_write_result = PM_PZEM_REQUEST_SIZE;
    s_timeout_ticks = 0U;
}

int64_t esp_timer_get_time(void)
{
    return s_now_us;
}

esp_err_t uart_driver_install(uart_port_t port, int rx_buffer_size, int tx_buffer_size,
                              int queue_size, void *uart_queue, int interrupt_flags)
{
    (void)uart_queue;
    (void)interrupt_flags;
    ++s_install_calls;
    s_port = port;
    s_rx_buffer_size = rx_buffer_size;
    s_tx_buffer_size = tx_buffer_size;
    s_queue_size = queue_size;
    return ESP_OK;
}

esp_err_t uart_param_config(uart_port_t port, const uart_config_t *config)
{
    ++s_config_calls;
    s_port = port;
    s_uart_config = *config;
    return ESP_OK;
}

esp_err_t uart_set_pin(uart_port_t port, int tx_pin, int rx_pin, int rts_pin, int cts_pin)
{
    (void)rts_pin;
    (void)cts_pin;
    ++s_pin_calls;
    s_port = port;
    s_tx_pin = tx_pin;
    s_rx_pin = rx_pin;
    return ESP_OK;
}

esp_err_t uart_flush_input(uart_port_t port)
{
    ++s_flush_calls;
    s_port = port;
    return ESP_OK;
}

int uart_write_bytes(uart_port_t port, const void *source, size_t size)
{
    ++s_write_calls;
    s_port = port;
    s_written_size = size;
    memcpy(s_written, source, size <= sizeof(s_written) ? size : sizeof(s_written));
    return s_write_result;
}

int uart_read_bytes(uart_port_t port, void *destination, uint32_t size, TickType_t timeout_ticks)
{
    ++s_read_calls;
    s_port = port;
    s_timeout_ticks = timeout_ticks;
    if (s_read_result > 0) {
        const size_t copied = (size_t)s_read_result < size ? (size_t)s_read_result : size;
        memcpy(destination, s_response, copied);
    }
    return s_read_result;
}

static void prepare_valid_response(void)
{
    const uint8_t body[] = {
        0x01, 0x04, 0x14,
        0x04, 0xB0,
        0x04, 0xD2, 0x00, 0x00,
        0x02, 0x44, 0x00, 0x00,
        0x00, 0x7B, 0x00, 0x00,
        0x02, 0x58,
        0x00, 0x61,
        0x00, 0x00,
    };
    memcpy(s_response, body, sizeof(body));
    const uint16_t crc = pm_modbus_crc16(s_response, PM_PZEM_RESPONSE_SIZE - 2U);
    s_response[PM_PZEM_RESPONSE_SIZE - 2U] = (uint8_t)(crc & 0xFFU);
    s_response[PM_PZEM_RESPONSE_SIZE - 1U] = (uint8_t)(crc >> 8U);
    s_read_result = PM_PZEM_RESPONSE_SIZE;
}

static int test_disabled_gate(void)
{
    reset_uart();
    pm_meter_driver_t driver = {0};
    CHECK(pm_meter_create(&driver, PM_METER_PZEM004T_V4_CLASSIC, false, false) == ESP_ERR_INVALID_STATE);
    CHECK(s_install_calls == 0U);
    pm_meter_sample_t sample = {0};
    CHECK(pm_meter_read(&driver, &sample, 350U) == ESP_ERR_INVALID_STATE);
    CHECK(sample.status == PM_PZEM_NOT_VERIFIED);
    CHECK(s_write_calls == 0U && s_read_calls == 0U);
    return 0;
}

static int test_live_uart_and_valid_frame(void)
{
    reset_uart();
    pm_meter_driver_t driver = {0};
    CHECK(pm_meter_create(&driver, PM_METER_PZEM004T_V4_CLASSIC, true, false) == ESP_OK);
    CHECK(s_install_calls == 1U && s_config_calls == 1U && s_pin_calls == 1U);
    CHECK(s_port == PM_PZEM_UART_PORT);
    CHECK(s_rx_buffer_size == 256 && s_tx_buffer_size == 0 && s_queue_size == 0);
    CHECK(s_uart_config.baud_rate == 9600 && s_uart_config.data_bits == UART_DATA_8_BITS);
    CHECK(s_uart_config.parity == UART_PARITY_DISABLE && s_uart_config.stop_bits == UART_STOP_BITS_1);
    CHECK(s_uart_config.flow_ctrl == UART_HW_FLOWCTRL_DISABLE);
    CHECK(s_tx_pin == PM_PZEM_UART_TX && s_rx_pin == PM_PZEM_UART_RX);
    prepare_valid_response();
    pm_meter_sample_t sample = {0};
    CHECK(pm_meter_read(&driver, &sample, 350U) == ESP_OK);
    const uint8_t expected[] = {0x01, 0x04, 0x00, 0x00, 0x00, 0x0A, 0x70, 0x0D};
    CHECK(s_flush_calls == 1U && s_write_calls == 1U && s_read_calls == 1U);
    CHECK(s_written_size == sizeof(expected) && memcmp(s_written, expected, sizeof(expected)) == 0);
    CHECK(s_timeout_ticks == 350U);
    CHECK(sample.status == PM_PZEM_OK);
    CHECK(sample.voltage_mv == 120000);
    CHECK(sample.current_ma == 1234);
    CHECK(sample.active_power_mw == 58000);
    CHECK(sample.energy_wh == 123U);
    CHECK(sample.frequency_mhz == 60000);
    CHECK(sample.power_factor_milli == 970);
    CHECK(sample.sample_monotonic_us == s_now_us);
    return 0;
}

static int test_timeout_and_short_write(void)
{
    reset_uart();
    pm_meter_driver_t driver = {0};
    CHECK(pm_meter_create(&driver, PM_METER_PZEM004T_V4_CLASSIC, true, false) == ESP_OK);
    pm_meter_sample_t sample = {0};
    CHECK(pm_meter_read(&driver, &sample, 350U) == ESP_ERR_TIMEOUT);
    CHECK(sample.status == PM_PZEM_TIMEOUT);
    CHECK(sample.sample_monotonic_us == s_now_us);
    s_write_result = PM_PZEM_REQUEST_SIZE - 1;
    CHECK(pm_meter_read(&driver, &sample, 350U) == ESP_FAIL);
    CHECK(sample.status == PM_PZEM_UART_ERROR);
    return 0;
}

static int test_simulation_never_opens_uart(void)
{
    reset_uart();
    pm_meter_driver_t driver = {0};
    CHECK(pm_meter_create(&driver, PM_METER_PZEM004T_V4_CLASSIC, false, true) == ESP_OK);
    CHECK(s_install_calls == 0U);
    pm_meter_sample_t sample = {0};
    CHECK(pm_meter_read(&driver, &sample, 350U) == ESP_OK);
    CHECK(sample.status == PM_PZEM_OK && sample.simulated);
    CHECK(s_write_calls == 0U && s_read_calls == 0U);
    return 0;
}

int main(void)
{
    CHECK(test_disabled_gate() == 0);
    CHECK(test_live_uart_and_valid_frame() == 0);
    CHECK(test_timeout_and_short_write() == 0);
    CHECK(test_simulation_never_opens_uart() == 0);
    puts("pm_meter I/O tests passed");
    return 0;
}
