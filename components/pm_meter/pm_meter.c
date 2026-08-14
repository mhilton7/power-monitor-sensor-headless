#include "pm_meter.h"

#include <string.h>

#include "driver/uart.h"
#include "esp_timer.h"
#include "pm_board.h"

static esp_err_t pzem_initialize(pm_meter_driver_t *driver)
{
    if (driver == NULL || !driver->hardware_identity_verified) {
        return ESP_ERR_INVALID_STATE;
    }
    const uart_config_t config = {
        .baud_rate = PM_PZEM_BAUD,
        .data_bits = UART_DATA_8_BITS,
        .parity = UART_PARITY_DISABLE,
        .stop_bits = UART_STOP_BITS_1,
        .flow_ctrl = UART_HW_FLOWCTRL_DISABLE,
        .source_clk = UART_SCLK_DEFAULT,
        .flags = {0},
    };
    esp_err_t error = uart_driver_install(PM_PZEM_UART_PORT, 256, 0, 0, NULL, 0);
    if (error != ESP_OK && error != ESP_ERR_INVALID_STATE) {
        return error;
    }
    error = uart_param_config(PM_PZEM_UART_PORT, &config);
    if (error == ESP_OK) {
        error = uart_set_pin(PM_PZEM_UART_PORT, PM_PZEM_UART_TX, PM_PZEM_UART_RX,
                             UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE);
    }
    return error;
}

static esp_err_t pzem_read(pm_meter_driver_t *driver, pm_meter_sample_t *sample, uint32_t timeout_ms)
{
    if (driver == NULL || sample == NULL || !driver->hardware_identity_verified) {
        if (sample != NULL) {
            *sample = (pm_meter_sample_t){.status = PM_PZEM_NOT_VERIFIED};
        }
        return ESP_ERR_INVALID_STATE;
    }
    uint8_t request[PM_PZEM_REQUEST_SIZE];
    uint8_t response[PM_PZEM_RESPONSE_SIZE];
    (void)pm_pzem_v4_classic_build_request(driver->slave_address, request);
    (void)uart_flush_input(PM_PZEM_UART_PORT);
    if (uart_write_bytes(PM_PZEM_UART_PORT, request, sizeof(request)) != (int)sizeof(request)) {
        sample->status = PM_PZEM_UART_ERROR;
        return ESP_FAIL;
    }
    const int received = uart_read_bytes(PM_PZEM_UART_PORT, response, sizeof(response),
                                         pdMS_TO_TICKS(timeout_ms));
    if (received <= 0) {
        *sample = (pm_meter_sample_t){.status = PM_PZEM_TIMEOUT, .sample_monotonic_us = esp_timer_get_time()};
        return ESP_ERR_TIMEOUT;
    }
    sample->sample_monotonic_us = esp_timer_get_time();
    const pm_pzem_status_t status = pm_pzem_v4_classic_parse_response(driver->slave_address, response,
                                                                       (size_t)received, sample);
    return status == PM_PZEM_OK ? ESP_OK : ESP_ERR_INVALID_RESPONSE;
}

static esp_err_t simulated_initialize(pm_meter_driver_t *driver)
{
    return driver == NULL ? ESP_ERR_INVALID_ARG : ESP_OK;
}

static esp_err_t simulated_read(pm_meter_driver_t *driver, pm_meter_sample_t *sample, uint32_t timeout_ms)
{
    (void)timeout_ms;
    if (driver == NULL || sample == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    const uint64_t tick = driver->simulation_tick++;
    const int32_t wave = (int32_t)(tick % 120U) - 60;
    *sample = (pm_meter_sample_t){
        .voltage_mv = 120000 + wave * 10,
        .current_ma = 5000 + (int32_t)(tick % 100U),
        .active_power_mw = 580000 + wave * 100,
        .frequency_mhz = 60000,
        .power_factor_milli = 967,
        .energy_wh = tick / 6U,
        .status = PM_PZEM_OK,
        .sample_monotonic_us = esp_timer_get_time(),
        .time_trusted = false,
        .simulated = true,
    };
    return ESP_OK;
}

static const pm_meter_driver_ops_t pzem_ops = {
    .initialize = pzem_initialize,
    .read = pzem_read,
    .name = "pzem-004t-v4-classic-candidate",
    .abi_version = 1U,
};

static const pm_meter_driver_ops_t simulated_ops = {
    .initialize = simulated_initialize,
    .read = simulated_read,
    .name = "simulated-pzem-explicit-test-only",
    .abi_version = 1U,
};

esp_err_t pm_meter_create(pm_meter_driver_t *driver, pm_meter_variant_t variant, bool hardware_verified,
                          bool simulated)
{
    if (driver == NULL || variant != PM_METER_PZEM004T_V4_CLASSIC) {
        return ESP_ERR_NOT_SUPPORTED;
    }
    *driver = (pm_meter_driver_t){
        .ops = simulated ? &simulated_ops : &pzem_ops,
        .variant = variant,
        .slave_address = PM_PZEM_SLAVE_ADDRESS,
        .hardware_identity_verified = hardware_verified,
        .simulated = simulated,
    };
    return driver->ops->initialize(driver);
}

esp_err_t pm_meter_read(pm_meter_driver_t *driver, pm_meter_sample_t *sample, uint32_t timeout_ms)
{
    if (sample == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    if (driver == NULL || driver->ops == NULL) {
        *sample = (pm_meter_sample_t){.status = PM_PZEM_NOT_VERIFIED,
                                      .sample_monotonic_us = esp_timer_get_time()};
        return ESP_ERR_INVALID_STATE;
    }
    return driver->ops->read(driver, sample, timeout_ms);
}
