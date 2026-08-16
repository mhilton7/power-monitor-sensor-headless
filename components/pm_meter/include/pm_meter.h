#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "esp_err.h"
#include "pm_config.h"

#ifdef __cplusplus
extern "C" {
#endif

#define PM_PZEM_REQUEST_SIZE 8U
#define PM_PZEM_RESPONSE_SIZE 25U

typedef enum {
    PM_PZEM_OK = 0,
    PM_PZEM_TIMEOUT,
    PM_PZEM_SHORT_FRAME,
    PM_PZEM_BAD_CRC,
    PM_PZEM_WRONG_SLAVE,
    PM_PZEM_WRONG_FUNCTION,
    PM_PZEM_INVALID_RANGE,
    PM_PZEM_NOT_VERIFIED,
    PM_PZEM_UART_ERROR,
} pm_pzem_status_t;

typedef struct {
    int32_t voltage_mv;
    int32_t current_ma;
    int32_t active_power_mw;
    int32_t frequency_mhz;
    int32_t power_factor_milli;
    uint64_t energy_wh;
    uint16_t alarm_status;
    pm_pzem_status_t status;
    uint16_t error_code;
    int64_t sample_timestamp_utc_ms;
    int64_t sample_monotonic_us;
    bool time_trusted;
    bool simulated;
} pm_meter_sample_t;

typedef struct pm_meter_driver pm_meter_driver_t;

typedef struct {
    esp_err_t (*initialize)(pm_meter_driver_t *driver);
    esp_err_t (*read)(pm_meter_driver_t *driver, pm_meter_sample_t *sample, uint32_t timeout_ms);
    const char *name;
    uint16_t abi_version;
} pm_meter_driver_ops_t;

struct pm_meter_driver {
    const pm_meter_driver_ops_t *ops;
    pm_meter_variant_t variant;
    uint8_t slave_address;
    bool physical_reads_enabled;
    bool simulated;
    uint64_t simulation_tick;
};

uint16_t pm_modbus_crc16(const uint8_t *data, size_t length);
size_t pm_pzem_v4_classic_build_request(uint8_t slave, uint8_t request[PM_PZEM_REQUEST_SIZE]);
pm_pzem_status_t pm_pzem_v4_classic_parse_response(uint8_t slave, const uint8_t *frame, size_t length,
                                                   pm_meter_sample_t *sample);
esp_err_t pm_meter_create(pm_meter_driver_t *driver, pm_meter_variant_t variant, bool physical_reads_enabled,
                          bool simulated);
esp_err_t pm_meter_read(pm_meter_driver_t *driver, pm_meter_sample_t *sample, uint32_t timeout_ms);
bool pm_meter_sample_valid(const pm_meter_sample_t *sample, uint16_t ct_rating_a);
const char *pm_pzem_status_name(pm_pzem_status_t status);

#ifdef __cplusplus
}
#endif

