#include "pm_meter.h"

#include <string.h>

uint16_t pm_modbus_crc16(const uint8_t *data, size_t length)
{
    uint16_t crc = UINT16_C(0xFFFF);
    if (data == NULL) {
        return crc;
    }
    for (size_t i = 0U; i < length; ++i) {
        crc ^= data[i];
        for (uint8_t bit = 0U; bit < 8U; ++bit) {
            crc = (crc & 1U) != 0U ? (uint16_t)((crc >> 1U) ^ UINT16_C(0xA001)) : (uint16_t)(crc >> 1U);
        }
    }
    return crc;
}

size_t pm_pzem_v4_classic_build_request(uint8_t slave, uint8_t request[PM_PZEM_REQUEST_SIZE])
{
    if (request == NULL) {
        return 0U;
    }
    const uint8_t prefix[6] = {slave, 0x04U, 0x00U, 0x00U, 0x00U, 0x0AU};
    memcpy(request, prefix, sizeof(prefix));
    const uint16_t crc = pm_modbus_crc16(request, sizeof(prefix));
    request[6] = (uint8_t)(crc & 0xFFU);
    request[7] = (uint8_t)(crc >> 8U);
    return PM_PZEM_REQUEST_SIZE;
}

static uint16_t word_be(const uint8_t *bytes)
{
    return (uint16_t)(((uint16_t)bytes[0] << 8U) | bytes[1]);
}

static uint32_t low_high_words(const uint8_t *bytes)
{
    const uint32_t low = word_be(bytes);
    const uint32_t high = word_be(bytes + 2U);
    return low | (high << 16U);
}

pm_pzem_status_t pm_pzem_v4_classic_parse_response(uint8_t slave, const uint8_t *frame, size_t length,
                                                   pm_meter_sample_t *sample)
{
    if (sample == NULL || frame == NULL) {
        return PM_PZEM_SHORT_FRAME;
    }
    *sample = (pm_meter_sample_t){.status = PM_PZEM_SHORT_FRAME};
    if (length != PM_PZEM_RESPONSE_SIZE) {
        return sample->status;
    }
    const uint16_t received_crc = (uint16_t)(frame[length - 2U] | ((uint16_t)frame[length - 1U] << 8U));
    if (pm_modbus_crc16(frame, length - 2U) != received_crc) {
        sample->status = PM_PZEM_BAD_CRC;
        return sample->status;
    }
    if (frame[0] != slave) {
        sample->status = PM_PZEM_WRONG_SLAVE;
        return sample->status;
    }
    if (frame[1] != 0x04U || frame[2] != 20U) {
        sample->status = PM_PZEM_WRONG_FUNCTION;
        return sample->status;
    }

    sample->voltage_mv = (int32_t)word_be(&frame[3]) * 100;
    sample->current_ma = (int32_t)low_high_words(&frame[5]);
    sample->active_power_mw = (int32_t)low_high_words(&frame[9]) * 100;
    sample->energy_wh = low_high_words(&frame[13]);
    sample->frequency_mhz = (int32_t)word_be(&frame[17]) * 100;
    sample->power_factor_milli = (int32_t)word_be(&frame[19]) * 10;
    sample->alarm_status = word_be(&frame[21]);
    sample->status = PM_PZEM_OK;
    if (!pm_meter_sample_valid(sample, 100U)) {
        sample->status = PM_PZEM_INVALID_RANGE;
    }
    return sample->status;
}

bool pm_meter_sample_valid(const pm_meter_sample_t *sample, uint16_t ct_rating_a)
{
    if (sample == NULL || ct_rating_a == 0U) {
        return false;
    }
    return sample->voltage_mv >= 0 && sample->voltage_mv <= 300000 && sample->current_ma >= 0 &&
           sample->current_ma <= (int32_t)ct_rating_a * 1100 && sample->active_power_mw >= 0 &&
           sample->active_power_mw <= 30000000 && sample->frequency_mhz >= 40000 &&
           sample->frequency_mhz <= 70000 && sample->power_factor_milli >= 0 &&
           sample->power_factor_milli <= 1000;
}

const char *pm_pzem_status_name(pm_pzem_status_t status)
{
    static const char *const names[] = {
        "ok", "timeout", "short_frame", "bad_crc", "wrong_slave", "wrong_function", "invalid_range",
        "hardware_identity_not_verified", "uart_error",
    };
    return status <= PM_PZEM_UART_ERROR ? names[status] : "unknown";
}
