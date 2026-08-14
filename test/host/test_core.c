#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "pm_measurement.h"
#include "pm_meter.h"
#include "pm_state.h"
#include "pm_storage.h"

static unsigned tests_run;
static unsigned tests_failed;

#define CHECK(condition)                                                                                               \
    do {                                                                                                               \
        tests_run++;                                                                                                   \
        if (!(condition)) {                                                                                            \
            tests_failed++;                                                                                            \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #condition);                                    \
        }                                                                                                              \
    } while (0)

uint32_t pm_crc32_ieee(const void *data, size_t length)
{
    const uint8_t *bytes = (const uint8_t *)data;
    uint32_t crc = UINT32_C(0xFFFFFFFF);
    for (size_t i = 0U; i < length; ++i) {
        crc ^= bytes[i];
        for (uint8_t bit = 0U; bit < 8U; ++bit) {
            const uint32_t mask = (uint32_t)-(int32_t)(crc & 1U);
            crc = (crc >> 1U) ^ (UINT32_C(0xEDB88320) & mask);
        }
    }
    return ~crc;
}

static void put_word(uint8_t *frame, size_t offset, uint16_t value)
{
    frame[offset] = (uint8_t)(value >> 8U);
    frame[offset + 1U] = (uint8_t)value;
}

static void put_low_high(uint8_t *frame, size_t offset, uint32_t value)
{
    put_word(frame, offset, (uint16_t)value);
    put_word(frame, offset + 2U, (uint16_t)(value >> 16U));
}

static void valid_frame(uint8_t frame[PM_PZEM_RESPONSE_SIZE])
{
    memset(frame, 0, PM_PZEM_RESPONSE_SIZE);
    frame[0] = 1U;
    frame[1] = 4U;
    frame[2] = 20U;
    put_word(frame, 3U, 1201U);
    put_low_high(frame, 5U, 12345U);
    put_low_high(frame, 9U, 14822U);
    put_low_high(frame, 13U, 123456U);
    put_word(frame, 17U, 600U);
    put_word(frame, 19U, 98U);
    put_word(frame, 21U, 0U);
    const uint16_t crc = pm_modbus_crc16(frame, PM_PZEM_RESPONSE_SIZE - 2U);
    frame[23] = (uint8_t)crc;
    frame[24] = (uint8_t)(crc >> 8U);
}

static void test_modbus_and_parser(void)
{
    uint8_t request[PM_PZEM_REQUEST_SIZE];
    CHECK(pm_pzem_v4_classic_build_request(1U, request) == PM_PZEM_REQUEST_SIZE);
    static const uint8_t expected[] = {0x01U, 0x04U, 0x00U, 0x00U, 0x00U, 0x0AU, 0x70U, 0x0DU};
    CHECK(memcmp(request, expected, sizeof(expected)) == 0);

    uint8_t frame[PM_PZEM_RESPONSE_SIZE];
    valid_frame(frame);
    pm_meter_sample_t sample;
    CHECK(pm_pzem_v4_classic_parse_response(1U, frame, sizeof(frame), &sample) == PM_PZEM_OK);
    CHECK(sample.voltage_mv == 120100);
    CHECK(sample.current_ma == 12345);
    CHECK(sample.active_power_mw == 1482200);
    CHECK(sample.energy_wh == 123456U);
    CHECK(sample.frequency_mhz == 60000);
    CHECK(sample.power_factor_milli == 980);
    CHECK(pm_pzem_v4_classic_parse_response(1U, frame, sizeof(frame) - 1U, &sample) == PM_PZEM_SHORT_FRAME);
    frame[23] ^= 1U;
    CHECK(pm_pzem_v4_classic_parse_response(1U, frame, sizeof(frame), &sample) == PM_PZEM_BAD_CRC);
    valid_frame(frame);
    CHECK(pm_pzem_v4_classic_parse_response(2U, frame, sizeof(frame), &sample) == PM_PZEM_WRONG_SLAVE);
    valid_frame(frame);
    put_word(frame, 17U, 100U);
    const uint16_t crc = pm_modbus_crc16(frame, sizeof(frame) - 2U);
    frame[23] = (uint8_t)crc;
    frame[24] = (uint8_t)(crc >> 8U);
    CHECK(pm_pzem_v4_classic_parse_response(1U, frame, sizeof(frame), &sample) == PM_PZEM_INVALID_RANGE);
}

static pm_meter_sample_t sample_at(uint64_t energy_wh, int64_t monotonic_us, int32_t current_ma, bool trusted)
{
    return (pm_meter_sample_t){
        .voltage_mv = 120000,
        .current_ma = current_ma,
        .active_power_mw = 1200000,
        .frequency_mhz = 60000,
        .power_factor_milli = 990,
        .energy_wh = energy_wh,
        .status = PM_PZEM_OK,
        .sample_timestamp_utc_ms = trusted ? INT64_C(1760000000000) + monotonic_us / 1000 : 0,
        .sample_monotonic_us = monotonic_us,
        .time_trusted = trusted,
    };
}

static void test_aggregation(void)
{
    pm_interval_accumulator_t accumulator;
    pm_interval_init(&accumulator, 3U);
    pm_meter_sample_t a = sample_at(100U, 1000000, 81000, true);
    pm_meter_sample_t b = sample_at(100U, 2000000, 91000, true);
    pm_meter_sample_t c = sample_at(101U, 3000000, 5000, true);
    CHECK(pm_interval_add(&accumulator, &a, 100U));
    CHECK(pm_interval_add(&accumulator, &b, 100U));
    CHECK(pm_interval_add(&accumulator, &c, 100U));
    pm_durable_interval_t interval;
    CHECK(pm_interval_finalize(&accumulator, &interval, 10000U));
    CHECK(interval.selected_energy_mwh == 1000U);
    CHECK(interval.selected_energy_source == PM_ENERGY_PZEM_DELTA);
    CHECK(interval.completeness_permille == 1000U);
    CHECK((interval.flags & PM_INTERVAL_FLAG_CT_WARNING_80) != 0U);
    CHECK((interval.flags & PM_INTERVAL_FLAG_CT_CRITICAL_90) != 0U);

    pm_interval_init(&accumulator, 60U);
    a = sample_at(101U, 4000000, 1000, true);
    CHECK(pm_interval_add(&accumulator, &a, 100U));
    CHECK(pm_interval_finalize(&accumulator, &interval, 10000U));
    CHECK(interval.selected_energy_source == PM_ENERGY_NONE);
    CHECK(interval.selected_energy_mwh == 0U);
    CHECK((interval.flags & PM_INTERVAL_FLAG_MISSING_SAMPLE) != 0U);

    pm_interval_init(&accumulator, 2U);
    a = sample_at(500U, 1000000, 1000, false);
    b = sample_at(2U, 2000000, 1000, false);
    CHECK(pm_interval_add(&accumulator, &a, 100U));
    CHECK(pm_interval_add(&accumulator, &b, 100U));
    CHECK(pm_interval_finalize(&accumulator, &interval, 10000U));
    CHECK(interval.selected_energy_source == PM_ENERGY_NONE);
    CHECK((interval.flags & PM_INTERVAL_FLAG_PZEM_RESET) != 0U);
    CHECK((interval.flags & PM_INTERVAL_FLAG_TIME_UNTRUSTED) != 0U);

    pm_interval_init(&accumulator, 2U);
    a = sample_at(UINT32_C(0xFFFFFFFE), 1000000, 1000, true);
    b = sample_at(1U, 2000000, 1000, true);
    CHECK(pm_interval_add(&accumulator, &a, 100U));
    CHECK(pm_interval_add(&accumulator, &b, 100U));
    CHECK(pm_interval_finalize(&accumulator, &interval, 10000U));
    CHECK((interval.flags & PM_INTERVAL_FLAG_PZEM_ROLLOVER) != 0U);
    CHECK(interval.selected_energy_mwh == 3000U);
}

static void test_journal(void)
{
    pm_segment_header_t header = {
        .first_sequence = 42U,
        .created_utc_ms = INT64_C(1760000000000),
        .created_monotonic_us = INT64_C(1234000),
        .time_trusted = true,
    };
    for (size_t i = 0U; i < 16U; ++i) {
        header.device_id[i] = (uint8_t)i;
        header.card_id[i] = (uint8_t)(i + 16U);
        header.segment_id[i] = (uint8_t)(i + 32U);
    }
    uint8_t header_bytes[PM_JOURNAL_SEGMENT_HEADER_SIZE];
    CHECK(pm_journal_encode_segment_header(&header, header_bytes, sizeof(header_bytes)) == sizeof(header_bytes));
    pm_segment_header_t decoded_header;
    CHECK(pm_journal_decode_segment_header(header_bytes, sizeof(header_bytes), &decoded_header));
    CHECK(decoded_header.first_sequence == header.first_sequence);
    header_bytes[30] ^= 1U;
    CHECK(!pm_journal_decode_segment_header(header_bytes, sizeof(header_bytes), &decoded_header));

    pm_journal_record_t record = {.sequence = 42U, .reset_generation = 3U};
    memcpy(record.device_id, header.device_id, sizeof(record.device_id));
    record.interval = (pm_durable_interval_t){
        .voltage_mv = 120000,
        .current_ma = 1000,
        .active_power_mw = 119000,
        .frequency_mhz = 60000,
        .power_factor_milli = 992,
        .pzem_energy_start_wh = 8U,
        .pzem_energy_end_wh = 9U,
        .selected_energy_mwh = 1000U,
        .sample_count = 60U,
        .expected_samples = 60U,
        .completeness_permille = 1000U,
        .selected_energy_source = PM_ENERGY_PZEM_DELTA,
        .start_utc_ms = INT64_C(1760000000000),
        .end_utc_ms = INT64_C(1760000060000),
    };
    uint8_t bytes[PM_JOURNAL_RECORD_SIZE];
    CHECK(pm_journal_encode_record(&record, bytes, sizeof(bytes)) == sizeof(bytes));
    pm_journal_record_t decoded;
    CHECK(pm_journal_decode_record(bytes, sizeof(bytes), &decoded));
    CHECK(decoded.sequence == record.sequence);
    CHECK(decoded.interval.selected_energy_mwh == 1000U);
    bytes[84] ^= 1U;
    CHECK(!pm_journal_decode_record(bytes, sizeof(bytes), &decoded));
}

static void test_state_machine(void)
{
    pm_state_machine_t state;
    pm_state_init(&state, 0);
    CHECK(state.state == PM_STATE_BOOT);
    CHECK(pm_state_transition(&state, PM_EVENT_BOOTSTRAP, 1));
    CHECK(state.state == PM_STATE_SELF_TEST);
    CHECK(pm_state_transition(&state, PM_EVENT_CONFIG_MISSING, 2));
    CHECK(state.state == PM_STATE_UNPROVISIONED_COM);
    CHECK(pm_state_transition(&state, PM_EVENT_CONFIG_VALID, 3));
    CHECK(pm_state_transition(&state, PM_EVENT_WIFI_CONNECTED, 4));
    CHECK(state.state == PM_STATE_RUNNING);
    CHECK(pm_state_transition(&state, PM_EVENT_STORAGE_FAILED, 5));
    CHECK(state.state == PM_STATE_DEGRADED_STORAGE);
    CHECK(pm_state_transition(&state, PM_EVENT_STORAGE_RECOVERED, 6));
    CHECK(state.state == PM_STATE_RUNNING);
    CHECK(pm_state_transition(&state, PM_EVENT_OTA_AVAILABLE, 7));
    CHECK(pm_state_transition(&state, PM_EVENT_OTA_STARTED, 8));
    CHECK(pm_state_transition(&state, PM_EVENT_OTA_FINISHED, 9));
    CHECK(state.state == PM_STATE_SAFE_REBOOT);
}

int main(void)
{
    test_modbus_and_parser();
    test_aggregation();
    test_journal();
    test_state_machine();
    printf("{\"suite\":\"host-core\",\"assertions\":%u,\"failures\":%u}\n", tests_run, tests_failed);
    return tests_failed == 0U ? EXIT_SUCCESS : EXIT_FAILURE;
}
