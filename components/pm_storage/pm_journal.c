#include "pm_storage.h"

#include <string.h>

#include "pm_config.h"

static void put_u16(uint8_t *buffer, uint16_t value)
{
    buffer[0] = (uint8_t)value;
    buffer[1] = (uint8_t)(value >> 8U);
}

static void put_u32(uint8_t *buffer, uint32_t value)
{
    for (uint8_t i = 0U; i < 4U; ++i) {
        buffer[i] = (uint8_t)(value >> (8U * i));
    }
}

static void put_u64(uint8_t *buffer, uint64_t value)
{
    for (uint8_t i = 0U; i < 8U; ++i) {
        buffer[i] = (uint8_t)(value >> (8U * i));
    }
}

static uint16_t get_u16(const uint8_t *buffer)
{
    return (uint16_t)(buffer[0] | ((uint16_t)buffer[1] << 8U));
}

static uint32_t get_u32(const uint8_t *buffer)
{
    uint32_t value = 0U;
    for (uint8_t i = 0U; i < 4U; ++i) {
        value |= (uint32_t)buffer[i] << (8U * i);
    }
    return value;
}

static uint64_t get_u64(const uint8_t *buffer)
{
    uint64_t value = 0U;
    for (uint8_t i = 0U; i < 8U; ++i) {
        value |= (uint64_t)buffer[i] << (8U * i);
    }
    return value;
}

size_t pm_journal_encode_segment_header(const pm_segment_header_t *header, uint8_t *output, size_t capacity)
{
    if (header == NULL || output == NULL || capacity < PM_JOURNAL_SEGMENT_HEADER_SIZE) {
        return 0U;
    }
    memset(output, 0, PM_JOURNAL_SEGMENT_HEADER_SIZE);
    put_u32(&output[0], PM_JOURNAL_SEGMENT_MAGIC);
    put_u16(&output[4], PM_JOURNAL_FORMAT_VERSION);
    put_u16(&output[6], PM_JOURNAL_SEGMENT_HEADER_SIZE);
    memcpy(&output[8], header->device_id, 16U);
    memcpy(&output[24], header->card_id, 16U);
    memcpy(&output[40], header->segment_id, 16U);
    put_u64(&output[56], header->first_sequence);
    put_u64(&output[64], (uint64_t)header->created_utc_ms);
    put_u64(&output[72], (uint64_t)header->created_monotonic_us);
    output[80] = header->time_trusted ? 1U : 0U;
    put_u32(&output[92], pm_crc32_ieee(output, 92U));
    return PM_JOURNAL_SEGMENT_HEADER_SIZE;
}

bool pm_journal_decode_segment_header(const uint8_t *data, size_t length, pm_segment_header_t *header)
{
    if (data == NULL || header == NULL || length != PM_JOURNAL_SEGMENT_HEADER_SIZE ||
        get_u32(&data[0]) != PM_JOURNAL_SEGMENT_MAGIC ||
        get_u16(&data[4]) != PM_JOURNAL_FORMAT_VERSION ||
        get_u16(&data[6]) != PM_JOURNAL_SEGMENT_HEADER_SIZE ||
        get_u32(&data[92]) != pm_crc32_ieee(data, 92U)) {
        return false;
    }
    memset(header, 0, sizeof(*header));
    memcpy(header->device_id, &data[8], 16U);
    memcpy(header->card_id, &data[24], 16U);
    memcpy(header->segment_id, &data[40], 16U);
    header->first_sequence = get_u64(&data[56]);
    header->created_utc_ms = (int64_t)get_u64(&data[64]);
    header->created_monotonic_us = (int64_t)get_u64(&data[72]);
    header->time_trusted = data[80] != 0U;
    return true;
}

size_t pm_journal_encode_record(const pm_journal_record_t *record, uint8_t *output, size_t capacity)
{
    if (record == NULL || output == NULL || capacity < PM_JOURNAL_RECORD_SIZE) {
        return 0U;
    }
    memset(output, 0, PM_JOURNAL_RECORD_SIZE);
    put_u32(&output[0], PM_JOURNAL_RECORD_MAGIC);
    put_u16(&output[4], PM_JOURNAL_FORMAT_VERSION);
    put_u16(&output[6], PM_JOURNAL_RECORD_SIZE);
    memcpy(&output[8], record->device_id, 16U);
    put_u64(&output[24], record->sequence);
    put_u32(&output[32], record->reset_generation);
    put_u32(&output[36], record->interval.flags);
    put_u64(&output[40], (uint64_t)record->interval.start_utc_ms);
    put_u64(&output[48], (uint64_t)record->interval.end_utc_ms);
    put_u64(&output[56], (uint64_t)record->interval.start_monotonic_us);
    put_u64(&output[64], (uint64_t)record->interval.end_monotonic_us);
    put_u32(&output[72], record->interval.sample_count);
    put_u32(&output[76], record->interval.expected_samples);
    put_u16(&output[80], record->interval.completeness_permille);
    put_u16(&output[82], (uint16_t)record->interval.selected_energy_source);
    put_u32(&output[84], (uint32_t)record->interval.voltage_mv);
    put_u32(&output[88], (uint32_t)record->interval.current_ma);
    put_u32(&output[92], (uint32_t)record->interval.active_power_mw);
    put_u32(&output[96], (uint32_t)record->interval.frequency_mhz);
    put_u32(&output[100], (uint32_t)record->interval.power_factor_milli);
    put_u64(&output[104], record->interval.pzem_energy_start_wh);
    put_u64(&output[112], record->interval.pzem_energy_end_wh);
    put_u32(&output[120], (uint32_t)(record->interval.selected_energy_mwh > UINT32_MAX
                                         ? UINT32_MAX
                                         : record->interval.selected_energy_mwh));
    put_u32(&output[124], pm_crc32_ieee(output, 124U));
    return PM_JOURNAL_RECORD_SIZE;
}

bool pm_journal_decode_record(const uint8_t *data, size_t length, pm_journal_record_t *record)
{
    if (data == NULL || record == NULL || length != PM_JOURNAL_RECORD_SIZE ||
        get_u32(&data[0]) != PM_JOURNAL_RECORD_MAGIC || get_u16(&data[4]) != PM_JOURNAL_FORMAT_VERSION ||
        get_u16(&data[6]) != PM_JOURNAL_RECORD_SIZE || get_u32(&data[124]) != pm_crc32_ieee(data, 124U)) {
        return false;
    }
    memset(record, 0, sizeof(*record));
    memcpy(record->device_id, &data[8], 16U);
    record->sequence = get_u64(&data[24]);
    record->reset_generation = get_u32(&data[32]);
    record->interval.flags = get_u32(&data[36]);
    record->interval.start_utc_ms = (int64_t)get_u64(&data[40]);
    record->interval.end_utc_ms = (int64_t)get_u64(&data[48]);
    record->interval.start_monotonic_us = (int64_t)get_u64(&data[56]);
    record->interval.end_monotonic_us = (int64_t)get_u64(&data[64]);
    record->interval.sample_count = get_u32(&data[72]);
    record->interval.expected_samples = get_u32(&data[76]);
    record->interval.completeness_permille = get_u16(&data[80]);
    record->interval.selected_energy_source = (pm_energy_source_t)get_u16(&data[82]);
    record->interval.voltage_mv = (int32_t)get_u32(&data[84]);
    record->interval.current_ma = (int32_t)get_u32(&data[88]);
    record->interval.active_power_mw = (int32_t)get_u32(&data[92]);
    record->interval.frequency_mhz = (int32_t)get_u32(&data[96]);
    record->interval.power_factor_milli = (int32_t)get_u32(&data[100]);
    record->interval.pzem_energy_start_wh = get_u64(&data[104]);
    record->interval.pzem_energy_end_wh = get_u64(&data[112]);
    record->interval.selected_energy_mwh = get_u32(&data[120]);
    return record->sequence != 0U && record->interval.completeness_permille <= 1000U;
}

