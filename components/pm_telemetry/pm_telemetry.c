#include "pm_telemetry.h"

#include <limits.h>
#include <string.h>

void pm_telemetry_slot_init(pm_telemetry_slot_t *slot)
{
    if (slot != NULL) {
        memset(slot, 0, sizeof(*slot));
        slot->next_sequence = 1U;
    }
}

esp_err_t pm_telemetry_offer(pm_telemetry_slot_t *slot, const pm_meter_sample_t *measurement,
                             uint64_t *sample_sequence)
{
    if (slot == NULL || measurement == NULL || slot->next_sequence == 0U ||
        slot->next_sequence == UINT64_MAX) {
        return ESP_ERR_INVALID_ARG;
    }
    pm_telemetry_sample_t offered = {
        .measurement = *measurement,
        .sample_sequence = slot->next_sequence++,
    };
    if (slot->pending_present) {
        slot->replaced_pending++;
    }
    slot->pending = offered;
    slot->pending_present = true;
    if (sample_sequence != NULL) {
        *sample_sequence = offered.sample_sequence;
    }
    return ESP_OK;
}

bool pm_telemetry_begin_send(pm_telemetry_slot_t *slot, pm_telemetry_sample_t *sample)
{
    if (slot == NULL || sample == NULL || slot->in_flight_present || !slot->pending_present) {
        return false;
    }
    slot->in_flight = slot->pending;
    slot->in_flight_present = true;
    memset(&slot->pending, 0, sizeof(slot->pending));
    slot->pending_present = false;
    *sample = slot->in_flight;
    return true;
}

esp_err_t pm_telemetry_complete_send(pm_telemetry_slot_t *slot, uint64_t sample_sequence,
                                     bool accepted)
{
    if (slot == NULL || !slot->in_flight_present || sample_sequence == 0U ||
        slot->in_flight.sample_sequence != sample_sequence) {
        return ESP_ERR_INVALID_STATE;
    }
    if (!accepted) {
        slot->failed_transmissions++;
    }
    memset(&slot->in_flight, 0, sizeof(slot->in_flight));
    slot->in_flight_present = false;
    return ESP_OK;
}

size_t pm_telemetry_resident_samples(const pm_telemetry_slot_t *slot)
{
    return slot == NULL ? 0U : (slot->in_flight_present ? 1U : 0U) +
                                     (slot->pending_present ? 1U : 0U);
}

void pm_telemetry_backoff_reset(pm_telemetry_backoff_t *backoff, int64_t now_us)
{
    if (backoff != NULL) {
        backoff->failures = 0U;
        backoff->next_attempt_us = now_us;
    }
}

uint32_t pm_telemetry_backoff_fail(pm_telemetry_backoff_t *backoff, int64_t now_us,
                                   uint32_t random_value)
{
    if (backoff == NULL) {
        return 60000U;
    }
    const uint32_t exponent = backoff->failures > 6U ? 6U : backoff->failures;
    const uint32_t base = 1000U << exponent;
    const uint32_t capped = base > 60000U ? 60000U : base;
    const uint32_t jitter_width = capped / 4U + 1U;
    uint32_t delay_ms = capped - capped / 8U + random_value % jitter_width;
    if (delay_ms > 60000U) {
        delay_ms = 60000U;
    }
    if (backoff->failures != UINT32_MAX) {
        backoff->failures++;
    }
    backoff->next_attempt_us = now_us + (int64_t)delay_ms * INT64_C(1000);
    return delay_ms;
}

bool pm_telemetry_backoff_due(const pm_telemetry_backoff_t *backoff, int64_t now_us)
{
    return backoff != NULL && now_us >= backoff->next_attempt_us;
}
