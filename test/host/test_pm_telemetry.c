#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "pm_telemetry.h"

static unsigned failures;

#define CHECK(expression) do { if (!(expression)) { failures++; } } while (0)

static pm_meter_sample_t measurement(int32_t watts)
{
    return (pm_meter_sample_t){
        .voltage_mv = 240000,
        .current_ma = 1000,
        .active_power_mw = watts * 1000,
        .frequency_mhz = 60000,
        .power_factor_milli = 950,
        .energy_wh = (uint64_t)watts,
        .sample_monotonic_us = (int64_t)watts * 1000,
        .status = PM_PZEM_OK,
        .time_trusted = true,
    };
}

static void test_latest_value_wins(void)
{
    pm_telemetry_slot_t slot;
    pm_telemetry_slot_init(&slot);
    slot.next_sequence = 10U;
    pm_meter_sample_t missing_ten = measurement(10);
    uint64_t sequence = 0U;
    CHECK(pm_telemetry_offer(&slot, &missing_ten, &sequence) == ESP_OK);
    CHECK(sequence == 10U);
    pm_telemetry_sample_t in_flight = {0};
    CHECK(pm_telemetry_begin_send(&slot, &in_flight));
    CHECK(in_flight.sample_sequence == 10U);
    pm_meter_sample_t eleven = measurement(11);
    pm_meter_sample_t newest = measurement(12);
    CHECK(pm_telemetry_offer(&slot, &eleven, &sequence) == ESP_OK);
    CHECK(sequence == 11U);
    CHECK(pm_telemetry_complete_send(&slot, 10U, false) == ESP_OK);
    CHECK(slot.failed_transmissions == 1U);
    memset(&in_flight, 0, sizeof(in_flight));
    CHECK(pm_telemetry_begin_send(&slot, &in_flight));
    CHECK(in_flight.sample_sequence == 11U);
    CHECK(pm_telemetry_complete_send(&slot, 11U, true) == ESP_OK);

    CHECK(pm_telemetry_offer(&slot, &eleven, &sequence) == ESP_OK);
    CHECK(sequence == 12U);
    CHECK(pm_telemetry_offer(&slot, &newest, &sequence) == ESP_OK);
    CHECK(sequence == 13U);
    CHECK(slot.replaced_pending == 1U);
    CHECK(pm_telemetry_resident_samples(&slot) == 1U);
    memset(&in_flight, 0, sizeof(in_flight));
    CHECK(pm_telemetry_begin_send(&slot, &in_flight));
    CHECK(in_flight.sample_sequence == 13U);
    CHECK(in_flight.measurement.active_power_mw == 12000);
    CHECK(pm_telemetry_complete_send(&slot, 13U, true) == ESP_OK);
    CHECK(pm_telemetry_resident_samples(&slot) == 0U);
}

static void test_memory_is_strictly_bounded(void)
{
    pm_telemetry_slot_t slot;
    pm_telemetry_slot_init(&slot);
    for (int32_t i = 1; i <= 100000; ++i) {
        pm_meter_sample_t sample = measurement(i);
        CHECK(pm_telemetry_offer(&slot, &sample, NULL) == ESP_OK);
        CHECK(pm_telemetry_resident_samples(&slot) <= 1U);
    }
    CHECK(slot.next_sequence == 100001U);
    CHECK(slot.replaced_pending == 99999U);
}

static void test_bounded_backoff_and_reset(void)
{
    pm_telemetry_backoff_t backoff;
    pm_telemetry_backoff_reset(&backoff, 1000);
    CHECK(pm_telemetry_backoff_due(&backoff, 1000));
    uint32_t prior = 0U;
    for (unsigned i = 0U; i < 20U; ++i) {
        const uint32_t delay = pm_telemetry_backoff_fail(&backoff, 1000, i);
        CHECK(delay >= 875U);
        CHECK(delay <= 60000U);
        if (i < 6U) CHECK(delay >= prior);
        prior = delay;
        CHECK(!pm_telemetry_backoff_due(&backoff, 1000));
    }
    pm_telemetry_backoff_reset(&backoff, 5000);
    CHECK(backoff.failures == 0U);
    CHECK(pm_telemetry_backoff_due(&backoff, 5000));
}

int main(void)
{
    test_latest_value_wins();
    test_memory_is_strictly_bounded();
    test_bounded_backoff_and_reset();
    printf("{\"suite\":\"pm_telemetry\",\"failures\":%u}\n", failures);
    return failures == 0U ? 0 : 1;
}
