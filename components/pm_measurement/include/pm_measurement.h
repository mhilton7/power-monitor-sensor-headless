#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "pm_meter.h"

typedef enum {
    PM_ENERGY_NONE = 0,
    PM_ENERGY_PZEM_DELTA,
    PM_ENERGY_POWER_DIAGNOSTIC,
} pm_energy_source_t;

typedef enum {
    PM_INTERVAL_FLAG_NONE = 0U,
    PM_INTERVAL_FLAG_TIME_UNTRUSTED = 1U << 0,
    PM_INTERVAL_FLAG_MISSING_SAMPLE = 1U << 1,
    PM_INTERVAL_FLAG_PZEM_RESET = 1U << 2,
    PM_INTERVAL_FLAG_PZEM_ROLLOVER = 1U << 3,
    PM_INTERVAL_FLAG_IMPLAUSIBLE_JUMP = 1U << 4,
    PM_INTERVAL_FLAG_CT_WARNING_80 = 1U << 5,
    PM_INTERVAL_FLAG_CT_CRITICAL_90 = 1U << 6,
    PM_INTERVAL_FLAG_SIMULATED = 1U << 7,
} pm_interval_flag_t;

typedef struct {
    uint32_t expected_samples;
    uint32_t valid_samples;
    uint64_t sum_voltage_mv;
    uint64_t sum_current_ma;
    uint64_t sum_power_mw;
    uint64_t sum_frequency_mhz;
    uint64_t sum_pf_milli;
    uint64_t first_energy_wh;
    uint64_t last_energy_wh;
    uint64_t trapezoid_power_mw_ms;
    int64_t interval_start_utc_ms;
    int64_t interval_end_utc_ms;
    int64_t interval_start_monotonic_us;
    int64_t last_sample_monotonic_us;
    int32_t last_power_mw;
    uint32_t flags;
    bool have_energy;
} pm_interval_accumulator_t;

typedef struct {
    int32_t voltage_mv;
    int32_t current_ma;
    int32_t active_power_mw;
    int32_t frequency_mhz;
    int32_t power_factor_milli;
    uint64_t pzem_energy_start_wh;
    uint64_t pzem_energy_end_wh;
    uint64_t selected_energy_mwh;
    uint64_t diagnostic_energy_mwh;
    uint32_t sample_count;
    uint32_t expected_samples;
    uint16_t completeness_permille;
    pm_energy_source_t selected_energy_source;
    uint32_t flags;
    int64_t start_utc_ms;
    int64_t end_utc_ms;
    int64_t start_monotonic_us;
    int64_t end_monotonic_us;
} pm_durable_interval_t;

void pm_interval_init(pm_interval_accumulator_t *accumulator, uint32_t expected_samples);
bool pm_interval_add(pm_interval_accumulator_t *accumulator, const pm_meter_sample_t *sample,
                     uint16_t ct_rating_a);
bool pm_interval_finalize(pm_interval_accumulator_t *accumulator, pm_durable_interval_t *interval,
                          uint64_t maximum_plausible_mwh);

