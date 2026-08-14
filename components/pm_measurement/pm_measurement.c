#include "pm_measurement.h"

#include <string.h>

void pm_interval_init(pm_interval_accumulator_t *accumulator, uint32_t expected_samples)
{
    if (accumulator != NULL) {
        *accumulator = (pm_interval_accumulator_t){.expected_samples = expected_samples};
    }
}

bool pm_interval_add(pm_interval_accumulator_t *accumulator, const pm_meter_sample_t *sample,
                     uint16_t ct_rating_a)
{
    if (accumulator == NULL || sample == NULL || sample->status != PM_PZEM_OK ||
        !pm_meter_sample_valid(sample, ct_rating_a)) {
        if (accumulator != NULL) {
            accumulator->flags |= PM_INTERVAL_FLAG_MISSING_SAMPLE;
        }
        return false;
    }
    if (accumulator->valid_samples == 0U) {
        accumulator->first_energy_wh = sample->energy_wh;
        accumulator->interval_start_utc_ms = sample->sample_timestamp_utc_ms;
        accumulator->interval_start_monotonic_us = sample->sample_monotonic_us;
        accumulator->last_sample_monotonic_us = sample->sample_monotonic_us;
        accumulator->last_power_mw = sample->active_power_mw;
        accumulator->have_energy = true;
    } else {
        const int64_t elapsed_us = sample->sample_monotonic_us - accumulator->last_sample_monotonic_us;
        if (elapsed_us > 0 && elapsed_us <= INT64_C(60000000)) {
            const uint64_t mean_power_mw = (uint64_t)(accumulator->last_power_mw + sample->active_power_mw) / 2U;
            accumulator->trapezoid_power_mw_ms += mean_power_mw * (uint64_t)elapsed_us / 1000U;
        }
        accumulator->last_sample_monotonic_us = sample->sample_monotonic_us;
        accumulator->last_power_mw = sample->active_power_mw;
    }
    accumulator->last_energy_wh = sample->energy_wh;
    accumulator->interval_end_utc_ms = sample->sample_timestamp_utc_ms;
    accumulator->sum_voltage_mv += (uint32_t)sample->voltage_mv;
    accumulator->sum_current_ma += (uint32_t)sample->current_ma;
    accumulator->sum_power_mw += (uint32_t)sample->active_power_mw;
    accumulator->sum_frequency_mhz += (uint32_t)sample->frequency_mhz;
    accumulator->sum_pf_milli += (uint32_t)sample->power_factor_milli;
    accumulator->valid_samples++;
    if (!sample->time_trusted) {
        accumulator->flags |= PM_INTERVAL_FLAG_TIME_UNTRUSTED;
    }
    if (sample->simulated) {
        accumulator->flags |= PM_INTERVAL_FLAG_SIMULATED;
    }
    const uint32_t current_ma = (uint32_t)sample->current_ma;
    const uint32_t rated_ma = (uint32_t)ct_rating_a * 1000U;
    if (current_ma >= rated_ma * 9U / 10U) {
        accumulator->flags |= PM_INTERVAL_FLAG_CT_CRITICAL_90;
    } else if (current_ma >= rated_ma * 8U / 10U) {
        accumulator->flags |= PM_INTERVAL_FLAG_CT_WARNING_80;
    }
    return true;
}

bool pm_interval_finalize(pm_interval_accumulator_t *accumulator, pm_durable_interval_t *interval,
                          uint64_t maximum_plausible_mwh)
{
    if (accumulator == NULL || interval == NULL || accumulator->valid_samples == 0U) {
        return false;
    }
    const uint32_t count = accumulator->valid_samples;
    const uint64_t diagnostic_mwh = accumulator->trapezoid_power_mw_ms / UINT64_C(3600000);
    *interval = (pm_durable_interval_t){
        .voltage_mv = (int32_t)(accumulator->sum_voltage_mv / count),
        .current_ma = (int32_t)(accumulator->sum_current_ma / count),
        .active_power_mw = (int32_t)(accumulator->sum_power_mw / count),
        .frequency_mhz = (int32_t)(accumulator->sum_frequency_mhz / count),
        .power_factor_milli = (int32_t)(accumulator->sum_pf_milli / count),
        .pzem_energy_start_wh = accumulator->first_energy_wh,
        .pzem_energy_end_wh = accumulator->last_energy_wh,
        .diagnostic_energy_mwh = diagnostic_mwh,
        .sample_count = count,
        .expected_samples = accumulator->expected_samples,
        .completeness_permille = (uint16_t)(((uint64_t)count * 1000U /
                                              (accumulator->expected_samples == 0U ? count : accumulator->expected_samples)) > 1000U
                                                 ? 1000U
                                                 : ((uint64_t)count * 1000U /
                                                    (accumulator->expected_samples == 0U ? count : accumulator->expected_samples))),
        .selected_energy_source = PM_ENERGY_NONE,
        .flags = accumulator->flags,
        .start_utc_ms = accumulator->interval_start_utc_ms,
        .end_utc_ms = accumulator->interval_end_utc_ms,
        .start_monotonic_us = accumulator->interval_start_monotonic_us,
        .end_monotonic_us = accumulator->last_sample_monotonic_us,
    };
    /* A cumulative counter delta needs two distinct authenticated frames.
     * One surviving frame is incomplete evidence, never a measured zero. */
    const bool have_delta_boundary = count >= 2U &&
                                     accumulator->last_sample_monotonic_us >
                                         accumulator->interval_start_monotonic_us;
    if (!have_delta_boundary) {
        interval->flags |= PM_INTERVAL_FLAG_MISSING_SAMPLE;
    } else if (accumulator->last_energy_wh >= accumulator->first_energy_wh) {
        const uint64_t delta_mwh = (accumulator->last_energy_wh - accumulator->first_energy_wh) * 1000U;
        if (delta_mwh <= maximum_plausible_mwh) {
            interval->selected_energy_mwh = delta_mwh;
            interval->selected_energy_source = PM_ENERGY_PZEM_DELTA;
        } else {
            interval->flags |= PM_INTERVAL_FLAG_IMPLAUSIBLE_JUMP;
        }
    } else if (accumulator->first_energy_wh > UINT32_C(0xF0000000) &&
               accumulator->last_energy_wh < UINT32_C(0x0FFFFFFF)) {
        const uint64_t delta_wh = (UINT64_C(1) << 32U) - accumulator->first_energy_wh + accumulator->last_energy_wh;
        interval->flags |= PM_INTERVAL_FLAG_PZEM_ROLLOVER;
        if (delta_wh * 1000U <= maximum_plausible_mwh) {
            interval->selected_energy_mwh = delta_wh * 1000U;
            interval->selected_energy_source = PM_ENERGY_PZEM_DELTA;
        }
    } else {
        interval->flags |= PM_INTERVAL_FLAG_PZEM_RESET;
    }
    /* Integration is evidence only. Missing or suspect PZEM deltas remain missing. */
    *accumulator = (pm_interval_accumulator_t){.expected_samples = accumulator->expected_samples};
    return true;
}
