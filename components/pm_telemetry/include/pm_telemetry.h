#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "esp_err.h"
#include "pm_meter.h"

#ifdef __cplusplus
extern "C" {
#endif

#define PM_TELEMETRY_PROTOCOL_ID "pm-telemetry/2.0.0"

typedef struct {
    pm_meter_sample_t measurement;
    uint64_t sample_sequence;
} pm_telemetry_sample_t;

/* Fixed-memory latest-value-wins queue. Callers provide synchronization. */
typedef struct {
    pm_telemetry_sample_t in_flight;
    pm_telemetry_sample_t pending;
    uint64_t next_sequence;
    uint64_t replaced_pending;
    uint64_t failed_transmissions;
    bool in_flight_present;
    bool pending_present;
} pm_telemetry_slot_t;

typedef struct {
    uint32_t failures;
    int64_t next_attempt_us;
} pm_telemetry_backoff_t;

void pm_telemetry_slot_init(pm_telemetry_slot_t *slot);
esp_err_t pm_telemetry_offer(pm_telemetry_slot_t *slot, const pm_meter_sample_t *measurement,
                             uint64_t *sample_sequence);
bool pm_telemetry_begin_send(pm_telemetry_slot_t *slot, pm_telemetry_sample_t *sample);
esp_err_t pm_telemetry_complete_send(pm_telemetry_slot_t *slot, uint64_t sample_sequence,
                                     bool accepted);
size_t pm_telemetry_resident_samples(const pm_telemetry_slot_t *slot);

void pm_telemetry_backoff_reset(pm_telemetry_backoff_t *backoff, int64_t now_us);
uint32_t pm_telemetry_backoff_fail(pm_telemetry_backoff_t *backoff, int64_t now_us,
                                   uint32_t random_value);
bool pm_telemetry_backoff_due(const pm_telemetry_backoff_t *backoff, int64_t now_us);

#ifdef __cplusplus
}
#endif
