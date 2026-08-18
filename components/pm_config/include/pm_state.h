#pragma once

#include <stdbool.h>
#include <stdint.h>

typedef enum {
    PM_STATE_BOOT = 0,
    PM_STATE_SELF_TEST,
    PM_STATE_UNPROVISIONED_COM,
    PM_STATE_CONNECTING_WIFI,
    PM_STATE_ENROLLING,
    PM_STATE_RUNNING,
    PM_STATE_DEGRADED_NETWORK,
    PM_STATE_DEGRADED_SERVER,
    PM_STATE_DEGRADED_METER,
    PM_STATE_OTA_PENDING,
    PM_STATE_OTA_INSTALLING,
    PM_STATE_RECOVERY_COM,
    PM_STATE_SAFE_REBOOT,
    PM_STATE_COUNT,
} pm_operating_state_t;

typedef enum {
    PM_EVENT_BOOTSTRAP = 0,
    PM_EVENT_SELF_TEST_OK,
    PM_EVENT_SELF_TEST_FAILED,
    PM_EVENT_CONFIG_MISSING,
    PM_EVENT_CONFIG_VALID,
    PM_EVENT_WIFI_CONNECTED,
    PM_EVENT_WIFI_FAILED,
    PM_EVENT_ENROLLMENT_REQUIRED,
    PM_EVENT_ENROLLED,
    PM_EVENT_SERVER_FAILED,
    PM_EVENT_SERVER_RECOVERED,
    PM_EVENT_METER_FAILED,
    PM_EVENT_METER_RECOVERED,
    PM_EVENT_OTA_AVAILABLE,
    PM_EVENT_OTA_STARTED,
    PM_EVENT_OTA_FINISHED,
    PM_EVENT_PHYSICAL_RECOVERY,
    PM_EVENT_SAFE_REBOOT,
} pm_state_event_t;

typedef enum {
    PM_HEALTH_NETWORK = 1U << 0,
    PM_HEALTH_SERVER = 1U << 1,
    PM_HEALTH_METER = 1U << 2,
    PM_HEALTH_TIME = 1U << 3,
} pm_health_flag_t;

typedef struct {
    pm_operating_state_t state;
    uint32_t health_flags;
    uint32_t transition_count;
    int64_t entered_monotonic_us;
} pm_state_machine_t;

void pm_state_init(pm_state_machine_t *machine, int64_t now_us);
bool pm_state_transition(pm_state_machine_t *machine, pm_state_event_t event, int64_t now_us);
void pm_state_health_set(pm_state_machine_t *machine, pm_health_flag_t flag, bool healthy);
const char *pm_state_name(pm_operating_state_t state);

