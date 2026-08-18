#include "pm_state.h"

#include <stddef.h>

static bool transition_to(pm_state_machine_t *machine, pm_operating_state_t next, int64_t now_us)
{
    if (machine == NULL || next >= PM_STATE_COUNT) {
        return false;
    }
    if (machine->state != next) {
        machine->state = next;
        machine->transition_count++;
        machine->entered_monotonic_us = now_us;
    }
    return true;
}

void pm_state_init(pm_state_machine_t *machine, int64_t now_us)
{
    if (machine != NULL) {
        *machine = (pm_state_machine_t){
            .state = PM_STATE_BOOT,
            .health_flags = 0U,
            .transition_count = 0U,
            .entered_monotonic_us = now_us,
        };
    }
}

bool pm_state_transition(pm_state_machine_t *machine, pm_state_event_t event, int64_t now_us)
{
    if (machine == NULL) {
        return false;
    }
    switch (event) {
    case PM_EVENT_BOOTSTRAP:
        return machine->state == PM_STATE_BOOT && transition_to(machine, PM_STATE_SELF_TEST, now_us);
    case PM_EVENT_SELF_TEST_OK:
        return machine->state == PM_STATE_SELF_TEST && transition_to(machine, PM_STATE_CONNECTING_WIFI, now_us);
    case PM_EVENT_SELF_TEST_FAILED:
        return machine->state == PM_STATE_SELF_TEST && transition_to(machine, PM_STATE_RECOVERY_COM, now_us);
    case PM_EVENT_CONFIG_MISSING:
        return (machine->state == PM_STATE_BOOT || machine->state == PM_STATE_SELF_TEST) &&
               transition_to(machine, PM_STATE_UNPROVISIONED_COM, now_us);
    case PM_EVENT_CONFIG_VALID:
        return (machine->state == PM_STATE_BOOT || machine->state == PM_STATE_SELF_TEST ||
                machine->state == PM_STATE_RECOVERY_COM || machine->state == PM_STATE_UNPROVISIONED_COM) &&
               transition_to(machine, PM_STATE_CONNECTING_WIFI, now_us);
    case PM_EVENT_WIFI_CONNECTED:
        return (machine->state == PM_STATE_CONNECTING_WIFI || machine->state == PM_STATE_DEGRADED_NETWORK) &&
               transition_to(machine, PM_STATE_RUNNING, now_us);
    case PM_EVENT_WIFI_FAILED:
        return transition_to(machine, PM_STATE_DEGRADED_NETWORK, now_us);
    case PM_EVENT_ENROLLMENT_REQUIRED:
        return transition_to(machine, PM_STATE_ENROLLING, now_us);
    case PM_EVENT_ENROLLED:
        return machine->state == PM_STATE_ENROLLING && transition_to(machine, PM_STATE_RUNNING, now_us);
    case PM_EVENT_SERVER_FAILED:
        return transition_to(machine, PM_STATE_DEGRADED_SERVER, now_us);
    case PM_EVENT_SERVER_RECOVERED:
    case PM_EVENT_METER_RECOVERED:
        return transition_to(machine, PM_STATE_RUNNING, now_us);
    case PM_EVENT_METER_FAILED:
        return transition_to(machine, PM_STATE_DEGRADED_METER, now_us);
    case PM_EVENT_OTA_AVAILABLE:
        return transition_to(machine, PM_STATE_OTA_PENDING, now_us);
    case PM_EVENT_OTA_STARTED:
        return machine->state == PM_STATE_OTA_PENDING && transition_to(machine, PM_STATE_OTA_INSTALLING, now_us);
    case PM_EVENT_OTA_FINISHED:
        return machine->state == PM_STATE_OTA_INSTALLING && transition_to(machine, PM_STATE_SAFE_REBOOT, now_us);
    case PM_EVENT_PHYSICAL_RECOVERY:
        return transition_to(machine, PM_STATE_RECOVERY_COM, now_us);
    case PM_EVENT_SAFE_REBOOT:
        return transition_to(machine, PM_STATE_SAFE_REBOOT, now_us);
    default:
        return false;
    }
}

void pm_state_health_set(pm_state_machine_t *machine, pm_health_flag_t flag, bool healthy)
{
    if (machine == NULL) {
        return;
    }
    if (healthy) {
        machine->health_flags |= (uint32_t)flag;
    } else {
        machine->health_flags &= ~(uint32_t)flag;
    }
}

const char *pm_state_name(pm_operating_state_t state)
{
    static const char *const names[PM_STATE_COUNT] = {
        "BOOT", "SELF_TEST", "UNPROVISIONED_COM", "CONNECTING_WIFI", "ENROLLING", "RUNNING",
        "DEGRADED_NETWORK", "DEGRADED_SERVER", "DEGRADED_METER", "OTA_PENDING",
        "OTA_INSTALLING", "RECOVERY_COM", "SAFE_REBOOT",
    };
    return state < PM_STATE_COUNT ? names[state] : "INVALID";
}

