#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define PM_DIAGNOSTIC_TASKS_MAX 8U
#define PM_DIAGNOSTIC_TASK_NAME_MAX 15U

typedef struct {
    char name[PM_DIAGNOSTIC_TASK_NAME_MAX + 1U];
    uint32_t stack_high_water_bytes;
    uint32_t configured_stack_bytes;
    bool watchdog_registered;
} pm_task_diagnostic_t;

typedef struct {
    uint32_t free_internal_heap;
    uint32_t minimum_free_internal_heap;
    uint32_t largest_internal_block;
    uint32_t free_psram;
    uint32_t tls_request_high_water_bytes;
    uint32_t reboot_reason;
    pm_task_diagnostic_t tasks[PM_DIAGNOSTIC_TASKS_MAX];
    size_t task_count;
} pm_diagnostics_snapshot_t;

void pm_diagnostics_capture(pm_diagnostics_snapshot_t *snapshot);
bool pm_diagnostics_add_task(pm_diagnostics_snapshot_t *snapshot, const char *name, uint32_t high_water_bytes,
                             uint32_t configured_bytes, bool watchdog_registered);
size_t pm_diagnostics_redact(const char *input, char *output, size_t output_size);

