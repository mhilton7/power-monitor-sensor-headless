#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    PM_BACKLOG_PROBE_OK = 0,
    PM_BACKLOG_PROBE_TOO_LARGE,
    PM_BACKLOG_PROBE_FAILED,
} pm_backlog_probe_status_t;

typedef pm_backlog_probe_status_t (*pm_backlog_probe_fn)(size_t record_count,
                                                         size_t *serialized_bytes,
                                                         void *context);

typedef enum {
    PM_BACKLOG_PLAN_OK = 0,
    PM_BACKLOG_PLAN_EMPTY,
    PM_BACKLOG_PLAN_SINGLE_RECORD_TOO_LARGE,
    PM_BACKLOG_PLAN_SERIALIZATION_FAILED,
    PM_BACKLOG_PLAN_INVALID_ARGUMENT,
} pm_backlog_plan_status_t;

typedef struct {
    size_t configured_max_records;
    size_t available_records;
    size_t candidate_records;
    size_t selected_records;
    size_t serialized_bytes;
    size_t body_capacity;
    bool reduced;
} pm_backlog_plan_t;

typedef struct {
    uint64_t first_sequence;
    uint64_t last_sequence;
    uint64_t count;
} pm_missing_prefix_t;

typedef enum {
    PM_MISSING_PREFIX_NONE = 0,
    PM_MISSING_PREFIX_CONFIRMED,
    PM_MISSING_PREFIX_NOT_CONFIRMED,
    PM_MISSING_PREFIX_INVALID_ARGUMENT,
} pm_missing_prefix_status_t;

size_t pm_backlog_bounded_record_limit(size_t configured_max_records,
                                       size_t hard_record_limit);
pm_backlog_plan_status_t pm_backlog_select_largest_fitting(
    size_t available_records, size_t configured_max_records,
    size_t hard_record_limit, size_t body_capacity,
    pm_backlog_probe_fn probe, void *probe_context, pm_backlog_plan_t *plan);
pm_missing_prefix_status_t pm_backlog_detect_missing_prefix(
    uint64_t server_acknowledgement, bool storage_ready,
    bool inventory_complete, uint64_t earliest_local_sequence,
    pm_missing_prefix_t *prefix);

#ifdef __cplusplus
}
#endif
