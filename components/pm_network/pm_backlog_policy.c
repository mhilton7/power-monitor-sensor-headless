#include "pm_backlog_policy.h"

#include <limits.h>

size_t pm_backlog_bounded_record_limit(size_t configured_max_records,
                                       size_t hard_record_limit)
{
    if (hard_record_limit == 0U) {
        return 0U;
    }
    if (configured_max_records == 0U) {
        return 1U;
    }
    return configured_max_records > hard_record_limit ? hard_record_limit :
                                                        configured_max_records;
}

pm_backlog_plan_status_t pm_backlog_select_largest_fitting(
    size_t available_records, size_t configured_max_records,
    size_t hard_record_limit, size_t body_capacity,
    pm_backlog_probe_fn probe, void *probe_context, pm_backlog_plan_t *plan)
{
    if (plan == NULL || probe == NULL || hard_record_limit == 0U ||
        body_capacity < 2U) {
        return PM_BACKLOG_PLAN_INVALID_ARGUMENT;
    }
    *plan = (pm_backlog_plan_t){
        .configured_max_records = configured_max_records,
        .available_records = available_records,
        .body_capacity = body_capacity,
    };
    if (available_records == 0U) {
        return PM_BACKLOG_PLAN_EMPTY;
    }
    const size_t bounded = pm_backlog_bounded_record_limit(
        configured_max_records, hard_record_limit);
    size_t candidate = available_records < bounded ? available_records : bounded;
    plan->candidate_records = candidate;
    while (candidate > 0U) {
        size_t serialized_bytes = 0U;
        const pm_backlog_probe_status_t status =
            probe(candidate, &serialized_bytes, probe_context);
        if (status == PM_BACKLOG_PROBE_FAILED) {
            return PM_BACKLOG_PLAN_SERIALIZATION_FAILED;
        }
        if (status == PM_BACKLOG_PROBE_OK &&
            serialized_bytes < body_capacity) {
            plan->selected_records = candidate;
            plan->serialized_bytes = serialized_bytes;
            plan->reduced = candidate < plan->candidate_records;
            return PM_BACKLOG_PLAN_OK;
        }
        plan->serialized_bytes = serialized_bytes;
        candidate--;
    }
    plan->reduced = plan->candidate_records > 1U;
    return PM_BACKLOG_PLAN_SINGLE_RECORD_TOO_LARGE;
}

pm_missing_prefix_status_t pm_backlog_detect_missing_prefix(
    uint64_t server_acknowledgement, bool storage_ready,
    bool inventory_complete, uint64_t earliest_local_sequence,
    pm_missing_prefix_t *prefix)
{
    if (prefix == NULL) {
        return PM_MISSING_PREFIX_INVALID_ARGUMENT;
    }
    *prefix = (pm_missing_prefix_t){0};
    if (server_acknowledgement == UINT64_MAX ||
        earliest_local_sequence == 0U ||
        earliest_local_sequence <= server_acknowledgement + 1U) {
        return PM_MISSING_PREFIX_NONE;
    }
    if (!storage_ready || !inventory_complete) {
        return PM_MISSING_PREFIX_NOT_CONFIRMED;
    }
    prefix->first_sequence = server_acknowledgement + 1U;
    prefix->last_sequence = earliest_local_sequence - 1U;
    prefix->count = prefix->last_sequence - prefix->first_sequence + 1U;
    return PM_MISSING_PREFIX_CONFIRMED;
}
