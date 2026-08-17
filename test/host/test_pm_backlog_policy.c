#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "pm_backlog_policy.h"

static unsigned failures;

#define CHECK(condition)                                                                       \
    do {                                                                                       \
        if (!(condition)) {                                                                    \
            failures++;                                                                        \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #condition);             \
        }                                                                                      \
    } while (0)

typedef struct {
    size_t lengths[17];
    size_t calls;
    size_t fail_at;
} probe_fixture_t;

static pm_backlog_probe_status_t fixture_probe(size_t records, size_t *bytes,
                                                void *opaque)
{
    probe_fixture_t *fixture = (probe_fixture_t *)opaque;
    fixture->calls++;
    if (records == fixture->fail_at) {
        return PM_BACKLOG_PROBE_FAILED;
    }
    *bytes = fixture->lengths[records];
    return PM_BACKLOG_PROBE_OK;
}

static void test_exact_8287_regression(void)
{
    probe_fixture_t fixture = {0};
    fixture.lengths[16] = 8287U;
    fixture.lengths[15] = 7772U;
    pm_backlog_plan_t plan = {0};
    CHECK(pm_backlog_select_largest_fitting(16U, 16U, 16U, 8193U,
                                             fixture_probe, &fixture, &plan) ==
          PM_BACKLOG_PLAN_OK);
    CHECK(plan.candidate_records == 16U);
    CHECK(plan.selected_records == 15U);
    CHECK(plan.serialized_bytes == 7772U);
    CHECK(plan.serialized_bytes + 1U <= plan.body_capacity);
    CHECK(plan.reduced);
    CHECK(fixture.calls == 2U);
}

static void test_small_and_variable_batches_select_largest_fit(void)
{
    probe_fixture_t fixture = {0};
    fixture.lengths[1] = 563U;
    fixture.lengths[2] = 1300U;
    fixture.lengths[3] = 2500U;
    fixture.lengths[4] = 8193U;
    pm_backlog_plan_t plan = {0};
    CHECK(pm_backlog_select_largest_fitting(3U, 16U, 16U, 8193U,
                                             fixture_probe, &fixture, &plan) ==
          PM_BACKLOG_PLAN_OK);
    CHECK(plan.selected_records == 3U);
    CHECK(!plan.reduced);
    CHECK(pm_backlog_select_largest_fitting(4U, 16U, 16U, 8193U,
                                             fixture_probe, &fixture, &plan) ==
          PM_BACKLOG_PLAN_OK);
    CHECK(plan.selected_records == 3U);
    CHECK(plan.reduced);
    CHECK(pm_backlog_select_largest_fitting(4U, 2U, 16U, 8193U,
                                             fixture_probe, &fixture, &plan) ==
          PM_BACKLOG_PLAN_OK);
    CHECK(plan.selected_records == 2U);
    CHECK(plan.candidate_records == 2U);
}

static void test_record_and_byte_bounds(void)
{
    probe_fixture_t fixture = {0};
    for (size_t count = 1U; count <= 16U; ++count) {
        fixture.lengths[count] = 40U + count * 500U;
    }
    pm_backlog_plan_t plan = {0};
    CHECK(pm_backlog_select_largest_fitting(16U, 8U, 16U, 8193U,
                                             fixture_probe, &fixture, &plan) ==
          PM_BACKLOG_PLAN_OK);
    CHECK(plan.selected_records == 8U);
    fixture.lengths[8] = 8192U;
    fixture.calls = 0U;
    CHECK(pm_backlog_select_largest_fitting(8U, 8U, 16U, 8193U,
                                             fixture_probe, &fixture, &plan) ==
          PM_BACKLOG_PLAN_OK);
    CHECK(plan.selected_records == 8U);
    CHECK(plan.serialized_bytes + 1U == 8193U);
    fixture.lengths[1] = 563U;
    CHECK(pm_backlog_select_largest_fitting(1U, 1U, 16U, 8193U,
                                             fixture_probe, &fixture, &plan) ==
          PM_BACKLOG_PLAN_OK);
    CHECK(plan.selected_records == 1U);
    CHECK(pm_backlog_bounded_record_limit(0U, 16U) == 1U);
    CHECK(pm_backlog_bounded_record_limit(99U, 16U) == 16U);
}

static void test_fail_closed_edges(void)
{
    probe_fixture_t fixture = {0};
    fixture.lengths[1] = 9000U;
    pm_backlog_plan_t plan = {0};
    CHECK(pm_backlog_select_largest_fitting(1U, 16U, 16U, 8193U,
                                             fixture_probe, &fixture, &plan) ==
          PM_BACKLOG_PLAN_SINGLE_RECORD_TOO_LARGE);
    CHECK(plan.selected_records == 0U);
    fixture.fail_at = 2U;
    fixture.lengths[2] = 1000U;
    CHECK(pm_backlog_select_largest_fitting(2U, 16U, 16U, 8193U,
                                             fixture_probe, &fixture, &plan) ==
          PM_BACKLOG_PLAN_SERIALIZATION_FAILED);
    CHECK(pm_backlog_select_largest_fitting(0U, 16U, 16U, 8193U,
                                             fixture_probe, &fixture, &plan) ==
          PM_BACKLOG_PLAN_EMPTY);
    CHECK(pm_backlog_select_largest_fitting(1U, 1U, 0U, 8193U,
                                             fixture_probe, &fixture, &plan) ==
          PM_BACKLOG_PLAN_INVALID_ARGUMENT);
}

static void test_missing_prefix_policy(void)
{
    pm_missing_prefix_t prefix = {0};
    CHECK(pm_backlog_detect_missing_prefix(1U, true, true, 1089U, &prefix) ==
          PM_MISSING_PREFIX_CONFIRMED);
    CHECK(prefix.first_sequence == 2U);
    CHECK(prefix.last_sequence == 1088U);
    CHECK(prefix.count == 1087U);
    CHECK(pm_backlog_detect_missing_prefix(1088U, true, true, 1089U, &prefix) ==
          PM_MISSING_PREFIX_NONE);
    CHECK(pm_backlog_detect_missing_prefix(1U, false, true, 1089U, &prefix) ==
          PM_MISSING_PREFIX_NOT_CONFIRMED);
    CHECK(pm_backlog_detect_missing_prefix(1U, true, false, 1089U, &prefix) ==
          PM_MISSING_PREFIX_NOT_CONFIRMED);
    CHECK(pm_backlog_detect_missing_prefix(1U, true, true, 2U, &prefix) ==
          PM_MISSING_PREFIX_NONE);
    CHECK(pm_backlog_detect_missing_prefix(100U, true, true, 1089U, &prefix) ==
          PM_MISSING_PREFIX_CONFIRMED);
    CHECK(prefix.first_sequence == 101U);
    CHECK(prefix.last_sequence == 1088U);
    CHECK(pm_backlog_detect_missing_prefix(1U, true, true, 2000U, &prefix) ==
          PM_MISSING_PREFIX_CONFIRMED);
    CHECK(prefix.first_sequence == 2U);
    CHECK(prefix.last_sequence == 1999U);
    CHECK(pm_backlog_detect_missing_prefix(UINT64_MAX, true, true, 1089U, &prefix) ==
          PM_MISSING_PREFIX_NONE);
}

static void test_repeated_selection_has_fixed_storage(void)
{
    probe_fixture_t fixture = {0};
    fixture.lengths[16] = 8287U;
    fixture.lengths[15] = 7772U;
    for (size_t iteration = 0U; iteration < 100000U; ++iteration) {
        pm_backlog_plan_t plan = {0};
        CHECK(pm_backlog_select_largest_fitting(16U, 16U, 16U, 8193U,
                                                 fixture_probe, &fixture, &plan) ==
              PM_BACKLOG_PLAN_OK);
        CHECK(plan.selected_records == 15U);
    }
}

int main(void)
{
    test_exact_8287_regression();
    test_small_and_variable_batches_select_largest_fit();
    test_record_and_byte_bounds();
    test_fail_closed_edges();
    test_missing_prefix_policy();
    test_repeated_selection_has_fixed_storage();
    printf("{\"suite\":\"pm_backlog_policy\",\"failures\":%u}\n", failures);
    return failures == 0U ? 0 : 1;
}
