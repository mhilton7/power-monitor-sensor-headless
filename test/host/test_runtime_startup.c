#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "runtime_startup.h"

#define CHECK(condition)                                                                                              \
    do {                                                                                                              \
        if (!(condition)) {                                                                                           \
            fprintf(stderr, "check failed at %s:%d: %s\n", __FILE__, __LINE__, #condition);                         \
            return 1;                                                                                                 \
        }                                                                                                             \
    } while (0)

static size_t s_create_call;
static size_t s_fail_call;
static size_t s_delete_count;
static TaskHandle_t s_deleted[4];

BaseType_t xTaskCreate(TaskFunction_t task, const char *name, uint32_t stack_depth,
                       void *context, UBaseType_t priority, TaskHandle_t *handle)
{
    (void)task;
    (void)name;
    (void)stack_depth;
    (void)context;
    (void)priority;
    const size_t call = s_create_call++;
    if (call == s_fail_call) {
        return pdFAIL;
    }
    *handle = (TaskHandle_t)(uintptr_t)(call + 1U);
    return pdPASS;
}

void vTaskDelete(TaskHandle_t handle)
{
    s_deleted[s_delete_count++] = handle;
}

void vTaskDelay(TickType_t ticks)
{
    (void)ticks;
}

static void dummy_task(void *argument)
{
    (void)argument;
}

static int test_failure_at_every_creation_index_rolls_back(void)
{
    for (size_t failure = 0U; failure < 4U; ++failure) {
        TaskHandle_t handles[4] = {0};
        const pm_runtime_task_spec_t specs[] = {
            {dummy_task, "a", 1U, NULL, 1U, &handles[0]},
            {dummy_task, "b", 1U, NULL, 1U, &handles[1]},
            {dummy_task, "c", 1U, NULL, 1U, &handles[2]},
            {dummy_task, "d", 1U, NULL, 1U, &handles[3]},
        };
        s_create_call = 0U;
        s_fail_call = failure;
        s_delete_count = 0U;
        CHECK(pm_runtime_create_task_set(specs, 4U) == ESP_ERR_NO_MEM);
        CHECK(s_create_call == failure + 1U);
        CHECK(s_delete_count == failure);
        for (size_t index = 0U; index < 4U; ++index) {
            CHECK(handles[index] == NULL);
        }
        for (size_t index = 0U; index < failure; ++index) {
            CHECK(s_deleted[index] == (TaskHandle_t)(uintptr_t)(failure - index));
        }
    }
    return 0;
}

static int test_success_retains_all_handles(void)
{
    TaskHandle_t handles[4] = {0};
    const pm_runtime_task_spec_t specs[] = {
        {dummy_task, "a", 1U, NULL, 1U, &handles[0]},
        {dummy_task, "b", 1U, NULL, 1U, &handles[1]},
        {dummy_task, "c", 1U, NULL, 1U, &handles[2]},
        {dummy_task, "d", 1U, NULL, 1U, &handles[3]},
    };
    s_create_call = 0U;
    s_fail_call = 4U;
    s_delete_count = 0U;
    CHECK(pm_runtime_create_task_set(specs, 4U) == ESP_OK);
    CHECK(s_delete_count == 0U);
    for (size_t index = 0U; index < 4U; ++index) {
        CHECK(handles[index] == (TaskHandle_t)(uintptr_t)(index + 1U));
    }
    return 0;
}

int main(void)
{
    CHECK(test_failure_at_every_creation_index_rolls_back() == 0);
    CHECK(test_success_retains_all_handles() == 0);
    puts("runtime task-set startup tests passed");
    return 0;
}
