#include "runtime_startup.h"

void pm_runtime_delete_task_set(const pm_runtime_task_spec_t *specs, size_t count)
{
    if (specs == NULL) {
        return;
    }
    while (count > 0U) {
        count--;
        if (specs[count].handle != NULL && *specs[count].handle != NULL) {
            vTaskDelete(*specs[count].handle);
            *specs[count].handle = NULL;
        }
    }
}

esp_err_t pm_runtime_create_task_set(const pm_runtime_task_spec_t *specs, size_t count)
{
    if (specs == NULL || count == 0U) {
        return ESP_ERR_INVALID_ARG;
    }
    for (size_t i = 0U; i < count; ++i) {
        if (specs[i].function == NULL || specs[i].name == NULL || specs[i].handle == NULL) {
            pm_runtime_delete_task_set(specs, i);
            return ESP_ERR_INVALID_ARG;
        }
        *specs[i].handle = NULL;
        if (xTaskCreate(specs[i].function, specs[i].name, specs[i].stack_depth,
                        specs[i].argument, specs[i].priority, specs[i].handle) != pdPASS) {
            pm_runtime_delete_task_set(specs, i + 1U);
            return ESP_ERR_NO_MEM;
        }
    }
    return ESP_OK;
}
