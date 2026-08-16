#pragma once

#include <stddef.h>
#include <stdint.h>

#include "esp_err.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

typedef struct {
    TaskFunction_t function;
    const char *name;
    uint32_t stack_depth;
    void *argument;
    UBaseType_t priority;
    TaskHandle_t *handle;
} pm_runtime_task_spec_t;

esp_err_t pm_runtime_create_task_set(const pm_runtime_task_spec_t *specs, size_t count);
void pm_runtime_delete_task_set(const pm_runtime_task_spec_t *specs, size_t count);
