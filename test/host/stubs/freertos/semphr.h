#pragma once

#include "freertos/FreeRTOS.h"

extern unsigned int s_test_mutex_depth;
extern unsigned int s_test_mutex_max_depth;

static inline SemaphoreHandle_t xSemaphoreCreateRecursiveMutexStatic(StaticSemaphore_t *storage)
{
    return (SemaphoreHandle_t)storage;
}

static inline BaseType_t xSemaphoreTakeRecursive(SemaphoreHandle_t semaphore, uint32_t timeout)
{
    (void)semaphore;
    (void)timeout;
    s_test_mutex_depth++;
    if (s_test_mutex_depth > s_test_mutex_max_depth) {
        s_test_mutex_max_depth = s_test_mutex_depth;
    }
    return pdTRUE;
}

static inline BaseType_t xSemaphoreGiveRecursive(SemaphoreHandle_t semaphore)
{
    (void)semaphore;
    if (s_test_mutex_depth > 0U) {
        s_test_mutex_depth--;
    }
    return pdTRUE;
}
