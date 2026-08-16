#pragma once

#include <stdint.h>

typedef int BaseType_t;
typedef unsigned int UBaseType_t;
typedef uint32_t TickType_t;
typedef struct {
    uintptr_t unused;
} StaticSemaphore_t;
typedef void *SemaphoreHandle_t;
typedef int portMUX_TYPE;

#define pdTRUE 1
#define pdPASS 1
#define pdFAIL 0
#define portMAX_DELAY UINT32_MAX
#define pdMS_TO_TICKS(milliseconds) ((TickType_t)(milliseconds))
#define portMUX_INITIALIZER_UNLOCKED 0
#define taskENTER_CRITICAL(lock) ((void)(lock))
#define taskEXIT_CRITICAL(lock) ((void)(lock))
