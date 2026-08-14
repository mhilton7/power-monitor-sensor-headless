#include "pm_diagnostics.h"

#include <ctype.h>
#include <stdio.h>
#include <string.h>

#include "esp_heap_caps.h"
#include "esp_system.h"

void pm_diagnostics_capture(pm_diagnostics_snapshot_t *snapshot)
{
    if (snapshot == NULL) {
        return;
    }
    const size_t task_count = snapshot->task_count;
    const uint32_t tls_high_water = snapshot->tls_request_high_water_bytes;
    snapshot->free_internal_heap = (uint32_t)heap_caps_get_free_size(MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
    snapshot->minimum_free_internal_heap =
        (uint32_t)heap_caps_get_minimum_free_size(MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
    snapshot->largest_internal_block =
        (uint32_t)heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
    snapshot->free_psram = (uint32_t)heap_caps_get_free_size(MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    snapshot->reboot_reason = (uint32_t)esp_reset_reason();
    snapshot->task_count = task_count;
    snapshot->tls_request_high_water_bytes = tls_high_water;
}

bool pm_diagnostics_add_task(pm_diagnostics_snapshot_t *snapshot, const char *name, uint32_t high_water_bytes,
                             uint32_t configured_bytes, bool watchdog_registered)
{
    if (snapshot == NULL || name == NULL || snapshot->task_count >= PM_DIAGNOSTIC_TASKS_MAX ||
        strlen(name) > PM_DIAGNOSTIC_TASK_NAME_MAX || high_water_bytes > configured_bytes) {
        return false;
    }
    pm_task_diagnostic_t *task = &snapshot->tasks[snapshot->task_count++];
    memset(task, 0, sizeof(*task));
    (void)snprintf(task->name, sizeof(task->name), "%s", name);
    task->stack_high_water_bytes = high_water_bytes;
    task->configured_stack_bytes = configured_bytes;
    task->watchdog_registered = watchdog_registered;
    return true;
}

static bool case_prefix(const char *text, const char *key)
{
    for (size_t i = 0U; key[i] != '\0'; ++i) {
        if (text[i] == '\0' || (char)tolower((unsigned char)text[i]) != key[i]) {
            return false;
        }
    }
    return true;
}

size_t pm_diagnostics_redact(const char *input, char *output, size_t output_size)
{
    if (input == NULL || output == NULL || output_size == 0U) {
        return 0U;
    }
    size_t in = 0U;
    size_t out = 0U;
    static const char *const keys[] = {
        "password", "secret", "token", "authorization", "cookie", "private_key", "hmac_key",
    };
    while (input[in] != '\0' && out + 1U < output_size) {
        const char *matched = NULL;
        for (size_t k = 0U; k < sizeof(keys) / sizeof(keys[0]); ++k) {
            const size_t length = strlen(keys[k]);
            const bool left_boundary = in == 0U || (!isalnum((unsigned char)input[in - 1U]) && input[in - 1U] != '_');
            if (left_boundary && case_prefix(&input[in], keys[k])) {
                const bool right_boundary = !isalnum((unsigned char)input[in + length]) && input[in + length] != '_';
                if (right_boundary) {
                    matched = keys[k];
                    break;
                }
            }
        }
        if (matched != NULL) {
            const size_t key_length = strlen(matched);
            for (size_t k = 0U; k < key_length && out + 1U < output_size; ++k) {
                output[out++] = input[in++];
            }
            while (input[in] == ' ' || input[in] == '\t' || input[in] == ':' || input[in] == '=') {
                if (out + 1U < output_size) {
                    output[out++] = input[in];
                }
                in++;
            }
            const char quote = input[in] == '"' || input[in] == '\'' ? input[in++] : '\0';
            if (quote != '\0' && out + 1U < output_size) {
                output[out++] = quote;
            }
            static const char redacted[] = "[REDACTED]";
            for (size_t k = 0U; k < sizeof(redacted) - 1U && out + 1U < output_size; ++k) {
                output[out++] = redacted[k];
            }
            while (input[in] != '\0' && ((quote != '\0' && input[in] != quote) ||
                                          (quote == '\0' && input[in] != ',' && input[in] != '}' &&
                                           input[in] != '\r' && input[in] != '\n' && !isspace((unsigned char)input[in])))) {
                in++;
            }
            if (quote != '\0' && input[in] == quote) {
                if (out + 1U < output_size) {
                    output[out++] = input[in];
                }
                in++;
            }
            continue;
        }
        output[out++] = input[in++];
    }
    output[out] = '\0';
    return out;
}
