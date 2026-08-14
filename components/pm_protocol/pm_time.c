#include "pm_protocol.h"

#include <stddef.h>

#include "nvs.h"

typedef struct {
    int64_t utc_ms;
    uint32_t generation;
    uint32_t crc32;
} time_checkpoint_t;

static uint32_t crc32_ieee(const void *data, size_t length)
{
    const uint8_t *bytes = (const uint8_t *)data;
    uint32_t crc = UINT32_C(0xFFFFFFFF);
    for (size_t i = 0U; i < length; ++i) {
        crc ^= bytes[i];
        for (uint8_t bit = 0U; bit < 8U; ++bit) {
            const uint32_t mask = (uint32_t)-(int32_t)(crc & 1U);
            crc = (crc >> 1U) ^ (UINT32_C(0xEDB88320) & mask);
        }
    }
    return ~crc;
}

static bool valid(const time_checkpoint_t *checkpoint)
{
    /* 2024-01-01 through 2100-01-01 bounds reject erased/fabricated values. */
    return checkpoint->utc_ms >= INT64_C(1704067200000) && checkpoint->utc_ms < INT64_C(4102444800000) &&
           checkpoint->crc32 == crc32_ieee(checkpoint, offsetof(time_checkpoint_t, crc32));
}

static esp_err_t persist(int64_t utc_ms)
{
    nvs_handle_t handle = 0;
    esp_err_t error = nvs_open("pm_time", NVS_READWRITE, &handle);
    if (error != ESP_OK) {
        return error;
    }
    time_checkpoint_t a = {0};
    time_checkpoint_t b = {0};
    size_t length = sizeof(a);
    (void)nvs_get_blob(handle, "slot_a", &a, &length);
    length = sizeof(b);
    (void)nvs_get_blob(handle, "slot_b", &b, &length);
    const uint32_t generation = (valid(&a) && valid(&b) ? (a.generation > b.generation ? a.generation : b.generation)
                                                        : (valid(&a) ? a.generation : (valid(&b) ? b.generation : 0U))) + 1U;
    const char *key = (generation & 1U) != 0U ? "slot_a" : "slot_b";
    time_checkpoint_t checkpoint = {.utc_ms = utc_ms, .generation = generation};
    checkpoint.crc32 = crc32_ieee(&checkpoint, offsetof(time_checkpoint_t, crc32));
    error = nvs_set_blob(handle, key, &checkpoint, sizeof(checkpoint));
    if (error == ESP_OK) {
        error = nvs_commit(handle);
    }
    nvs_close(handle);
    return error;
}

void pm_time_init(pm_time_state_t *state, int64_t monotonic_us)
{
    if (state != NULL) {
        *state = (pm_time_state_t){
            .source = PM_TIME_UNTRUSTED,
            .monotonic_checkpoint_us = monotonic_us,
            .maximum_backward_step_ms = 300000,
        };
    }
}

esp_err_t pm_time_load_checkpoint(pm_time_state_t *state, int64_t monotonic_us)
{
    if (state == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    nvs_handle_t handle = 0;
    esp_err_t error = nvs_open("pm_time", NVS_READONLY, &handle);
    if (error != ESP_OK) {
        return error;
    }
    time_checkpoint_t a = {0};
    time_checkpoint_t b = {0};
    size_t length = sizeof(a);
    const bool valid_a = nvs_get_blob(handle, "slot_a", &a, &length) == ESP_OK && length == sizeof(a) && valid(&a);
    length = sizeof(b);
    const bool valid_b = nvs_get_blob(handle, "slot_b", &b, &length) == ESP_OK && length == sizeof(b) && valid(&b);
    nvs_close(handle);
    if (!valid_a && !valid_b) {
        return ESP_ERR_NOT_FOUND;
    }
    const time_checkpoint_t *selected = valid_a && (!valid_b || a.generation >= b.generation) ? &a : &b;
    state->source = PM_TIME_PERSISTED_CHECKPOINT;
    state->utc_checkpoint_ms = selected->utc_ms;
    state->last_returned_utc_ms = selected->utc_ms;
    state->monotonic_checkpoint_us = monotonic_us;
    state->trusted = true;
    return ESP_OK;
}

esp_err_t pm_time_observe(pm_time_state_t *state, pm_time_source_t source, int64_t utc_ms, int64_t monotonic_us)
{
    if (state == NULL || source < PM_TIME_SNTP || source > PM_TIME_SERVER_CORROBORATED ||
        utc_ms < INT64_C(1704067200000) || utc_ms >= INT64_C(4102444800000)) {
        return ESP_ERR_INVALID_ARG;
    }
    int64_t projected = 0;
    if (state->trusted) {
        projected = state->utc_checkpoint_ms + (monotonic_us - state->monotonic_checkpoint_us) / 1000;
        if (utc_ms + state->maximum_backward_step_ms < projected) {
            return ESP_ERR_INVALID_STATE;
        }
    }
    state->source = source;
    state->utc_checkpoint_ms = utc_ms;
    state->monotonic_checkpoint_us = monotonic_us;
    state->last_returned_utc_ms = utc_ms > state->last_returned_utc_ms ? utc_ms : state->last_returned_utc_ms;
    state->trusted = true;
    return persist(state->last_returned_utc_ms);
}

bool pm_time_now(pm_time_state_t *state, int64_t monotonic_us, int64_t *utc_ms)
{
    if (state == NULL || utc_ms == NULL || !state->trusted || monotonic_us < state->monotonic_checkpoint_us) {
        return false;
    }
    int64_t projected = state->utc_checkpoint_ms + (monotonic_us - state->monotonic_checkpoint_us) / 1000;
    if (projected < state->last_returned_utc_ms) {
        projected = state->last_returned_utc_ms;
    }
    state->last_returned_utc_ms = projected;
    *utc_ms = projected;
    return true;
}

