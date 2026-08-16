#include "pm_storage.h"

#include <stddef.h>
#include <string.h>

#include "nvs.h"
#include "pm_config.h"

#define PM_SEQUENCE_NAMESPACE "pm_sequence"

typedef struct {
    pm_sequence_state_t state;
    uint32_t crc32;
} sequence_slot_t;

static uint32_t slot_crc(const sequence_slot_t *slot)
{
    return pm_crc32_ieee(slot, offsetof(sequence_slot_t, crc32));
}

static bool slot_valid(const sequence_slot_t *slot)
{
    return slot->state.next_sequence > 0U && slot->state.reserved_through >= slot->state.next_sequence - 1U &&
           slot->state.maximum_seen < slot->state.next_sequence && slot->state.acknowledged <= slot->state.maximum_seen &&
           slot->crc32 == slot_crc(slot);
}

static esp_err_t read_slot(nvs_handle_t handle, const char *key, sequence_slot_t *slot)
{
    size_t length = sizeof(*slot);
    const esp_err_t error = nvs_get_blob(handle, key, slot, &length);
    return error == ESP_OK && length == sizeof(*slot) && slot_valid(slot) ? ESP_OK :
           (error == ESP_OK ? ESP_ERR_INVALID_CRC : error);
}

static esp_err_t persist(pm_sequence_state_t *state)
{
    if (state == NULL || state->generation == UINT32_MAX) {
        return ESP_ERR_INVALID_STATE;
    }
    nvs_handle_t handle = 0;
    esp_err_t error = nvs_open(PM_SEQUENCE_NAMESPACE, NVS_READWRITE, &handle);
    if (error != ESP_OK) {
        return error;
    }
    uint8_t active = (uint8_t)'A';
    const esp_err_t selector_error = nvs_get_u8(handle, "active", &active);
    if (selector_error != ESP_OK &&
        !(selector_error == ESP_ERR_NVS_NOT_FOUND && state->generation == 0U)) {
        nvs_close(handle);
        return selector_error;
    }
    if (selector_error == ESP_OK && active != (uint8_t)'A' && active != (uint8_t)'B') {
        nvs_close(handle);
        return ESP_ERR_INVALID_STATE;
    }
    const uint8_t inactive = active == (uint8_t)'A' ? (uint8_t)'B' : (uint8_t)'A';
    const char *key = inactive == (uint8_t)'A' ? "slot_a" : "slot_b";
    sequence_slot_t slot = {.state = *state};
    slot.state.generation++;
    slot.crc32 = slot_crc(&slot);
    error = nvs_set_blob(handle, key, &slot, sizeof(slot));
    if (error == ESP_OK) {
        error = nvs_commit(handle);
    }
    sequence_slot_t verified = {0};
    if (error == ESP_OK) {
        error = read_slot(handle, key, &verified);
    }
    if (error == ESP_OK && memcmp(&verified, &slot, sizeof(slot)) == 0) {
        error = nvs_set_u8(handle, "active", inactive);
        if (error == ESP_OK) {
            error = nvs_commit(handle);
        }
    } else if (error == ESP_OK) {
        error = ESP_FAIL;
    }
    nvs_close(handle);
    if (error == ESP_OK) {
        *state = slot.state;
    }
    return error;
}

esp_err_t pm_sequence_load(pm_sequence_state_t *state)
{
    if (state == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    nvs_handle_t handle = 0;
    esp_err_t error = nvs_open(PM_SEQUENCE_NAMESPACE, NVS_READWRITE, &handle);
    if (error != ESP_OK) {
        return error;
    }
    sequence_slot_t a = {0};
    sequence_slot_t b = {0};
    const esp_err_t error_a = read_slot(handle, "slot_a", &a);
    const esp_err_t error_b = read_slot(handle, "slot_b", &b);
    const bool valid_a = error_a == ESP_OK;
    const bool valid_b = error_b == ESP_OK;
    nvs_close(handle);
    if (!valid_a && !valid_b) {
        if (error_a != ESP_ERR_NVS_NOT_FOUND || error_b != ESP_ERR_NVS_NOT_FOUND) {
            return error_a != ESP_ERR_NVS_NOT_FOUND ? error_a : error_b;
        }
        *state = (pm_sequence_state_t){.next_sequence = 1U, .reserved_through = 0U};
        return persist(state);
    }
    if ((!valid_a && error_a != ESP_ERR_NVS_NOT_FOUND) ||
        (!valid_b && error_b != ESP_ERR_NVS_NOT_FOUND)) {
        return !valid_a && error_a != ESP_ERR_NVS_NOT_FOUND ? error_a : error_b;
    }
    if (valid_a && valid_b && a.state.generation == b.state.generation &&
        memcmp(&a.state, &b.state, sizeof(a.state)) != 0) {
        return ESP_ERR_INVALID_STATE;
    }
    *state = valid_a && (!valid_b || a.state.generation >= b.state.generation) ? a.state : b.state;
    /* Never reuse an allocated-but-not-observed reservation after reboot. */
    if (state->next_sequence <= state->reserved_through) {
        if (state->reserved_through == UINT64_MAX) {
            return ESP_ERR_INVALID_STATE;
        }
        state->next_sequence = state->reserved_through + 1U;
    }
    return ESP_OK;
}

esp_err_t pm_sequence_next(pm_sequence_state_t *state, uint64_t *sequence)
{
    if (state == NULL || sequence == NULL || state->next_sequence == UINT64_MAX) {
        return ESP_ERR_INVALID_ARG;
    }
    if (state->next_sequence > state->reserved_through) {
        if (UINT64_MAX - state->next_sequence < PM_SEQUENCE_RESERVATION_BLOCK - 1U) {
            return ESP_ERR_INVALID_SIZE;
        }
        pm_sequence_state_t candidate = *state;
        candidate.reserved_through = candidate.next_sequence + PM_SEQUENCE_RESERVATION_BLOCK - 1U;
        const esp_err_t error = persist(&candidate);
        if (error != ESP_OK) {
            return error;
        }
        *state = candidate;
    }
    pm_sequence_state_t allocated = *state;
    *sequence = allocated.next_sequence++;
    allocated.maximum_seen = *sequence;
    /* Persist allocation before the caller can emit the record. A failed append
     * becomes an explicit unavailable sequence, never a reused identity. */
    const esp_err_t allocation_error = persist(&allocated);
    if (allocation_error == ESP_OK) {
        *state = allocated;
    }
    return allocation_error;
}

esp_err_t pm_sequence_acknowledge(pm_sequence_state_t *state, uint64_t acknowledged)
{
    if (state == NULL || acknowledged < state->acknowledged || acknowledged > state->maximum_seen) {
        return ESP_ERR_INVALID_ARG;
    }
    if (acknowledged == state->acknowledged) {
        return ESP_OK;
    }
    pm_sequence_state_t candidate = *state;
    candidate.acknowledged = acknowledged;
    const esp_err_t error = persist(&candidate);
    if (error == ESP_OK) {
        *state = candidate;
    }
    return error;
}

esp_err_t pm_sequence_raise_floor(pm_sequence_state_t *state, uint64_t floor, uint32_t reset_generation)
{
    if (state == NULL || floor == UINT64_MAX) {
        return ESP_ERR_INVALID_ARG;
    }
    if (reset_generation == state->reset_generation) {
        return state->maximum_seen == floor && state->next_sequence == floor + 1U &&
                       state->reserved_through == floor && state->acknowledged == floor
                   ? ESP_OK
                   : ESP_ERR_INVALID_STATE;
    }
    if (floor < state->maximum_seen || reset_generation < state->reset_generation) {
        return ESP_ERR_INVALID_ARG;
    }
    pm_sequence_state_t candidate = *state;
    candidate.maximum_seen = floor;
    candidate.next_sequence = floor + 1U;
    candidate.reserved_through = floor;
    candidate.acknowledged = floor;
    candidate.reset_generation = reset_generation;
    const esp_err_t error = persist(&candidate);
    if (error == ESP_OK) {
        *state = candidate;
    }
    return error;
}
