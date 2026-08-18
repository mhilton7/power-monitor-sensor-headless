#include "pm_commands.h"

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "nvs.h"
#include "pm_config.h"
#include "pm_protocol.h"

static const char *const type_names[PM_COMMAND_TYPE_COUNT] = {
    "reboot", "unsupported", "unsupported", "diagnostics_snapshot", "network_self_test",
    "meter_self_test", "unsupported", "unsupported", "unsupported", "unsupported",
    "unsupported", "ota_install", "unsupported", "unsupported", "unsupported",
};

static const char *const state_names[] = {
    "queued", "delivered", "accepted", "running", "succeeded", "failed", "expired", "cancelled",
    "superseded", "awaiting_reboot", "awaiting_heartbeat", "rolled_back",
};

static StaticSemaphore_t s_command_mutex_storage;
static SemaphoreHandle_t s_command_mutex;
static portMUX_TYPE s_command_mutex_init_lock = portMUX_INITIALIZER_UNLOCKED;

esp_err_t pm_commands_lock(void)
{
    if (s_command_mutex == NULL) {
        taskENTER_CRITICAL(&s_command_mutex_init_lock);
        if (s_command_mutex == NULL) {
            s_command_mutex = xSemaphoreCreateRecursiveMutexStatic(&s_command_mutex_storage);
        }
        taskEXIT_CRITICAL(&s_command_mutex_init_lock);
    }
    return s_command_mutex != NULL && xSemaphoreTakeRecursive(s_command_mutex, portMAX_DELAY) == pdTRUE ?
           ESP_OK : ESP_ERR_NO_MEM;
}

void pm_commands_unlock(void)
{
    if (s_command_mutex != NULL) {
        (void)xSemaphoreGiveRecursive(s_command_mutex);
    }
}

static void secure_zero_memory(void *value, size_t length)
{
    volatile uint8_t *bytes = (volatile uint8_t *)value;
    while (length-- > 0U) {
        *bytes++ = 0U;
    }
}

static uint32_t command_crc(const pm_command_t *command)
{
    return pm_crc32_ieee(command, offsetof(pm_command_t, crc32));
}

static uint32_t ledger_crc(const pm_command_ledger_t *ledger)
{
    return pm_crc32_ieee(ledger, offsetof(pm_command_ledger_t, crc32));
}

static bool command_valid(const pm_command_t *command)
{
    if (command->command_id[0] == '\0' || command->type >= PM_COMMAND_TYPE_COUNT ||
        command->state > PM_COMMAND_ROLLED_BACK || command->progress_percent > 100U ||
        (command->result_ack_required && command->state != PM_COMMAND_SUCCEEDED) ||
        command->crc32 != command_crc(command) ||
        memchr(command->payload, '\0', sizeof(command->payload)) == NULL) {
        return false;
    }
    if (command->payload_redacted) {
        for (size_t i = 0U; i < sizeof(command->payload); ++i) {
            if (command->payload[i] != '\0') {
                return false;
            }
        }
        return true;
    }
    uint8_t digest[PM_SHA256_SIZE] = {0};
    pm_sha256((const uint8_t *)command->payload, strlen(command->payload), digest);
    const bool valid = pm_constant_time_equal(digest, command->payload_sha256, sizeof(digest));
    secure_zero_memory(digest, sizeof(digest));
    return valid;
}

static bool command_terminal(pm_command_state_t state)
{
    return state == PM_COMMAND_SUCCEEDED || state == PM_COMMAND_FAILED ||
           state == PM_COMMAND_EXPIRED || state == PM_COMMAND_CANCELLED ||
           state == PM_COMMAND_SUPERSEDED || state == PM_COMMAND_ROLLED_BACK;
}

static bool ledger_valid(const pm_command_ledger_t *ledger)
{
    if (ledger->next >= PM_COMMAND_LEDGER_SIZE || ledger->crc32 != ledger_crc(ledger)) {
        return false;
    }
    for (size_t i = 0U; i < PM_COMMAND_LEDGER_SIZE; ++i) {
        if (ledger->entries[i].command_id[0] != '\0' && !command_valid(&ledger->entries[i])) {
            return false;
        }
    }
    return true;
}

static esp_err_t persist(pm_command_ledger_t *ledger)
{
    if (ledger->generation == UINT32_MAX) {
        return ESP_ERR_INVALID_STATE;
    }
    ledger->generation++;
    for (size_t i = 0U; i < PM_COMMAND_LEDGER_SIZE; ++i) {
        if (ledger->entries[i].command_id[0] != '\0') {
            ledger->entries[i].crc32 = command_crc(&ledger->entries[i]);
        }
    }
    ledger->crc32 = ledger_crc(ledger);
    nvs_handle_t handle = 0;
    esp_err_t error = nvs_open("pm_commands", NVS_READWRITE, &handle);
    if (error == ESP_OK) {
        error = nvs_set_blob(handle, (ledger->generation & 1U) != 0U ? "slot_a" : "slot_b", ledger, sizeof(*ledger));
    }
    if (error == ESP_OK) {
        error = nvs_commit(handle);
    }
    if (handle != 0) {
        nvs_close(handle);
    }
    return error;
}

typedef enum {
    PM_LEDGER_SLOT_MISSING = 0,
    PM_LEDGER_SLOT_INVALID,
    PM_LEDGER_SLOT_VALID,
} pm_ledger_slot_status_t;

typedef struct {
    pm_ledger_slot_status_t status;
    size_t size;
    uint32_t generation;
    uint8_t sha256[PM_SHA256_SIZE];
} pm_ledger_slot_meta_t;

static esp_err_t inspect_slot(nvs_handle_t handle, const char *key, pm_command_ledger_t *ledger,
                              pm_ledger_slot_meta_t *meta)
{
    secure_zero_memory(ledger, sizeof(*ledger));
    secure_zero_memory(meta, sizeof(*meta));
    size_t size = sizeof(*ledger);
    const esp_err_t error = nvs_get_blob(handle, key, ledger, &size);
    if (error == ESP_ERR_NVS_NOT_FOUND) {
        meta->status = PM_LEDGER_SLOT_MISSING;
        return ESP_OK;
    }
    if (error != ESP_OK) {
        return error;
    }
    meta->size = size;
    if (size != sizeof(*ledger)) {
        meta->status = PM_LEDGER_SLOT_INVALID;
        pm_sha256((const uint8_t *)ledger, size < sizeof(*ledger) ? size : sizeof(*ledger), meta->sha256);
        return ESP_OK;
    }
    meta->generation = ledger->generation;
    pm_sha256((const uint8_t *)ledger, sizeof(*ledger), meta->sha256);
    meta->status = ledger_valid(ledger) ? PM_LEDGER_SLOT_VALID : PM_LEDGER_SLOT_INVALID;
    return ESP_OK;
}

pm_command_boot_action_t pm_command_boot_action(const pm_command_t *command)
{
    if (command == NULL || command->type >= PM_COMMAND_TYPE_COUNT) {
        return PM_COMMAND_BOOT_IGNORE;
    }
    if (command->state == PM_COMMAND_ACCEPTED || command->state == PM_COMMAND_RUNNING) {
        if (command->state == PM_COMMAND_RUNNING && command->type == PM_COMMAND_OTA_INSTALL) {
            /* OTA checkpoints are advanced before boot selection. A reset in
             * the narrow BOOT_SELECTED -> AWAITING_REBOOT ledger window must
             * therefore be reconciled from that checkpoint, never replayed. */
            return PM_COMMAND_BOOT_RECONCILE_OTA;
        }
        switch (command->type) {
        case PM_COMMAND_DIAGNOSTICS_SNAPSHOT:
        case PM_COMMAND_NETWORK_SELF_TEST:
        case PM_COMMAND_METER_SELF_TEST:
            return PM_COMMAND_BOOT_REQUEUE;
        default:
            return PM_COMMAND_BOOT_FAIL_INTERRUPTED;
        }
    }
    if (command->state == PM_COMMAND_AWAITING_REBOOT) {
        if (command->type == PM_COMMAND_REBOOT) {
            return PM_COMMAND_BOOT_COMPLETE_REBOOT;
        }
        if (command->type == PM_COMMAND_OTA_INSTALL) {
            return PM_COMMAND_BOOT_RECONCILE_OTA;
        }
        return PM_COMMAND_BOOT_FAIL_INTERRUPTED;
    }
    if (command->state == PM_COMMAND_AWAITING_HEARTBEAT)
        return PM_COMMAND_BOOT_FAIL_INTERRUPTED;
    return PM_COMMAND_BOOT_IGNORE;
}

static bool slot_meta_equal(const pm_ledger_slot_meta_t *left, const pm_ledger_slot_meta_t *right)
{
    return left->status == right->status && left->size == right->size &&
           left->generation == right->generation &&
           pm_constant_time_equal(left->sha256, right->sha256, sizeof(left->sha256));
}

static esp_err_t commands_load_locked(pm_command_ledger_t *ledger)
{
    if (ledger == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    nvs_handle_t handle = 0;
    esp_err_t error = nvs_open("pm_commands", NVS_READWRITE, &handle);
    if (error != ESP_OK) {
        return error;
    }
    pm_ledger_slot_meta_t initial_a = {0};
    pm_ledger_slot_meta_t initial_b = {0};
    error = inspect_slot(handle, "slot_a", ledger, &initial_a);
    if (error == ESP_OK) {
        error = inspect_slot(handle, "slot_b", ledger, &initial_b);
    }
    if (error != ESP_OK) {
        nvs_close(handle);
        secure_zero_memory(ledger, sizeof(*ledger));
        return error;
    }
    if (initial_a.status == PM_LEDGER_SLOT_MISSING && initial_b.status == PM_LEDGER_SLOT_MISSING) {
        nvs_close(handle);
        secure_zero_memory(ledger, sizeof(*ledger));
        return persist(ledger);
    }
    const bool valid_a = initial_a.status == PM_LEDGER_SLOT_VALID;
    const bool valid_b = initial_b.status == PM_LEDGER_SLOT_VALID;
    if (!valid_a && !valid_b) {
        nvs_close(handle);
        secure_zero_memory(ledger, sizeof(*ledger));
        return ESP_ERR_INVALID_CRC;
    }
    if (valid_a && valid_b && initial_a.generation == initial_b.generation &&
        !pm_constant_time_equal(initial_a.sha256, initial_b.sha256, sizeof(initial_a.sha256))) {
        nvs_close(handle);
        secure_zero_memory(ledger, sizeof(*ledger));
        return ESP_ERR_INVALID_STATE;
    }
    const bool select_a = valid_a && (!valid_b || initial_a.generation >= initial_b.generation);
    const char *selected_key = select_a ? "slot_a" : "slot_b";
    const pm_ledger_slot_meta_t *selected_initial = select_a ? &initial_a : &initial_b;
    pm_ledger_slot_meta_t final_a = {0};
    pm_ledger_slot_meta_t final_b = {0};
    pm_ledger_slot_meta_t selected_final = {0};
    error = inspect_slot(handle, "slot_a", ledger, &final_a);
    if (error == ESP_OK) {
        error = inspect_slot(handle, "slot_b", ledger, &final_b);
    }
    if (error == ESP_OK && slot_meta_equal(&initial_a, &final_a) && slot_meta_equal(&initial_b, &final_b)) {
        error = inspect_slot(handle, selected_key, ledger, &selected_final);
    } else if (error == ESP_OK) {
        error = ESP_ERR_INVALID_STATE;
    }
    nvs_close(handle);
    if (error != ESP_OK || selected_final.status != PM_LEDGER_SLOT_VALID ||
        !slot_meta_equal(selected_initial, &selected_final)) {
        secure_zero_memory(ledger, sizeof(*ledger));
        return error == ESP_OK ? ESP_ERR_INVALID_STATE : error;
    }
    secure_zero_memory(&initial_a, sizeof(initial_a));
    secure_zero_memory(&initial_b, sizeof(initial_b));
    secure_zero_memory(&final_a, sizeof(final_a));
    secure_zero_memory(&final_b, sizeof(final_b));
    secure_zero_memory(&selected_final, sizeof(selected_final));
    return ESP_OK;
}

static esp_err_t command_accept_locked(pm_command_ledger_t *ledger, const pm_command_t *incoming,
                                       int64_t now_utc_ms, pm_command_t **stored, bool *duplicate)
{
    if (ledger == NULL || incoming == NULL || stored == NULL || duplicate == NULL ||
        incoming->command_id[0] == '\0' || incoming->idempotency_key[0] == '\0' ||
        incoming->type >= PM_COMMAND_TYPE_COUNT ||
        memchr(incoming->payload, '\0', sizeof(incoming->payload)) == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    for (size_t i = 0U; i < PM_COMMAND_LEDGER_SIZE; ++i) {
        if (strcmp(ledger->entries[i].command_id, incoming->command_id) == 0 ||
            strcmp(ledger->entries[i].idempotency_key, incoming->idempotency_key) == 0) {
            uint8_t incoming_digest[PM_SHA256_SIZE] = {0};
            pm_sha256((const uint8_t *)incoming->payload, strlen(incoming->payload), incoming_digest);
            const bool matches = ledger->entries[i].type == incoming->type &&
                                 pm_constant_time_equal(ledger->entries[i].payload_sha256,
                                                        incoming_digest, sizeof(incoming_digest));
            secure_zero_memory(incoming_digest, sizeof(incoming_digest));
            if (!matches) {
                return ESP_ERR_INVALID_CRC;
            }
            *stored = &ledger->entries[i];
            *duplicate = true;
            return ESP_OK;
        }
    }
    pm_command_t candidate = *incoming;
    pm_sha256((const uint8_t *)candidate.payload, strlen(candidate.payload), candidate.payload_sha256);
    candidate.payload_redacted = false;
    candidate.state = now_utc_ms > candidate.expires_utc_ms ? PM_COMMAND_EXPIRED : PM_COMMAND_ACCEPTED;
    candidate.progress_percent = 0U;
    candidate.crc32 = command_crc(&candidate);
    size_t selected = PM_COMMAND_LEDGER_SIZE;
    for (size_t offset = 0U; offset < PM_COMMAND_LEDGER_SIZE; ++offset) {
        const size_t index = (ledger->next + offset) % PM_COMMAND_LEDGER_SIZE;
        if (ledger->entries[index].command_id[0] == '\0' ||
            (command_terminal(ledger->entries[index].state) &&
             !ledger->entries[index].result_ack_required)) {
            selected = index;
            break;
        }
    }
    if (selected == PM_COMMAND_LEDGER_SIZE) {
        /* Never discard an accepted/running/reboot-pending command merely to
         * make room for a later command. The server can retry after one of the
         * bounded entries reaches a terminal, authenticated result. */
        secure_zero_memory(&candidate, sizeof(candidate));
        return ESP_ERR_NO_MEM;
    }
    pm_command_t *previous = malloc(sizeof(*previous));
    if (previous == NULL) {
        secure_zero_memory(&candidate, sizeof(candidate));
        return ESP_ERR_NO_MEM;
    }
    *previous = ledger->entries[selected];
    const uint8_t previous_next = ledger->next;
    const uint32_t previous_generation = ledger->generation;
    const uint32_t previous_crc = ledger->crc32;
    ledger->entries[selected] = candidate;
    pm_command_t *entry = &ledger->entries[selected];
    ledger->next = (uint8_t)((selected + 1U) % PM_COMMAND_LEDGER_SIZE);
    const esp_err_t error = persist(ledger);
    if (error != ESP_OK) {
        ledger->entries[selected] = *previous;
        ledger->next = previous_next;
        ledger->generation = previous_generation;
        ledger->crc32 = previous_crc;
        secure_zero_memory(previous, sizeof(*previous));
        free(previous);
        secure_zero_memory(&candidate, sizeof(candidate));
        return error;
    }
    *stored = entry;
    *duplicate = false;
    const bool expired = candidate.state == PM_COMMAND_EXPIRED;
    secure_zero_memory(previous, sizeof(*previous));
    free(previous);
    secure_zero_memory(&candidate, sizeof(candidate));
    return expired ? ESP_ERR_TIMEOUT : ESP_OK;
}

static esp_err_t command_transition_locked(pm_command_ledger_t *ledger, pm_command_t *command,
                                           pm_command_state_t state, uint8_t progress_percent,
                                           int32_t result_code)
{
    if (ledger == NULL || command == NULL || state > PM_COMMAND_ROLLED_BACK || progress_percent > 100U ||
        progress_percent < command->progress_percent) {
        return ESP_ERR_INVALID_ARG;
    }
    const bool terminal = command->state == PM_COMMAND_SUCCEEDED || command->state == PM_COMMAND_FAILED ||
                          command->state == PM_COMMAND_EXPIRED || command->state == PM_COMMAND_CANCELLED ||
                          command->state == PM_COMMAND_ROLLED_BACK;
    if (terminal && state != command->state) {
        return ESP_ERR_INVALID_STATE;
    }
    pm_command_t *previous = (pm_command_t *)malloc(sizeof(*previous));
    if (previous == NULL) {
        return ESP_ERR_NO_MEM;
    }
    *previous = *command;
    const uint32_t previous_generation = ledger->generation;
    const uint32_t previous_ledger_crc = ledger->crc32;
    command->state = state;
    command->progress_percent = progress_percent;
    command->result_code = result_code;
    const esp_err_t error = persist(ledger);
    if (error != ESP_OK) {
        *command = *previous;
        ledger->generation = previous_generation;
        ledger->crc32 = previous_ledger_crc;
    }
    secure_zero_memory(previous, sizeof(*previous));
    free(previous);
    return error;
}

static esp_err_t command_acknowledge_result_locked(pm_command_ledger_t *ledger, const char *command_id)
{
    if (ledger == NULL || command_id == NULL || strlen(command_id) != PM_COMMAND_ID_MAX) {
        return ESP_ERR_INVALID_ARG;
    }
    for (size_t i = 0U; i < PM_COMMAND_LEDGER_SIZE; ++i) {
        pm_command_t *command = &ledger->entries[i];
        if (strcmp(command->command_id, command_id) != 0) {
            continue;
        }
        if (command->state != PM_COMMAND_SUCCEEDED) {
            return ESP_ERR_INVALID_STATE;
        }
        if (!command->result_ack_required) {
            return ESP_OK;
        }
        const uint32_t previous_command_crc = command->crc32;
        const uint32_t previous_generation = ledger->generation;
        const uint32_t previous_ledger_crc = ledger->crc32;
        command->result_ack_required = false;
        const esp_err_t error = persist(ledger);
        if (error != ESP_OK) {
            command->result_ack_required = true;
            command->crc32 = previous_command_crc;
            ledger->generation = previous_generation;
            ledger->crc32 = previous_ledger_crc;
        }
        return error;
    }
    return ESP_ERR_NOT_FOUND;
}

static esp_err_t command_zeroize_payload_locked(pm_command_ledger_t *ledger, pm_command_t *command)
{
    if (ledger == NULL || command == NULL || command->command_id[0] == '\0') {
        return ESP_ERR_INVALID_ARG;
    }
    if (command->payload_redacted) {
        return persist(ledger);
    }
    secure_zero_memory(command->payload, sizeof(command->payload));
    command->payload_redacted = true;
    /* Never restore plaintext after a durability failure. The in-memory
     * ledger remains redacted and the caller must retry until a later A/B
     * generation durably records that redaction. */
    return persist(ledger);
}

static esp_err_t command_reconcile_boot_locked(pm_command_ledger_t *ledger, pm_command_t *command,
                                               pm_command_state_t state, int32_t result_code,
                                               const char *result_text)
{
    if (ledger == NULL || command == NULL || result_text == NULL ||
        strlen(result_text) > PM_COMMAND_RESULT_MAX ||
        (state != PM_COMMAND_SUCCEEDED && state != PM_COMMAND_FAILED &&
         state != PM_COMMAND_ROLLED_BACK) || command_terminal(command->state)) {
        return ESP_ERR_INVALID_ARG;
    }
    pm_command_t *previous = (pm_command_t *)malloc(sizeof(*previous));
    if (previous == NULL) {
        return ESP_ERR_NO_MEM;
    }
    *previous = *command;
    const uint32_t previous_generation = ledger->generation;
    const uint32_t previous_ledger_crc = ledger->crc32;
    command->state = state;
    command->progress_percent = state == PM_COMMAND_SUCCEEDED ? 100U : command->progress_percent;
    command->result_code = result_code;
    (void)snprintf(command->result_text, sizeof(command->result_text), "%s", result_text);
    command->evidence_json[0] = '\0';
    const esp_err_t error = persist(ledger);
    if (error != ESP_OK) {
        *command = *previous;
        ledger->generation = previous_generation;
        ledger->crc32 = previous_ledger_crc;
    }
    secure_zero_memory(previous, sizeof(*previous));
    free(previous);
    return error;
}

esp_err_t pm_commands_load(pm_command_ledger_t *ledger)
{
    const esp_err_t lock_error = pm_commands_lock();
    if (lock_error != ESP_OK) {
        return lock_error;
    }
    const esp_err_t error = commands_load_locked(ledger);
    pm_commands_unlock();
    return error;
}

esp_err_t pm_command_accept(pm_command_ledger_t *ledger, const pm_command_t *incoming, int64_t now_utc_ms,
                            pm_command_t **stored, bool *duplicate)
{
    const esp_err_t lock_error = pm_commands_lock();
    if (lock_error != ESP_OK) {
        return lock_error;
    }
    const esp_err_t error = command_accept_locked(ledger, incoming, now_utc_ms, stored, duplicate);
    pm_commands_unlock();
    return error;
}

esp_err_t pm_command_transition(pm_command_ledger_t *ledger, pm_command_t *command, pm_command_state_t state,
                                uint8_t progress_percent, int32_t result_code)
{
    const esp_err_t lock_error = pm_commands_lock();
    if (lock_error != ESP_OK) {
        return lock_error;
    }
    const esp_err_t error = command_transition_locked(ledger, command, state, progress_percent, result_code);
    pm_commands_unlock();
    return error;
}

esp_err_t pm_command_acknowledge_result(pm_command_ledger_t *ledger, const char *command_id)
{
    const esp_err_t lock_error = pm_commands_lock();
    if (lock_error != ESP_OK) {
        return lock_error;
    }
    const esp_err_t error = command_acknowledge_result_locked(ledger, command_id);
    pm_commands_unlock();
    return error;
}

esp_err_t pm_command_zeroize_payload(pm_command_ledger_t *ledger, pm_command_t *command)
{
    const esp_err_t lock_error = pm_commands_lock();
    if (lock_error != ESP_OK) {
        return lock_error;
    }
    const esp_err_t error = command_zeroize_payload_locked(ledger, command);
    pm_commands_unlock();
    return error;
}

esp_err_t pm_command_reconcile_boot(pm_command_ledger_t *ledger, pm_command_t *command,
                                    pm_command_state_t state, int32_t result_code,
                                    const char *result_text)
{
    const esp_err_t lock_error = pm_commands_lock();
    if (lock_error != ESP_OK) {
        return lock_error;
    }
    const esp_err_t error = command_reconcile_boot_locked(ledger, command, state,
                                                          result_code, result_text);
    pm_commands_unlock();
    return error;
}

const char *pm_command_type_name(pm_command_type_t type)
{
    return type < PM_COMMAND_TYPE_COUNT ? type_names[type] : "invalid";
}

const char *pm_command_state_name(pm_command_state_t state)
{
    return state <= PM_COMMAND_ROLLED_BACK ? state_names[state] : "invalid";
}

bool pm_command_type_from_name(const char *name, pm_command_type_t *type)
{
    if (name == NULL || type == NULL) {
        return false;
    }
    static const struct { const char *name; pm_command_type_t type; } supported[] = {
        {"reboot", PM_COMMAND_REBOOT},
        {"diagnostics_snapshot", PM_COMMAND_DIAGNOSTICS_SNAPSHOT},
        {"network_self_test", PM_COMMAND_NETWORK_SELF_TEST},
        {"meter_self_test", PM_COMMAND_METER_SELF_TEST},
        {"ota_install", PM_COMMAND_OTA_INSTALL},
    };
    for (size_t i = 0U; i < sizeof(supported) / sizeof(supported[0]); ++i) {
        if (strcmp(name, supported[i].name) == 0) {
            *type = supported[i].type;
            return true;
        }
    }
    return false;
}
