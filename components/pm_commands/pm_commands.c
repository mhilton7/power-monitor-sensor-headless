#include "pm_commands.h"

#include <stddef.h>
#include <string.h>

#include "nvs.h"
#include "pm_config.h"
#include "pm_protocol.h"

static const char *const type_names[PM_COMMAND_TYPE_COUNT] = {
    "reboot", "maintenance_sleep", "sync_now", "diagnostics_snapshot", "network_self_test",
    "meter_self_test", "storage_self_test", "format_storage_prepare", "format_storage_commit",
    "apply_configuration", "rotate_device_credentials", "ota_install", "data_reset_prepare",
    "data_reset_commit", "data_reset_cancel",
};

static const char *const state_names[] = {
    "queued", "delivered", "accepted", "running", "succeeded", "failed", "expired", "cancelled",
    "superseded", "awaiting_reboot", "awaiting_heartbeat", "rolled_back",
};

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
    memset(digest, 0, sizeof(digest));
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

static bool load_slot(nvs_handle_t handle, const char *key, pm_command_ledger_t *ledger)
{
    size_t size = sizeof(*ledger);
    return nvs_get_blob(handle, key, ledger, &size) == ESP_OK && size == sizeof(*ledger) && ledger_valid(ledger);
}

esp_err_t pm_commands_load(pm_command_ledger_t *ledger)
{
    if (ledger == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    nvs_handle_t handle = 0;
    esp_err_t error = nvs_open("pm_commands", NVS_READWRITE, &handle);
    if (error != ESP_OK) {
        return error;
    }
    pm_command_ledger_t a = {0};
    pm_command_ledger_t b = {0};
    const bool valid_a = load_slot(handle, "slot_a", &a);
    const bool valid_b = load_slot(handle, "slot_b", &b);
    nvs_close(handle);
    if (!valid_a && !valid_b) {
        memset(ledger, 0, sizeof(*ledger));
        return persist(ledger);
    }
    *ledger = valid_a && (!valid_b || a.generation >= b.generation) ? a : b;
    return ESP_OK;
}

esp_err_t pm_command_accept(pm_command_ledger_t *ledger, const pm_command_t *incoming, int64_t now_utc_ms,
                            pm_command_t **stored, bool *duplicate)
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
            memset(incoming_digest, 0, sizeof(incoming_digest));
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
        return ESP_ERR_NO_MEM;
    }
    ledger->entries[selected] = candidate;
    pm_command_t *entry = &ledger->entries[selected];
    ledger->next = (uint8_t)((selected + 1U) % PM_COMMAND_LEDGER_SIZE);
    const esp_err_t error = persist(ledger);
    if (error != ESP_OK) {
        return error;
    }
    *stored = entry;
    *duplicate = false;
    return candidate.state == PM_COMMAND_EXPIRED ? ESP_ERR_TIMEOUT : ESP_OK;
}

esp_err_t pm_command_transition(pm_command_ledger_t *ledger, pm_command_t *command, pm_command_state_t state,
                                uint8_t progress_percent, int32_t result_code)
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
    command->state = state;
    command->progress_percent = progress_percent;
    command->result_code = result_code;
    return persist(ledger);
}

esp_err_t pm_command_acknowledge_result(pm_command_ledger_t *ledger, const char *command_id)
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
        command->result_ack_required = false;
        return persist(ledger);
    }
    return ESP_ERR_NOT_FOUND;
}

esp_err_t pm_command_zeroize_payload(pm_command_ledger_t *ledger, pm_command_t *command)
{
    if (ledger == NULL || command == NULL || command->command_id[0] == '\0') {
        return ESP_ERR_INVALID_ARG;
    }
    if (command->payload_redacted) {
        return persist(ledger);
    }
    memset(command->payload, 0, sizeof(command->payload));
    command->payload_redacted = true;
    return persist(ledger);
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
    for (size_t i = 0U; i < PM_COMMAND_TYPE_COUNT; ++i) {
        if (strcmp(name, type_names[i]) == 0) {
            *type = (pm_command_type_t)i;
            return true;
        }
    }
    return false;
}
