#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "cJSON.h"
#include "driver/gpio.h"
#include "esp_log.h"
#include "esp_random.h"
#include "esp_sleep.h"
#include "esp_system.h"
#include "esp_task_wdt.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/task.h"
#include "nvs.h"
#include "nvs_flash.h"
#include "pm_board.h"
#include "pm_commands.h"
#include "pm_config.h"
#include "pm_diagnostics.h"
#include "pm_measurement.h"
#include "pm_meter.h"
#include "pm_network.h"
#include "pm_ota.h"
#include "pm_protocol.h"
#include "pm_provisioning.h"
#include "pm_state.h"
#include "pm_storage.h"

#if CONFIG_PM_PRODUCTION_RELEASE && (!CONFIG_PM_METER_VARIANT_PZEM004T_V4_CLASSIC || !CONFIG_PM_HARDWARE_IDENTITY_VERIFIED)
#error "Stable production firmware requires an explicit PZEM variant and machine-readable hardware identity evidence"
#endif

#if CONFIG_PM_PRODUCTION_RELEASE && !CONFIG_NVS_ENCRYPTION
#error "Stable production firmware requires NVS encryption backed by a deliberately provisioned device HMAC key"
#endif

#define PM_SAMPLE_QUEUE_DEPTH 8U
#define PM_COMMAND_QUEUE_DEPTH 4U

#ifdef CONFIG_PM_HARDWARE_IDENTITY_VERIFIED
#define PM_BUILD_HARDWARE_VERIFIED true
#else
#define PM_BUILD_HARDWARE_VERIFIED false
#endif

#ifdef CONFIG_PM_SIMULATED_METER
#define PM_BUILD_SIMULATED_METER true
#else
#define PM_BUILD_SIMULATED_METER false
#endif

static const char *const TAG = "power_meter";
static StaticQueue_t s_sample_queue_buffer;
static uint8_t s_sample_queue_storage[PM_SAMPLE_QUEUE_DEPTH * sizeof(pm_meter_sample_t)];
static QueueHandle_t s_sample_queue;
static StaticQueue_t s_command_queue_buffer;
static uint8_t s_command_queue_storage[PM_COMMAND_QUEUE_DEPTH * sizeof(pm_command_t *)];
static QueueHandle_t s_command_queue;
static pm_meter_driver_t s_meter;
static pm_sequence_state_t s_sequence;
static pm_storage_health_t s_storage;
static pm_command_ledger_t s_commands;
static pm_config_t s_config;
static pm_state_machine_t s_state;
static pm_time_state_t s_time;
static pm_network_context_t s_network;
static pm_provisioning_session_t s_provisioning;
static pm_format_transaction_t s_format;
static struct {
    uint8_t token[16];
    int64_t expires_us;
    uint32_t generation;
    uint64_t floor;
    bool prepared;
    pm_format_transaction_t storage_format;
} s_reset;
static pm_config_t s_credential_candidate;
static pm_config_transaction_t s_credential_transaction;
static bool s_credential_prepared;
static portMUX_TYPE s_state_lock = portMUX_INITIALIZER_UNLOCKED;

typedef struct {
    uint8_t device_id[16];
    uint32_t generation;
    uint32_t crc32;
} local_identity_t;

static esp_err_t load_or_create_identity(uint8_t device_id[16])
{
    nvs_handle_t handle = 0;
    esp_err_t error = nvs_open("pm_identity", NVS_READWRITE, &handle);
    if (error != ESP_OK) {
        return error;
    }
    local_identity_t identity = {0};
    size_t size = sizeof(identity);
    error = nvs_get_blob(handle, "identity", &identity, &size);
    const uint32_t expected = pm_crc32_ieee(&identity, offsetof(local_identity_t, crc32));
    if (error != ESP_OK || size != sizeof(identity) || identity.generation == 0U || identity.crc32 != expected) {
        memset(&identity, 0, sizeof(identity));
        esp_fill_random(identity.device_id, sizeof(identity.device_id));
        /* RFC 4122 variant/version bits make the locally generated UUID explicit. */
        identity.device_id[6] = (uint8_t)((identity.device_id[6] & 0x0FU) | 0x40U);
        identity.device_id[8] = (uint8_t)((identity.device_id[8] & 0x3FU) | 0x80U);
        identity.generation = 1U;
        identity.crc32 = pm_crc32_ieee(&identity, offsetof(local_identity_t, crc32));
        error = nvs_set_blob(handle, "identity", &identity, sizeof(identity));
        if (error == ESP_OK) {
            error = nvs_commit(handle);
        }
    }
    nvs_close(handle);
    if (error == ESP_OK) {
        memcpy(device_id, identity.device_id, sizeof(identity.device_id));
    }
    return error;
}

static esp_err_t persist_identity(const uint8_t device_id[16])
{
    if (device_id == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    nvs_handle_t handle = 0;
    esp_err_t error = nvs_open("pm_identity", NVS_READWRITE, &handle);
    if (error != ESP_OK) {
        return error;
    }
    local_identity_t prior = {0};
    size_t size = sizeof(prior);
    const bool prior_valid = nvs_get_blob(handle, "identity", &prior, &size) == ESP_OK && size == sizeof(prior) &&
                             prior.generation != 0U &&
                             prior.crc32 == pm_crc32_ieee(&prior, offsetof(local_identity_t, crc32));
    local_identity_t identity = {.generation = prior_valid ? prior.generation + 1U : 1U};
    memcpy(identity.device_id, device_id, sizeof(identity.device_id));
    identity.crc32 = pm_crc32_ieee(&identity, offsetof(local_identity_t, crc32));
    error = nvs_set_blob(handle, "identity", &identity, sizeof(identity));
    if (error == ESP_OK) {
        error = nvs_commit(handle);
    }
    nvs_close(handle);
    return error;
}

static void uuid_text(const uint8_t id[16], char output[37])
{
    (void)snprintf(output, 37U,
                   "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
                   id[0], id[1], id[2], id[3], id[4], id[5], id[6], id[7], id[8], id[9], id[10], id[11], id[12],
                   id[13], id[14], id[15]);
}

static void set_degraded(pm_state_event_t event)
{
    taskENTER_CRITICAL(&s_state_lock);
    (void)pm_state_transition(&s_state, event, esp_timer_get_time());
    taskEXIT_CRITICAL(&s_state_lock);
}

static void measurement_task(void *argument)
{
    (void)argument;
    (void)esp_task_wdt_add(NULL);
    TickType_t last_wake = xTaskGetTickCount();
    for (;;) {
        pm_meter_sample_t sample = {0};
        const esp_err_t error = pm_meter_read(&s_meter, &sample, 350U);
        sample.sample_monotonic_us = esp_timer_get_time();
        int64_t utc_ms = 0;
        taskENTER_CRITICAL(&s_state_lock);
        sample.time_trusted = pm_time_now(&s_time, sample.sample_monotonic_us, &utc_ms);
        taskEXIT_CRITICAL(&s_state_lock);
        sample.sample_timestamp_utc_ms = sample.time_trusted ? utc_ms : 0;
        if (error != ESP_OK) {
            set_degraded(PM_EVENT_METER_FAILED);
        }
        (void)pm_network_publish_live(&sample);
        if (xQueueSend(s_sample_queue, &sample, 0U) != pdTRUE) {
            ESP_LOGW(TAG, "measurement queue full; sample is missing, never coerced to zero");
        }
        (void)esp_task_wdt_reset();
        xTaskDelayUntil(&last_wake, pdMS_TO_TICKS(CONFIG_PM_METER_SAMPLE_MS));
    }
}

static void record_unavailable(uint64_t sequence)
{
    if (s_storage.unavailable_first == 0U || sequence < s_storage.unavailable_first) {
        s_storage.unavailable_first = sequence;
    }
    if (sequence > s_storage.unavailable_last) {
        s_storage.unavailable_last = sequence;
    }
}

static void interval_task(void *argument)
{
    (void)argument;
    (void)esp_task_wdt_add(NULL);
    const uint32_t expected = (CONFIG_PM_DURABLE_INTERVAL_SECONDS * 1000U) / CONFIG_PM_METER_SAMPLE_MS;
    pm_interval_accumulator_t accumulator;
    pm_interval_init(&accumulator, expected);
    int64_t interval_started_us = esp_timer_get_time();
    for (;;) {
        pm_meter_sample_t sample = {0};
        if (xQueueReceive(s_sample_queue, &sample, pdMS_TO_TICKS(1000)) == pdTRUE) {
            (void)pm_interval_add(&accumulator, &sample, s_config.ct_rating_a == 0U ? 100U : s_config.ct_rating_a);
        } else {
            accumulator.flags |= PM_INTERVAL_FLAG_MISSING_SAMPLE;
        }
        const int64_t now = esp_timer_get_time();
        if (now - interval_started_us >= (int64_t)CONFIG_PM_DURABLE_INTERVAL_SECONDS * INT64_C(1000000)) {
            pm_durable_interval_t interval;
            if (pm_interval_finalize(&accumulator, &interval,
                                     (uint64_t)(s_config.ct_rating_a == 0U ? 100U : s_config.ct_rating_a) *
                                         UINT64_C(300000))) {
                uint64_t sequence = 0U;
                if (pm_sequence_next(&s_sequence, &sequence) == ESP_OK) {
                    pm_journal_record_t record = {
                        .sequence = sequence,
                        .reset_generation = s_sequence.reset_generation,
                        .interval = interval,
                    };
                    memcpy(record.device_id, s_config.device_id, sizeof(record.device_id));
                    if (pm_storage_append(&record, 500U) != ESP_OK) {
                        record_unavailable(sequence);
                        set_degraded(PM_EVENT_STORAGE_FAILED);
                    }
                }
            } else {
                pm_interval_init(&accumulator, expected);
            }
            interval_started_us = now;
        }
        (void)esp_task_wdt_reset();
    }
}

static bool hex_decode(const char *input, uint8_t *output, size_t length)
{
    if (input == NULL || output == NULL || strlen(input) != length * 2U) {
        return false;
    }
    for (size_t i = 0U; i < length; ++i) {
        unsigned int byte = 0U;
        if (sscanf(&input[i * 2U], "%2x", &byte) != 1) {
            return false;
        }
        output[i] = (uint8_t)byte;
    }
    return true;
}

static bool ota_manifest_from_payload(const char *payload, pm_ota_manifest_t *manifest)
{
    cJSON *root = cJSON_Parse(payload);
    if (root == NULL || manifest == NULL) {
        cJSON_Delete(root);
        return false;
    }
    memset(manifest, 0, sizeof(*manifest));
    const cJSON *version = cJSON_GetObjectItemCaseSensitive(root, "version");
    const cJSON *build = cJSON_GetObjectItemCaseSensitive(root, "build_number");
    const cJSON *project = cJSON_GetObjectItemCaseSensitive(root, "project_name");
    const cJSON *target = cJSON_GetObjectItemCaseSensitive(root, "target_chip");
    const cJSON *board = cJSON_GetObjectItemCaseSensitive(root, "board_profile");
    const cJSON *min_boot = cJSON_GetObjectItemCaseSensitive(root, "minimum_boot_version");
    const cJSON *min_config = cJSON_GetObjectItemCaseSensitive(root, "minimum_config_version");
    const cJSON *protocol = cJSON_GetObjectItemCaseSensitive(root, "minimum_protocol");
    const cJSON *size = cJSON_GetObjectItemCaseSensitive(root, "image_size");
    const cJSON *sha = cJSON_GetObjectItemCaseSensitive(root, "sha256");
    const cJSON *url = cJSON_GetObjectItemCaseSensitive(root, "download_url");
    const cJSON *nonce = cJSON_GetObjectItemCaseSensitive(root, "manifest_nonce");
    const cJSON *signature = cJSON_GetObjectItemCaseSensitive(root, "signature");
    const bool valid = cJSON_IsString(version) && strlen(version->valuestring) <= PM_OTA_VERSION_MAX &&
                       cJSON_IsNumber(build) && cJSON_IsString(project) && strlen(project->valuestring) <= PM_OTA_PROJECT_MAX &&
                       cJSON_IsString(target) && strlen(target->valuestring) <= PM_OTA_TARGET_MAX && cJSON_IsString(board) &&
                       strlen(board->valuestring) <= PM_OTA_BOARD_MAX && cJSON_IsNumber(min_boot) && cJSON_IsNumber(min_config) &&
                       cJSON_IsString(protocol) && strlen(protocol->valuestring) <= PM_OTA_PROTOCOL_MAX && cJSON_IsNumber(size) &&
                       cJSON_IsString(sha) && cJSON_IsString(url) && strlen(url->valuestring) <= PM_OTA_URL_MAX &&
                       cJSON_IsString(nonce) && cJSON_IsString(signature) &&
                       hex_decode(sha->valuestring, manifest->image_sha256, sizeof(manifest->image_sha256)) &&
                       hex_decode(nonce->valuestring, manifest->manifest_nonce, sizeof(manifest->manifest_nonce)) &&
                       hex_decode(signature->valuestring, manifest->signature, sizeof(manifest->signature));
    if (valid) {
        (void)snprintf(manifest->version, sizeof(manifest->version), "%s", version->valuestring);
        manifest->build_number = (uint32_t)build->valuedouble;
        (void)snprintf(manifest->project_name, sizeof(manifest->project_name), "%s", project->valuestring);
        (void)snprintf(manifest->target_chip, sizeof(manifest->target_chip), "%s", target->valuestring);
        (void)snprintf(manifest->board_profile, sizeof(manifest->board_profile), "%s", board->valuestring);
        manifest->minimum_boot_version = (uint32_t)min_boot->valuedouble;
        manifest->minimum_config_version = (uint32_t)min_config->valuedouble;
        (void)snprintf(manifest->minimum_protocol, sizeof(manifest->minimum_protocol), "%s", protocol->valuestring);
        manifest->image_size = (uint32_t)size->valuedouble;
        (void)snprintf(manifest->download_url, sizeof(manifest->download_url), "%s", url->valuestring);
    }
    cJSON_Delete(root);
    return valid;
}

static bool json_u64(const cJSON *root, const char *name, uint64_t *value)
{
    const cJSON *item = cJSON_GetObjectItemCaseSensitive(root, name);
    if (!cJSON_IsNumber(item) || item->valuedouble < 0.0) {
        return false;
    }
    *value = (uint64_t)item->valuedouble;
    return true;
}

static void ota_progress(uint8_t percent, pm_ota_stage_t stage, void *context)
{
    pm_command_t *command = (pm_command_t *)context;
    if (command != NULL) {
        (void)snprintf(command->result_text, sizeof(command->result_text), "ota_stage=%u", (unsigned)stage);
        (void)pm_command_transition(&s_commands, command, PM_COMMAND_RUNNING, percent, ESP_OK);
    }
}

static void ota_task(void *argument)
{
    pm_command_t *command = (pm_command_t *)argument;
    pm_ota_manifest_t manifest;
    esp_err_t result = ota_manifest_from_payload(command->payload, &manifest)
                           ? pm_ota_install(&manifest, s_config.ca_pem, s_network.server_to_device_key, ota_progress, command)
                           : ESP_ERR_INVALID_ARG;
    if (result == ESP_OK) {
        (void)pm_command_transition(&s_commands, command, PM_COMMAND_AWAITING_REBOOT, 100U, ESP_OK);
        (void)pm_storage_flush(3000U);
        vTaskDelay(pdMS_TO_TICKS(500));
        esp_restart();
    } else {
        pm_network_health_update(&s_network, PM_HEALTH_OTA_FAILED, true);
        (void)pm_command_transition(&s_commands, command, PM_COMMAND_FAILED, command->progress_percent, result);
    }
    vTaskDelete(NULL);
}

static void execute_command(pm_command_t *command)
{
    if (command == NULL) {
        return;
    }
    (void)pm_command_transition(&s_commands, command, PM_COMMAND_RUNNING, 1U, ESP_OK);
    esp_err_t result = ESP_OK;
    switch (command->type) {
    case PM_COMMAND_REBOOT:
        (void)pm_storage_flush(3000U);
        (void)pm_command_transition(&s_commands, command, PM_COMMAND_AWAITING_REBOOT, 100U, ESP_OK);
        vTaskDelay(pdMS_TO_TICKS(500));
        esp_restart();
        break;
    case PM_COMMAND_MAINTENANCE_SLEEP: {
        unsigned long seconds = strtoul(command->payload, NULL, 10);
        if (seconds < 10U || seconds > 3600U) {
            result = ESP_ERR_INVALID_ARG;
            break;
        }
        (void)pm_storage_flush(3000U);
        (void)pm_command_transition(&s_commands, command, PM_COMMAND_AWAITING_HEARTBEAT, 100U, ESP_OK);
        esp_sleep_enable_timer_wakeup((uint64_t)seconds * UINT64_C(1000000));
        esp_deep_sleep_start();
        break;
    }
    case PM_COMMAND_SYNC_NOW:
        pm_network_request_sync();
        break;
    case PM_COMMAND_DIAGNOSTICS_SNAPSHOT: {
        pm_diagnostics_snapshot_t snapshot = {0};
        pm_diagnostics_capture(&snapshot);
        (void)snprintf(command->result_text, sizeof(command->result_text),
                       "heap=%lu,min=%lu,largest=%lu,psram=%lu,reset=%lu",
                       (unsigned long)snapshot.free_internal_heap, (unsigned long)snapshot.minimum_free_internal_heap,
                       (unsigned long)snapshot.largest_internal_block, (unsigned long)snapshot.free_psram,
                       (unsigned long)snapshot.reboot_reason);
        break;
    }
    case PM_COMMAND_NETWORK_SELF_TEST:
        pm_network_request_sync();
        (void)snprintf(command->result_text, sizeof(command->result_text), "bounded_network_retry_requested");
        break;
    case PM_COMMAND_METER_SELF_TEST: {
        pm_meter_sample_t sample = {0};
        result = pm_meter_read(&s_meter, &sample, 500U);
        (void)snprintf(command->result_text, sizeof(command->result_text), "pzem_status=%s",
                       pm_pzem_status_name(sample.status));
        break;
    }
    case PM_COMMAND_STORAGE_SELF_TEST:
        result = pm_storage_rebuild_index(&s_storage);
        break;
    case PM_COMMAND_FORMAT_STORAGE_PREPARE: {
        result = pm_storage_prepare_format((uint64_t)esp_timer_get_time(),
                                           (uint64_t)esp_timer_get_time() + UINT64_C(60000000), &s_format);
        char token[33];
        pm_hex_lower(s_format.token, sizeof(s_format.token), token, sizeof(token));
        (void)snprintf(command->result_text, sizeof(command->result_text),
                       "token=%s,acknowledged_lost=%llu,unacknowledged_lost=%llu", token,
                       (unsigned long long)s_format.acknowledged_records_lost,
                       (unsigned long long)s_format.unacknowledged_records_lost);
        break;
    }
    case PM_COMMAND_FORMAT_STORAGE_COMMIT: {
        uint8_t token[16];
        result = hex_decode(command->payload, token, sizeof(token)) ? pm_storage_commit_format(&s_format, token) :
                                                                    ESP_ERR_INVALID_ARG;
        break;
    }
    case PM_COMMAND_OTA_INSTALL:
        if (xTaskCreate(ota_task, "pm_ota", 12288U, command, 6U, NULL) == pdPASS) {
            return;
        }
        result = ESP_ERR_NO_MEM;
        break;
    case PM_COMMAND_DATA_RESET_PREPARE: {
        cJSON *root = cJSON_Parse(command->payload);
        uint64_t generation = 0U;
        uint64_t server_floor = 0U;
        if (root == NULL || !json_u64(root, "reset_generation", &generation) ||
            !json_u64(root, "server_sequence_floor", &server_floor) || generation <= s_sequence.reset_generation ||
            generation > UINT32_MAX) {
            result = ESP_ERR_INVALID_ARG;
            cJSON_Delete(root);
            break;
        }
        cJSON_Delete(root);
        memset(&s_reset, 0, sizeof(s_reset));
        esp_fill_random(s_reset.token, sizeof(s_reset.token));
        s_reset.expires_us = esp_timer_get_time() + INT64_C(60000000);
        s_reset.generation = (uint32_t)generation;
        s_reset.floor = server_floor > s_sequence.maximum_seen ? server_floor : s_sequence.maximum_seen;
        result = pm_storage_prepare_format((uint64_t)esp_timer_get_time(), (uint64_t)s_reset.expires_us,
                                           &s_reset.storage_format);
        s_reset.prepared = result == ESP_OK;
        char encoded[33];
        pm_hex_lower(s_reset.token, sizeof(s_reset.token), encoded, sizeof(encoded));
        (void)snprintf(command->result_text, sizeof(command->result_text),
                       "token=%s,generation=%lu,floor=%llu,preserve=enrollment+network+identity+pzem",
                       encoded, (unsigned long)s_reset.generation, (unsigned long long)s_reset.floor);
        break;
    }
    case PM_COMMAND_DATA_RESET_CANCEL:
        memset(&s_reset, 0, sizeof(s_reset));
        break;
    case PM_COMMAND_DATA_RESET_COMMIT: {
        /* The server must first confirm its reset generation and boundary. The
         * commit repeats every prepared value and the typed token. */
        cJSON *root = cJSON_Parse(command->payload);
        const cJSON *token = root == NULL ? NULL : cJSON_GetObjectItemCaseSensitive(root, "confirmation_token");
        uint64_t generation = 0U;
        uint64_t floor = 0U;
        char expected[33];
        pm_hex_lower(s_reset.token, sizeof(s_reset.token), expected, sizeof(expected));
        if (!s_reset.prepared || esp_timer_get_time() > s_reset.expires_us || !cJSON_IsString(token) ||
            strlen(token->valuestring) != 32U || !json_u64(root, "reset_generation", &generation) ||
            !json_u64(root, "sequence_floor", &floor) || generation != s_reset.generation || floor != s_reset.floor ||
            !pm_constant_time_equal((const uint8_t *)expected, (const uint8_t *)token->valuestring, 32U)) {
            result = ESP_ERR_INVALID_STATE;
        } else {
            result = pm_sequence_raise_floor(&s_sequence, s_reset.floor, s_reset.generation);
            if (result == ESP_OK) {
                result = pm_storage_commit_format(&s_reset.storage_format, s_reset.storage_format.token);
            }
            if (result == ESP_OK) {
                s_config.sequence_floor = s_sequence.maximum_seen;
                s_config.acknowledged_sequence = s_sequence.acknowledged;
                s_config.reset_generation = s_sequence.reset_generation;
                pm_config_transaction_t transaction;
                result = pm_config_begin(&s_config, &transaction);
                if (result == ESP_OK) {
                    result = pm_config_mark_network_tested(&transaction);
                }
                if (result == ESP_OK) {
                    result = pm_config_commit(&transaction);
                }
            }
            memset(&s_reset, 0, sizeof(s_reset));
        }
        cJSON_Delete(root);
        break;
    }
    case PM_COMMAND_APPLY_CONFIGURATION: {
        /* Remote application is deliberately limited to settings that cannot
         * strand connectivity. Wi-Fi, server origin and CA repair use tested
         * COM A/B transactions. */
        cJSON *root = cJSON_Parse(command->payload);
        const cJSON *name = root == NULL ? NULL : cJSON_GetObjectItemCaseSensitive(root, "friendly_name");
        const cJSON *timezone = root == NULL ? NULL : cJSON_GetObjectItemCaseSensitive(root, "timezone");
        const cJSON *ct = root == NULL ? NULL : cJSON_GetObjectItemCaseSensitive(root, "ct_rating_a");
        if (!cJSON_IsString(name) || strlen(name->valuestring) > PM_CONFIG_NAME_MAX || !cJSON_IsString(timezone) ||
            strlen(timezone->valuestring) > PM_CONFIG_TIMEZONE_MAX || !cJSON_IsNumber(ct) || ct->valuedouble < 1.0 ||
            ct->valuedouble > 100.0 || cJSON_GetArraySize(root) != 3) {
            result = ESP_ERR_INVALID_ARG;
        } else {
            pm_config_t candidate = s_config;
            candidate.generation++;
            (void)snprintf(candidate.friendly_name, sizeof(candidate.friendly_name), "%s", name->valuestring);
            (void)snprintf(candidate.timezone, sizeof(candidate.timezone), "%s", timezone->valuestring);
            candidate.ct_rating_a = (uint16_t)ct->valuedouble;
            pm_config_transaction_t transaction;
            result = pm_config_begin(&candidate, &transaction);
            if (result == ESP_OK) {
                result = pm_config_mark_network_tested(&transaction);
            }
            if (result == ESP_OK) {
                result = pm_config_commit(&transaction);
                s_config = candidate;
                s_network.config = candidate;
            }
        }
        cJSON_Delete(root);
        break;
    }
    case PM_COMMAND_ROTATE_DEVICE_CREDENTIALS: {
        cJSON *root = cJSON_Parse(command->payload);
        const cJSON *action = root == NULL ? NULL : cJSON_GetObjectItemCaseSensitive(root, "action");
        const cJSON *secret = root == NULL ? NULL : cJSON_GetObjectItemCaseSensitive(root, "device_secret_hex");
        const cJSON *fingerprint_item = root == NULL ? NULL : cJSON_GetObjectItemCaseSensitive(root, "fingerprint");
        if (cJSON_IsString(action) && strcmp(action->valuestring, "prepare") == 0 && cJSON_IsString(secret) &&
            strlen(secret->valuestring) == 64U) {
            s_credential_candidate = s_config;
            s_credential_candidate.generation++;
            if (!hex_decode(secret->valuestring, s_credential_candidate.device_secret, 32U)) {
                result = ESP_ERR_INVALID_ARG;
            } else {
                s_credential_candidate.device_secret_len = 32U;
                result = pm_config_begin(&s_credential_candidate, &s_credential_transaction);
                s_credential_prepared = result == ESP_OK;
                uint8_t digest[32];
                char fingerprint[17];
                pm_sha256(s_credential_candidate.device_secret, 32U, digest);
                pm_hex_lower(digest, 8U, fingerprint, sizeof(fingerprint));
                (void)snprintf(command->result_text, sizeof(command->result_text), "prepared_fingerprint=%s", fingerprint);
            }
        } else if (cJSON_IsString(action) && strcmp(action->valuestring, "commit") == 0 &&
                   cJSON_IsString(fingerprint_item) && s_credential_prepared) {
            uint8_t digest[32];
            char fingerprint[17];
            pm_sha256(s_credential_candidate.device_secret, 32U, digest);
            pm_hex_lower(digest, 8U, fingerprint, sizeof(fingerprint));
            if (strcmp(fingerprint, fingerprint_item->valuestring) != 0) {
                result = ESP_ERR_INVALID_CRC;
            } else {
                result = pm_config_mark_network_tested(&s_credential_transaction);
                if (result == ESP_OK) {
                    result = pm_config_commit(&s_credential_transaction);
                }
                if (result == ESP_OK) {
                    s_config = s_credential_candidate;
                    s_network.config = s_credential_candidate;
                    result = pm_hkdf_directional_keys(s_config.device_secret, s_config.device_secret_len,
                                                      s_network.device_id_text,
                                                      s_network.device_to_server_key, s_network.server_to_device_key);
                }
                memset(&s_credential_candidate, 0, sizeof(s_credential_candidate));
                s_credential_prepared = false;
            }
        } else {
            result = ESP_ERR_INVALID_ARG;
        }
        cJSON_Delete(root);
        break;
    }
    default:
        result = ESP_ERR_NOT_SUPPORTED;
        break;
    }
    (void)pm_command_transition(&s_commands, command, result == ESP_OK ? PM_COMMAND_SUCCEEDED : PM_COMMAND_FAILED,
                                result == ESP_OK ? 100U : command->progress_percent, result);
}

static void control_task(void *argument)
{
    (void)argument;
    (void)esp_task_wdt_add(NULL);
    for (;;) {
        pm_command_t *command = NULL;
        if (xQueueReceive(s_command_queue, &command, pdMS_TO_TICKS(1000)) == pdTRUE) {
            execute_command(command);
        }
        (void)esp_task_wdt_reset();
    }
}

static void command_received(const pm_command_t *command, void *context)
{
    (void)context;
    pm_command_t *mutable_command = (pm_command_t *)command;
    if (xQueueSend(s_command_queue, &mutable_command, 0U) != pdTRUE) {
        ESP_LOGE(TAG, "bounded command queue full");
    }
}

static esp_err_t factory_reset_config_only(void *context)
{
    (void)context;
    nvs_handle_t handle = 0;
    esp_err_t error = nvs_open("pm_config", NVS_READWRITE, &handle);
    if (error == ESP_OK) {
        error = nvs_erase_all(handle);
    }
    if (error == ESP_OK) {
        error = nvs_commit(handle);
    }
    if (handle != 0) {
        nvs_close(handle);
    }
    /* Device identity and monotonic sequence namespace are intentionally not erased. */
    return error;
}

static void supervisor_task(void *argument)
{
    (void)argument;
    (void)esp_task_wdt_add(NULL);
    int64_t last_time_checkpoint = 0;
    for (;;) {
        const int64_t now_us = esp_timer_get_time();
        if (now_us - last_time_checkpoint >= INT64_C(3600000000)) {
            const int64_t system_utc_ms = (int64_t)time(NULL) * 1000;
            if (system_utc_ms >= INT64_C(1704067200000)) {
                (void)pm_time_observe(&s_time, PM_TIME_SNTP, system_utc_ms, now_us);
            }
            last_time_checkpoint = now_us;
        }
        (void)esp_task_wdt_reset();
        vTaskDelay(pdMS_TO_TICKS(5000));
    }
}

void app_main(void)
{
    pm_state_init(&s_state, esp_timer_get_time());
    (void)pm_state_transition(&s_state, PM_EVENT_BOOTSTRAP, esp_timer_get_time());
    esp_err_t error = nvs_flash_init();
    if (error != ESP_OK) {
        ESP_LOGE(TAG, "NVS initialization failed without destructive erase: %s", esp_err_to_name(error));
        (void)pm_state_transition(&s_state, PM_EVENT_SELF_TEST_FAILED, esp_timer_get_time());
        return;
    }
    uint8_t identity[16];
    if (load_or_create_identity(identity) != ESP_OK || pm_sequence_load(&s_sequence) != ESP_OK ||
        pm_commands_load(&s_commands) != ESP_OK) {
        ESP_LOGE(TAG, "identity/sequence/command recovery failed closed");
        (void)pm_state_transition(&s_state, PM_EVENT_SELF_TEST_FAILED, esp_timer_get_time());
        return;
    }
    error = pm_config_load(&s_config);
    const bool provisioned = error == ESP_OK;
    if (!provisioned) {
        memset(&s_config, 0, sizeof(s_config));
        s_config.schema_version = PM_CONFIG_SCHEMA_VERSION;
        memcpy(s_config.device_id, identity, sizeof(identity));
        s_config.ct_rating_a = 100U;
        s_config.meter_variant = PM_METER_PZEM004T_V4_CLASSIC;
        s_config.sequence_floor = s_sequence.maximum_seen;
        s_config.acknowledged_sequence = s_sequence.acknowledged;
    } else if (memcmp(s_config.device_id, identity, sizeof(identity)) != 0) {
        /* Enrollment assigns the permanent server UUID. Persist it independently so
         * configuration-only reset preserves device/sequence identity. */
        if (persist_identity(s_config.device_id) != ESP_OK) {
            ESP_LOGE(TAG, "enrolled identity checkpoint failed");
            (void)pm_state_transition(&s_state, PM_EVENT_SELF_TEST_FAILED, esp_timer_get_time());
            return;
        }
        memcpy(identity, s_config.device_id, sizeof(identity));
    }

    pm_time_init(&s_time, esp_timer_get_time());
    (void)pm_time_load_checkpoint(&s_time, esp_timer_get_time());
    const gpio_config_t recovery_button = {
        .pin_bit_mask = UINT64_C(1) << PM_USB_RECOVERY_BUTTON,
        .mode = GPIO_MODE_INPUT,
        .pull_up_en = GPIO_PULLUP_ENABLE,
        .pull_down_en = GPIO_PULLDOWN_DISABLE,
        .intr_type = GPIO_INTR_DISABLE,
    };
    (void)gpio_config(&recovery_button);
    const bool physical_recovery = gpio_get_level(PM_USB_RECOVERY_BUTTON) == 0;

    error = pm_storage_start(s_config.device_id, &s_storage);
    s_storage.acknowledged_sequence = s_sequence.acknowledged;
    if (error != ESP_OK) {
        set_degraded(PM_EVENT_STORAGE_FAILED);
    }
    error = pm_meter_create(&s_meter, PM_METER_PZEM004T_V4_CLASSIC,
                            PM_BUILD_HARDWARE_VERIFIED, PM_BUILD_SIMULATED_METER);
    if (error != ESP_OK) {
        set_degraded(PM_EVENT_METER_FAILED);
    }

    s_sample_queue = xQueueCreateStatic(PM_SAMPLE_QUEUE_DEPTH, sizeof(pm_meter_sample_t), s_sample_queue_storage,
                                        &s_sample_queue_buffer);
    s_command_queue = xQueueCreateStatic(PM_COMMAND_QUEUE_DEPTH, sizeof(pm_command_t *), s_command_queue_storage,
                                         &s_command_queue_buffer);
    if (s_sample_queue == NULL || s_command_queue == NULL) {
        ESP_LOGE(TAG, "static queue creation failed");
        return;
    }
    (void)xTaskCreate(measurement_task, "pm_measurement", 4096U, NULL, 12U, NULL);
    (void)xTaskCreate(interval_task, "pm_interval", 4096U, NULL, 9U, NULL);
    (void)xTaskCreate(control_task, "pm_control", 4096U, NULL, 6U, NULL);
    (void)xTaskCreate(supervisor_task, "pm_supervisor", 4096U, NULL, 5U, NULL);

    pm_provisioning_session_init(&s_provisioning, &s_config, physical_recovery || !provisioned,
                                 pm_network_provisioning_test, factory_reset_config_only, NULL);
    if (!provisioned || physical_recovery) {
        (void)pm_state_transition(&s_state, !provisioned ? PM_EVENT_CONFIG_MISSING : PM_EVENT_PHYSICAL_RECOVERY,
                                  esp_timer_get_time());
        (void)pm_provisioning_start_usb(&s_provisioning);
    }
    if (provisioned) {
        s_network.config = s_config;
        uuid_text(s_config.device_id, s_network.device_id_text);
        s_network.sequence = &s_sequence;
        s_network.storage = &s_storage;
        s_network.commands = &s_commands;
        s_network.command_callback = command_received;
        pm_ota_checkpoint_t ota_checkpoint;
        if (pm_ota_load_checkpoint(&ota_checkpoint) == ESP_OK) {
            pm_network_health_update(&s_network, PM_HEALTH_OTA_FAILED, ota_checkpoint.stage == PM_OTA_FAILED);
            pm_network_health_update(&s_network, PM_HEALTH_OTA_ROLLED_BACK,
                                     ota_checkpoint.stage == PM_OTA_ROLLED_BACK);
        }
        error = pm_network_start(&s_network);
        if (error == ESP_OK) {
            (void)pm_state_transition(&s_state, PM_EVENT_SELF_TEST_OK, esp_timer_get_time());
        } else {
            set_degraded(PM_EVENT_WIFI_FAILED);
        }
    }
    (void)pm_ota_post_boot_validate(provisioned, true, true, true, provisioned);
}
