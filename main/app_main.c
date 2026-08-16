#include <ctype.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "cJSON.h"
#include "driver/gpio.h"
#include "esp_heap_caps.h"
#include "esp_log.h"
#include "esp_random.h"
#include "esp_sleep.h"
#include "esp_system.h"
#include "esp_task_wdt.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"
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
#include "runtime_startup.h"

#if CONFIG_PM_PRODUCTION_RELEASE && (!CONFIG_PM_METER_VARIANT_PZEM004T_V4_CLASSIC || !CONFIG_PM_HARDWARE_IDENTITY_VERIFIED)
#error "Stable production firmware requires an explicit PZEM variant and machine-readable hardware identity evidence"
#endif

#if CONFIG_PM_PRODUCTION_RELEASE && !CONFIG_NVS_ENCRYPTION
#error "Stable production firmware requires NVS encryption backed by a deliberately provisioned device HMAC key"
#endif

#define PM_SAMPLE_QUEUE_DEPTH 8U
#define PM_COMMAND_QUEUE_DEPTH PM_COMMAND_LEDGER_SIZE
#define PM_RESULT_ACK_QUEUE_DEPTH 8U
#define PM_PREPARE_NAMESPACE "pm_prepare"
#define PM_PREPARE_SLOT_A "slot_a"
#define PM_PREPARE_SLOT_B "slot_b"
#define PM_PREPARE_LEGACY_KEY "active"
#define PM_PREPARE_SCHEMA 2U
#define PM_PREPARE_EXPIRY_US UINT64_C(600000000)
#define PM_ROTATION_NAMESPACE "pm_rotation"
#define PM_ROTATION_SLOT_A "slot_a"
#define PM_ROTATION_SLOT_B "slot_b"
#define PM_ROTATION_SCHEMA_VERSION 1U
#define PM_ROTATION_CONTRACT "pm-credential-rotation/1.0.0"
#define PM_NVS_RAW_DURABLE_BLOB_BUDGET UINT32_C(0xD000)
#define PM_NVS_OTHER_DURABLE_RESERVE UINT32_C(4096)
#define PM_RECOVERY_WINDOW_MS 3000U
#define PM_RECOVERY_DEBOUNCE_SAMPLES 5U
#define PM_RECOVERY_SAMPLE_MS 20U
#define PM_RUNTIME_START_BIT BIT0
#define PM_NETWORK_START_BIT BIT1
#define PM_MEASUREMENT_READY_BIT BIT2
#define PM_INTERVAL_READY_BIT BIT3
#define PM_CONTROL_READY_BIT BIT4
#define PM_SUPERVISOR_READY_BIT BIT5
#define PM_RUNTIME_TASK_FAILED_BIT BIT6
#define PM_RUNTIME_READY_BITS (PM_MEASUREMENT_READY_BIT | PM_INTERVAL_READY_BIT | \
                               PM_CONTROL_READY_BIT | PM_SUPERVISOR_READY_BIT)

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
typedef struct {
    char command_id[PM_COMMAND_ID_MAX + 1U];
} pm_result_ack_event_t;
static StaticQueue_t s_result_ack_queue_buffer;
static uint8_t s_result_ack_queue_storage[PM_RESULT_ACK_QUEUE_DEPTH * sizeof(pm_result_ack_event_t)];
static QueueHandle_t s_result_ack_queue;
static StaticEventGroup_t s_runtime_start_gate_storage;
static EventGroupHandle_t s_runtime_start_gate;
static TaskHandle_t s_measurement_task;
static TaskHandle_t s_interval_task;
static TaskHandle_t s_control_task;
static TaskHandle_t s_supervisor_task;
static pm_meter_driver_t s_meter;
static pm_sequence_state_t s_sequence;
static pm_storage_health_t s_storage;
static bool s_storage_flush_available;
static pm_command_ledger_t s_commands;
static pm_config_t s_config;
static pm_state_machine_t s_state;
static pm_time_state_t s_time;
static pm_network_context_t s_network;
static uint8_t s_runtime_device_id[PM_CONFIG_DEVICE_ID_LEN];
static uint16_t s_runtime_ct_rating_a;
static pm_provisioning_session_t s_provisioning;
static pm_format_transaction_t s_format;
static char s_format_prepare_command_id[PM_COMMAND_ID_MAX + 1U];
static struct {
    uint8_t token[16];
    char prepare_command_id[PM_COMMAND_ID_MAX + 1U];
    int64_t expires_us;
    uint32_t generation;
    uint64_t server_floor;
    uint64_t floor;
    bool prepared;
    pm_format_transaction_t storage_format;
} s_reset;
static portMUX_TYPE s_state_lock = portMUX_INITIALIZER_UNLOCKED;
static uint8_t s_prepare_boot_session[16];
static bool s_ota_task_active;

static bool begin_runtime_task(EventBits_t ready_bit)
{
    if (s_runtime_start_gate == NULL ||
        (xEventGroupWaitBits(s_runtime_start_gate, PM_RUNTIME_START_BIT, pdFALSE, pdTRUE,
                             portMAX_DELAY) & PM_RUNTIME_START_BIT) == 0U) {
        return false;
    }
    if (esp_task_wdt_add(NULL) != ESP_OK) {
        (void)xEventGroupSetBits(s_runtime_start_gate, PM_RUNTIME_TASK_FAILED_BIT);
        return false;
    }
    (void)xEventGroupSetBits(s_runtime_start_gate, ready_bit);
    return true;
}

static void update_runtime_measurement_config(const pm_config_t *config)
{
    if (config == NULL) {
        return;
    }
    taskENTER_CRITICAL(&s_state_lock);
    memcpy(s_runtime_device_id, config->device_id, sizeof(s_runtime_device_id));
    s_runtime_ct_rating_a = config->ct_rating_a == 0U ? 100U : config->ct_rating_a;
    taskEXIT_CRITICAL(&s_state_lock);
}

static uint16_t runtime_ct_rating_a(void)
{
    taskENTER_CRITICAL(&s_state_lock);
    const uint16_t rating = s_runtime_ct_rating_a;
    taskEXIT_CRITICAL(&s_state_lock);
    return rating;
}

static void copy_runtime_device_id(uint8_t output[PM_CONFIG_DEVICE_ID_LEN])
{
    taskENTER_CRITICAL(&s_state_lock);
    memcpy(output, s_runtime_device_id, PM_CONFIG_DEVICE_ID_LEN);
    taskEXIT_CRITICAL(&s_state_lock);
}

static void secure_zero(void *value, size_t length)
{
    volatile uint8_t *bytes = (volatile uint8_t *)value;
    while (length-- > 0U) {
        *bytes++ = 0U;
    }
}

static bool claim_ota_task(void)
{
    taskENTER_CRITICAL(&s_state_lock);
    const bool claimed = !s_ota_task_active;
    if (claimed) {
        s_ota_task_active = true;
    }
    taskEXIT_CRITICAL(&s_state_lock);
    return claimed;
}

static void release_ota_task(void)
{
    taskENTER_CRITICAL(&s_state_lock);
    s_ota_task_active = false;
    taskEXIT_CRITICAL(&s_state_lock);
}

static void zeroize_json_string(cJSON *object, const char *name)
{
    cJSON *item = object == NULL ? NULL : cJSON_GetObjectItemCaseSensitive(object, name);
    if (cJSON_IsString(item) && item->valuestring != NULL) {
        secure_zero(item->valuestring, strlen(item->valuestring));
    }
}

static pm_config_t *allocate_config_scratch(void)
{
    pm_config_t *config = (pm_config_t *)heap_caps_calloc(
        1U, sizeof(*config), MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if (config == NULL) {
        config = (pm_config_t *)heap_caps_calloc(
            1U, sizeof(*config), MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
    }
    return config;
}

static void free_config_scratch(pm_config_t *config)
{
    if (config != NULL) {
        secure_zero(config, sizeof(*config));
        heap_caps_free(config);
    }
}

typedef struct {
    pm_command_t *command;
    pm_network_auth_snapshot_t auth;
} pm_ota_task_context_t;

static pm_ota_task_context_t *allocate_ota_task_context(void)
{
    pm_ota_task_context_t *task = (pm_ota_task_context_t *)heap_caps_calloc(
        1U, sizeof(*task), MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if (task == NULL) {
        task = (pm_ota_task_context_t *)heap_caps_calloc(
            1U, sizeof(*task), MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
    }
    return task;
}

static void free_ota_task_context(pm_ota_task_context_t *task)
{
    if (task != NULL) {
        pm_network_clear_auth_snapshot(&task->auth);
        secure_zero(task, sizeof(*task));
        heap_caps_free(task);
    }
}

typedef enum {
    PM_PREPARE_KIND_NONE = 0,
    PM_PREPARE_KIND_FORMAT_STORAGE = 1,
    PM_PREPARE_KIND_DATA_RESET = 2,
} pm_prepare_kind_t;

typedef enum {
    PM_PREPARE_PHASE_NONE = 0,
    PM_PREPARE_PHASE_PREPARED = 1,
    PM_PREPARE_PHASE_COMMIT_INTENT_TOKEN_ZEROIZED = 2,
    PM_PREPARE_PHASE_RESET_SEQUENCE_FLOOR_DURABLE = 3,
    PM_PREPARE_PHASE_STORAGE_FORMAT_DURABLE = 4,
    PM_PREPARE_PHASE_RESET_CONFIG_DURABLE = 5,
    PM_PREPARE_PHASE_COMMAND_RESULT_DURABLE = 6,
    PM_PREPARE_PHASE_RESULT_ACKNOWLEDGED = 7,
} pm_prepare_phase_t;

typedef struct {
    uint32_t schema;
    uint32_t journal_generation;
    uint8_t kind;
    uint8_t phase;
    uint8_t reserved[2];
    uint8_t boot_session[16];
    uint8_t token[16];
    char prepare_command_id[PM_COMMAND_ID_MAX + 1U];
    char commit_command_id[PM_COMMAND_ID_MAX + 1U];
    uint64_t expires_monotonic_us;
    uint32_t reset_generation;
    uint64_t server_sequence_floor;
    uint64_t internal_sequence_floor;
    uint64_t acknowledged_records_lost;
    uint64_t unacknowledged_records_lost;
    uint32_t crc32;
} pm_prepare_record_t;

static pm_prepare_record_t s_prepare_record;

typedef enum {
    PM_ROTATION_PHASE_NONE = 0,
    PM_ROTATION_PHASE_CANDIDATE_PERSISTED = 1,
    PM_ROTATION_PHASE_CONFIG_STAGED = 2,
    PM_ROTATION_PHASE_COMMIT_INTENT_SECRET_ZEROIZED = 3,
    PM_ROTATION_PHASE_CONFIG_ACTIVATED = 4,
    PM_ROTATION_PHASE_COMMAND_RESULT_DURABLE = 5,
    PM_ROTATION_PHASE_RESULT_ACKNOWLEDGED = 6,
} pm_rotation_phase_t;

typedef struct {
    uint32_t schema_version;
    uint32_t journal_generation;
    uint8_t phase;
    uint8_t reserved[3];
    char rotation_id[PM_COMMAND_ID_MAX + 1U];
    char prepare_command_id[PM_COMMAND_ID_MAX + 1U];
    char commit_command_id[PM_COMMAND_ID_MAX + 1U];
    char credential_fingerprint[PM_SHA256_HEX_SIZE + 1U];
    uint8_t candidate_secret[PM_CONFIG_SECRET_MAX];
    int64_t overlap_expires_utc_ms;
    uint32_t candidate_config_generation;
    char candidate_slot;
    uint8_t reserved_tail[3];
    uint32_t crc32;
} pm_rotation_record_t;

static pm_rotation_record_t s_rotation_record;
static bool s_rotation_payload_redaction_retry;

_Static_assert((2U * sizeof(pm_command_ledger_t)) + (2U * sizeof(pm_config_t)) +
                   (2U * sizeof(pm_prepare_record_t)) + (2U * sizeof(pm_rotation_record_t)) +
                   PM_NVS_OTHER_DURABLE_RESERVE <= PM_NVS_RAW_DURABLE_BLOB_BUDGET,
               "A/B durable records exceed the conservative NVS payload budget");

static uint32_t prepare_record_crc(const pm_prepare_record_t *record)
{
    return pm_crc32_ieee(record, offsetof(pm_prepare_record_t, crc32));
}

static bool bytes_are_zero(const uint8_t *bytes, size_t length)
{
    uint8_t combined = 0U;
    for (size_t i = 0U; i < length; ++i) {
        combined |= bytes[i];
    }
    return combined == 0U;
}

static bool persisted_command_id_valid(const char value[PM_COMMAND_ID_MAX + 1U])
{
    return value[PM_COMMAND_ID_MAX] == '\0' && memchr(value, '\0', PM_COMMAND_ID_MAX) == NULL;
}

static bool prepare_record_valid(const pm_prepare_record_t *record)
{
    if (record == NULL || record->schema != PM_PREPARE_SCHEMA || record->journal_generation == 0U ||
        record->kind < PM_PREPARE_KIND_FORMAT_STORAGE || record->kind > PM_PREPARE_KIND_DATA_RESET ||
        record->phase < PM_PREPARE_PHASE_PREPARED || record->phase > PM_PREPARE_PHASE_RESULT_ACKNOWLEDGED ||
        !persisted_command_id_valid(record->prepare_command_id) ||
        record->crc32 != prepare_record_crc(record)) {
        return false;
    }
    if (record->phase == PM_PREPARE_PHASE_PREPARED) {
        return record->commit_command_id[0] == '\0' && record->expires_monotonic_us != 0U &&
               !bytes_are_zero(record->boot_session, sizeof(record->boot_session)) &&
               !bytes_are_zero(record->token, sizeof(record->token));
    }
    if (!persisted_command_id_valid(record->commit_command_id) ||
        !bytes_are_zero(record->token, sizeof(record->token))) {
        return false;
    }
    if (record->kind == PM_PREPARE_KIND_FORMAT_STORAGE &&
        (record->phase == PM_PREPARE_PHASE_RESET_SEQUENCE_FLOOR_DURABLE ||
         record->phase == PM_PREPARE_PHASE_RESET_CONFIG_DURABLE)) {
        return false;
    }
    return record->kind != PM_PREPARE_KIND_DATA_RESET ||
           (record->reset_generation != 0U &&
            record->internal_sequence_floor >= record->server_sequence_floor);
}

static esp_err_t prepare_read_slot(nvs_handle_t handle, const char *key, pm_prepare_record_t *record,
                                   bool *present)
{
    size_t size = sizeof(*record);
    const esp_err_t error = nvs_get_blob(handle, key, record, &size);
    *present = error != ESP_ERR_NVS_NOT_FOUND;
    if (error != ESP_OK) {
        secure_zero(record, sizeof(*record));
        return error;
    }
    if (size != sizeof(*record) || !prepare_record_valid(record)) {
        secure_zero(record, sizeof(*record));
        return ESP_ERR_INVALID_CRC;
    }
    return ESP_OK;
}

static esp_err_t prepare_state_load(void)
{
    nvs_handle_t handle = 0;
    esp_err_t error = nvs_open(PM_PREPARE_NAMESPACE, NVS_READONLY, &handle);
    if (error == ESP_ERR_NVS_NOT_FOUND) {
        return ESP_ERR_NOT_FOUND;
    }
    if (error != ESP_OK) {
        return error;
    }
    pm_prepare_record_t a = {0};
    pm_prepare_record_t b = {0};
    bool present_a = false;
    bool present_b = false;
    const esp_err_t error_a = prepare_read_slot(handle, PM_PREPARE_SLOT_A, &a, &present_a);
    const esp_err_t error_b = prepare_read_slot(handle, PM_PREPARE_SLOT_B, &b, &present_b);
    nvs_close(handle);
    if ((error_a != ESP_OK && error_a != ESP_ERR_NVS_NOT_FOUND && error_a != ESP_ERR_INVALID_CRC) ||
        (error_b != ESP_OK && error_b != ESP_ERR_NVS_NOT_FOUND && error_b != ESP_ERR_INVALID_CRC)) {
        error = error_a != ESP_OK && error_a != ESP_ERR_NVS_NOT_FOUND && error_a != ESP_ERR_INVALID_CRC ?
                error_a : error_b;
        secure_zero(&a, sizeof(a));
        secure_zero(&b, sizeof(b));
        return error;
    }
    const bool valid_a = error_a == ESP_OK;
    const bool valid_b = error_b == ESP_OK;
    if (!valid_a && !valid_b) {
        secure_zero(&a, sizeof(a));
        secure_zero(&b, sizeof(b));
        return present_a || present_b ? ESP_ERR_INVALID_CRC : ESP_ERR_NOT_FOUND;
    }
    if (valid_a && valid_b && a.journal_generation == b.journal_generation &&
        memcmp(&a, &b, sizeof(a)) != 0) {
        secure_zero(&a, sizeof(a));
        secure_zero(&b, sizeof(b));
        return ESP_ERR_INVALID_STATE;
    }
    s_prepare_record = valid_a && (!valid_b || a.journal_generation >= b.journal_generation) ? a : b;
    secure_zero(&a, sizeof(a));
    secure_zero(&b, sizeof(b));
    return ESP_OK;
}

static esp_err_t prepare_state_persist(const pm_prepare_record_t *candidate)
{
    if (candidate == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    pm_prepare_record_t record = *candidate;
    record.schema = PM_PREPARE_SCHEMA;
    record.journal_generation = s_prepare_record.journal_generation + 1U;
    if (record.journal_generation == 0U) {
        secure_zero(&record, sizeof(record));
        return ESP_ERR_INVALID_SIZE;
    }
    record.crc32 = prepare_record_crc(&record);
    if (!prepare_record_valid(&record)) {
        secure_zero(&record, sizeof(record));
        return ESP_ERR_INVALID_ARG;
    }
    nvs_handle_t handle = 0;
    esp_err_t error = nvs_open(PM_PREPARE_NAMESPACE, NVS_READWRITE, &handle);
    if (error == ESP_OK) {
        const char *key = (record.journal_generation & 1U) != 0U ? PM_PREPARE_SLOT_A : PM_PREPARE_SLOT_B;
        error = nvs_set_blob(handle, key, &record, sizeof(record));
    }
    if (error == ESP_OK) {
        error = nvs_commit(handle);
    }
    pm_prepare_record_t verified = {0};
    bool present = false;
    if (error == ESP_OK) {
        const char *key = (record.journal_generation & 1U) != 0U ? PM_PREPARE_SLOT_A : PM_PREPARE_SLOT_B;
        error = prepare_read_slot(handle, key, &verified, &present);
        if (error == ESP_OK && memcmp(&record, &verified, sizeof(record)) != 0) {
            error = ESP_FAIL;
        }
    }
    if (handle != 0) {
        nvs_close(handle);
    }
    if (error == ESP_OK) {
        s_prepare_record = record;
    }
        secure_zero(&record, sizeof(record));
    secure_zero(&verified, sizeof(verified));
    return error;
}

static void prepare_live_zeroize(void)
{
    pm_storage_cancel_format(&s_format);
    pm_storage_cancel_format(&s_reset.storage_format);
    secure_zero(s_format_prepare_command_id, sizeof(s_format_prepare_command_id));
    secure_zero(&s_reset, sizeof(s_reset));
}

static void prepare_state_zeroize(void)
{
    prepare_live_zeroize();
    secure_zero(&s_prepare_record, sizeof(s_prepare_record));
}

static esp_err_t prepare_state_erase_persisted(void)
{
    nvs_handle_t handle = 0;
    esp_err_t error = nvs_open(PM_PREPARE_NAMESPACE, NVS_READWRITE, &handle);
    if (error == ESP_OK) {
        const char *const keys[] = {PM_PREPARE_SLOT_A, PM_PREPARE_SLOT_B, PM_PREPARE_LEGACY_KEY};
        for (size_t i = 0U; i < sizeof(keys) / sizeof(keys[0]) && error == ESP_OK; ++i) {
            error = nvs_erase_key(handle, keys[i]);
            if (error == ESP_ERR_NVS_NOT_FOUND) {
                error = ESP_OK;
            }
        }
    }
    if (error == ESP_OK) {
        error = nvs_commit(handle);
    }
    if (handle != 0) {
        nvs_close(handle);
    }
    return error;
}

static esp_err_t prepare_state_clear(void)
{
    const esp_err_t error = prepare_state_erase_persisted();
    prepare_live_zeroize();
    if (error == ESP_OK) {
    secure_zero(&s_prepare_record, sizeof(s_prepare_record));
    } else {
        secure_zero(s_prepare_record.token, sizeof(s_prepare_record.token));
        secure_zero(s_prepare_record.boot_session, sizeof(s_prepare_record.boot_session));
    }
    return error;
}

static esp_err_t prepare_state_boot_load(void)
{
    esp_fill_random(s_prepare_boot_session, sizeof(s_prepare_boot_session));
    prepare_state_zeroize();
    const esp_err_t error = prepare_state_load();
    if (error == ESP_ERR_NOT_FOUND) {
        return prepare_state_erase_persisted();
    }
    if (error != ESP_OK) {
        return error;
    }
    if (s_prepare_record.phase == PM_PREPARE_PHASE_PREPARED) {
        return prepare_state_clear();
    }
    return ESP_OK;
}

static void prepare_state_expire_if_needed(void)
{
    const int64_t now_us = esp_timer_get_time();
    const bool record_expired = s_prepare_record.phase == PM_PREPARE_PHASE_PREPARED &&
                                (now_us < 0 || (uint64_t)now_us > s_prepare_record.expires_monotonic_us);
    if (record_expired) {
        if (prepare_state_clear() != ESP_OK) {
            ESP_LOGE(TAG, "expired destructive prepare NVS erase failed");
        } else {
            ESP_LOGI(TAG, "expired destructive prepare was zeroized and erased");
        }
    }
}

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
    if (error == ESP_ERR_NVS_NOT_FOUND) {
        secure_zero(&identity, sizeof(identity));
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
    } else if (error != ESP_OK) {
        nvs_close(handle);
        secure_zero(&identity, sizeof(identity));
        return error;
    } else if (size != sizeof(identity)) {
        nvs_close(handle);
        secure_zero(&identity, sizeof(identity));
        return ESP_ERR_INVALID_SIZE;
    } else if (identity.generation == 0U ||
               identity.crc32 != pm_crc32_ieee(&identity, offsetof(local_identity_t, crc32))) {
        nvs_close(handle);
        secure_zero(&identity, sizeof(identity));
        return ESP_ERR_INVALID_CRC;
    }
    nvs_close(handle);
    if (error == ESP_OK) {
        memcpy(device_id, identity.device_id, sizeof(identity.device_id));
    }
    secure_zero(&identity, sizeof(identity));
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
    const esp_err_t prior_error = nvs_get_blob(handle, "identity", &prior, &size);
    if (prior_error != ESP_OK && prior_error != ESP_ERR_NVS_NOT_FOUND) {
        nvs_close(handle);
        secure_zero(&prior, sizeof(prior));
        return prior_error;
    }
    if (prior_error == ESP_OK &&
        (size != sizeof(prior) || prior.generation == 0U || prior.generation == UINT32_MAX ||
         prior.crc32 != pm_crc32_ieee(&prior, offsetof(local_identity_t, crc32)))) {
        nvs_close(handle);
        secure_zero(&prior, sizeof(prior));
        return ESP_ERR_INVALID_CRC;
    }
    local_identity_t identity = {
        .generation = prior_error == ESP_ERR_NVS_NOT_FOUND ? 1U : prior.generation + 1U,
    };
    memcpy(identity.device_id, device_id, sizeof(identity.device_id));
    identity.crc32 = pm_crc32_ieee(&identity, offsetof(local_identity_t, crc32));
    error = nvs_set_blob(handle, "identity", &identity, sizeof(identity));
    if (error == ESP_OK) {
        error = nvs_commit(handle);
    }
    nvs_close(handle);
    secure_zero(&prior, sizeof(prior));
    secure_zero(&identity, sizeof(identity));
    return error;
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
    if (!begin_runtime_task(PM_MEASUREMENT_READY_BIT)) {
        vTaskDelete(NULL);
        return;
    }
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
    if (!begin_runtime_task(PM_INTERVAL_READY_BIT)) {
        vTaskDelete(NULL);
        return;
    }
    const uint32_t expected = (CONFIG_PM_DURABLE_INTERVAL_SECONDS * 1000U) / CONFIG_PM_METER_SAMPLE_MS;
    pm_interval_accumulator_t accumulator;
    pm_interval_init(&accumulator, expected);
    int64_t interval_started_us = esp_timer_get_time();
    for (;;) {
        pm_meter_sample_t sample = {0};
        if (xQueueReceive(s_sample_queue, &sample, pdMS_TO_TICKS(1000)) == pdTRUE) {
            (void)pm_interval_add(&accumulator, &sample, runtime_ct_rating_a());
        } else {
            accumulator.flags |= PM_INTERVAL_FLAG_MISSING_SAMPLE;
        }
        const int64_t now = esp_timer_get_time();
        if (now - interval_started_us >= (int64_t)CONFIG_PM_DURABLE_INTERVAL_SECONDS * INT64_C(1000000)) {
            pm_durable_interval_t interval;
            if (pm_interval_finalize(&accumulator, &interval,
                                     (uint64_t)runtime_ct_rating_a() * UINT64_C(300000))) {
                uint64_t sequence = 0U;
                if (pm_sequence_next(&s_sequence, &sequence) == ESP_OK) {
                    pm_journal_record_t record = {
                        .sequence = sequence,
                        .reset_generation = s_sequence.reset_generation,
                        .interval = interval,
                    };
                    copy_runtime_device_id(record.device_id);
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
        const char high = input[i * 2U];
        const char low = input[i * 2U + 1U];
        if ((!isdigit((unsigned char)high) && (high < 'a' || high > 'f')) ||
            (!isdigit((unsigned char)low) && (low < 'a' || low > 'f'))) {
            return false;
        }
        unsigned int byte = 0U;
        if (sscanf(&input[i * 2U], "%2x", &byte) != 1) {
            return false;
        }
        output[i] = (uint8_t)byte;
    }
    return true;
}

static bool json_u64(const cJSON *root, const char *name, uint64_t *value)
{
    const cJSON *item = cJSON_GetObjectItemCaseSensitive(root, name);
    if (!cJSON_IsNumber(item) || item->valuedouble < 0.0 ||
        item->valuedouble > 9007199254740991.0) {
        return false;
    }
    const uint64_t parsed = (uint64_t)item->valuedouble;
    if ((double)parsed != item->valuedouble) {
        return false;
    }
    *value = parsed;
    return true;
}

static pm_command_t *find_command_by_id(const char *command_id)
{
    if (command_id == NULL || strlen(command_id) != PM_COMMAND_ID_MAX) {
        return NULL;
    }
    for (size_t i = 0U; i < PM_COMMAND_LEDGER_SIZE; ++i) {
        if (strcmp(s_commands.entries[i].command_id, command_id) == 0) {
            return &s_commands.entries[i];
        }
    }
    return NULL;
}

static uint32_t rotation_record_crc(const pm_rotation_record_t *record)
{
    return pm_crc32_ieee(record, offsetof(pm_rotation_record_t, crc32));
}

static bool lowercase_hex_text(const char *value, size_t length)
{
    if (value == NULL || strlen(value) != length) {
        return false;
    }
    for (size_t i = 0U; i < length; ++i) {
        if (!isdigit((unsigned char)value[i]) && (value[i] < 'a' || value[i] > 'f')) {
            return false;
        }
    }
    return true;
}

static bool canonical_uuid_text(const char *value)
{
    if (value == NULL || strlen(value) != PM_COMMAND_ID_MAX) {
        return false;
    }
    for (size_t i = 0U; i < PM_COMMAND_ID_MAX; ++i) {
        if (i == 8U || i == 13U || i == 18U || i == 23U) {
            if (value[i] != '-') {
                return false;
            }
        } else if (!isdigit((unsigned char)value[i]) && (value[i] < 'a' || value[i] > 'f')) {
            return false;
        }
    }
    return true;
}

static bool rotation_record_valid(const pm_rotation_record_t *record)
{
    if (record == NULL || record->schema_version != PM_ROTATION_SCHEMA_VERSION ||
        record->journal_generation == 0U ||
        record->phase < PM_ROTATION_PHASE_CANDIDATE_PERSISTED ||
        record->phase > PM_ROTATION_PHASE_RESULT_ACKNOWLEDGED ||
        !canonical_uuid_text(record->rotation_id) ||
        !canonical_uuid_text(record->prepare_command_id) ||
        !lowercase_hex_text(record->credential_fingerprint, PM_SHA256_HEX_SIZE) ||
        record->overlap_expires_utc_ms < INT64_C(1704067200000) ||
        record->candidate_config_generation == 0U ||
        record->crc32 != rotation_record_crc(record)) {
        return false;
    }
    if (record->phase == PM_ROTATION_PHASE_CANDIDATE_PERSISTED) {
        return record->commit_command_id[0] == '\0' && record->candidate_slot == '\0' &&
               !bytes_are_zero(record->candidate_secret, sizeof(record->candidate_secret));
    }
    if (record->candidate_slot != 'A' && record->candidate_slot != 'B') {
        return false;
    }
    if (record->phase == PM_ROTATION_PHASE_CONFIG_STAGED) {
        return record->commit_command_id[0] == '\0' &&
               !bytes_are_zero(record->candidate_secret, sizeof(record->candidate_secret));
    }
    return canonical_uuid_text(record->commit_command_id) &&
           bytes_are_zero(record->candidate_secret, sizeof(record->candidate_secret));
}

static esp_err_t rotation_read_slot(nvs_handle_t handle, const char *key, pm_rotation_record_t *record,
                                    bool *present)
{
    size_t size = sizeof(*record);
    const esp_err_t error = nvs_get_blob(handle, key, record, &size);
    *present = error != ESP_ERR_NVS_NOT_FOUND;
    if (error != ESP_OK) {
        secure_zero(record, sizeof(*record));
        return error;
    }
    if (size != sizeof(*record) || !rotation_record_valid(record)) {
        secure_zero(record, sizeof(*record));
        return ESP_ERR_INVALID_CRC;
    }
    return ESP_OK;
}

static esp_err_t rotation_state_load(void)
{
    nvs_handle_t handle = 0;
    esp_err_t error = nvs_open(PM_ROTATION_NAMESPACE, NVS_READONLY, &handle);
    if (error == ESP_ERR_NVS_NOT_FOUND) {
        return ESP_ERR_NOT_FOUND;
    }
    if (error != ESP_OK) {
        return error;
    }
    pm_rotation_record_t a = {0};
    pm_rotation_record_t b = {0};
    bool present_a = false;
    bool present_b = false;
    const esp_err_t error_a = rotation_read_slot(handle, PM_ROTATION_SLOT_A, &a, &present_a);
    const esp_err_t error_b = rotation_read_slot(handle, PM_ROTATION_SLOT_B, &b, &present_b);
    nvs_close(handle);
    if ((error_a != ESP_OK && error_a != ESP_ERR_NVS_NOT_FOUND && error_a != ESP_ERR_INVALID_CRC) ||
        (error_b != ESP_OK && error_b != ESP_ERR_NVS_NOT_FOUND && error_b != ESP_ERR_INVALID_CRC)) {
        error = error_a != ESP_OK && error_a != ESP_ERR_NVS_NOT_FOUND && error_a != ESP_ERR_INVALID_CRC ?
                error_a : error_b;
        secure_zero(&a, sizeof(a));
        secure_zero(&b, sizeof(b));
        return error;
    }
    const bool valid_a = error_a == ESP_OK;
    const bool valid_b = error_b == ESP_OK;
    if (!valid_a && !valid_b) {
        secure_zero(&a, sizeof(a));
        secure_zero(&b, sizeof(b));
        return present_a || present_b ? ESP_ERR_INVALID_CRC : ESP_ERR_NOT_FOUND;
    }
    if (valid_a && valid_b && a.journal_generation == b.journal_generation &&
        memcmp(&a, &b, sizeof(a)) != 0) {
        secure_zero(&a, sizeof(a));
        secure_zero(&b, sizeof(b));
        return ESP_ERR_INVALID_STATE;
    }
    s_rotation_record = valid_a && (!valid_b || a.journal_generation >= b.journal_generation) ? a : b;
    secure_zero(&a, sizeof(a));
    secure_zero(&b, sizeof(b));
    return ESP_OK;
}

static esp_err_t rotation_state_persist(const pm_rotation_record_t *candidate)
{
    if (candidate == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    pm_rotation_record_t record = *candidate;
    record.schema_version = PM_ROTATION_SCHEMA_VERSION;
    record.journal_generation = s_rotation_record.journal_generation + 1U;
    if (record.journal_generation == 0U) {
        secure_zero(&record, sizeof(record));
        return ESP_ERR_INVALID_SIZE;
    }
    record.crc32 = rotation_record_crc(&record);
    if (!rotation_record_valid(&record)) {
        secure_zero(&record, sizeof(record));
        return ESP_ERR_INVALID_ARG;
    }
    nvs_handle_t handle = 0;
    esp_err_t error = nvs_open(PM_ROTATION_NAMESPACE, NVS_READWRITE, &handle);
    const char *key = (record.journal_generation & 1U) != 0U ? PM_ROTATION_SLOT_A : PM_ROTATION_SLOT_B;
    if (error == ESP_OK) {
        error = nvs_set_blob(handle, key, &record, sizeof(record));
    }
    if (error == ESP_OK) {
        error = nvs_commit(handle);
    }
    pm_rotation_record_t verified = {0};
    bool present = false;
    if (error == ESP_OK) {
        error = rotation_read_slot(handle, key, &verified, &present);
        if (error == ESP_OK && memcmp(&record, &verified, sizeof(record)) != 0) {
            error = ESP_FAIL;
        }
    }
    if (handle != 0) {
        nvs_close(handle);
    }
    if (error == ESP_OK) {
        s_rotation_record = record;
    }
    secure_zero(&record, sizeof(record));
    secure_zero(&verified, sizeof(verified));
    return error;
}

static esp_err_t rotation_state_erase_persisted(void)
{
    nvs_handle_t handle = 0;
    esp_err_t error = nvs_open(PM_ROTATION_NAMESPACE, NVS_READWRITE, &handle);
    if (error == ESP_OK) {
        const char *const keys[] = {PM_ROTATION_SLOT_A, PM_ROTATION_SLOT_B};
        for (size_t i = 0U; i < sizeof(keys) / sizeof(keys[0]) && error == ESP_OK; ++i) {
            error = nvs_erase_key(handle, keys[i]);
            if (error == ESP_ERR_NVS_NOT_FOUND) {
                error = ESP_OK;
            }
        }
    }
    if (error == ESP_OK) {
        error = nvs_commit(handle);
    }
    if (handle != 0) {
        nvs_close(handle);
    }
    return error;
}

static esp_err_t rotation_clear_prepared(void)
{
    if (s_rotation_record.phase >= PM_ROTATION_PHASE_COMMIT_INTENT_SECRET_ZEROIZED) {
        return ESP_ERR_INVALID_STATE;
    }
    esp_err_t error = ESP_OK;
    if (s_rotation_record.phase == PM_ROTATION_PHASE_CANDIDATE_PERSISTED) {
        error = pm_config_discard_inactive_generation(s_rotation_record.candidate_config_generation);
    } else if (s_rotation_record.phase == PM_ROTATION_PHASE_CONFIG_STAGED) {
        error = pm_config_discard_staged(s_rotation_record.candidate_slot,
                                         s_rotation_record.candidate_config_generation);
    }
    if (error == ESP_OK) {
        error = rotation_state_erase_persisted();
    }
    if (error == ESP_OK) {
        secure_zero(&s_rotation_record, sizeof(s_rotation_record));
    } else {
        /* Keep the transaction identity and phase fail-closed so a later
         * control-loop pass (or reboot from the valid journal slot) retries
         * cleanup.  Dropping the phase here could admit a second rotation
         * while an inactive candidate still exists. */
        return error;
    }
    return error;
}

static esp_err_t rotation_persist_phase(pm_rotation_phase_t phase)
{
    pm_rotation_record_t candidate = s_rotation_record;
    candidate.phase = (uint8_t)phase;
    const esp_err_t error = rotation_state_persist(&candidate);
    secure_zero(&candidate, sizeof(candidate));
    return error;
}

static bool rotation_fingerprint_matches(const uint8_t secret[PM_CONFIG_SECRET_MAX],
                                         const char expected[PM_SHA256_HEX_SIZE + 1U])
{
    uint8_t digest[PM_SHA256_SIZE] = {0};
    char fingerprint[PM_SHA256_HEX_SIZE + 1U] = {0};
    pm_sha256(secret, PM_CONFIG_SECRET_MAX, digest);
    pm_hex_lower(digest, sizeof(digest), fingerprint, sizeof(fingerprint));
    const bool matches = pm_constant_time_equal((const uint8_t *)fingerprint,
                                                (const uint8_t *)expected,
                                                PM_SHA256_HEX_SIZE);
    secure_zero(digest, sizeof(digest));
    secure_zero(fingerprint, sizeof(fingerprint));
    return matches;
}

static esp_err_t rotation_stage_candidate(void)
{
    if (s_rotation_record.phase != PM_ROTATION_PHASE_CANDIDATE_PERSISTED ||
        s_config.generation + 1U != s_rotation_record.candidate_config_generation ||
        s_rotation_record.candidate_config_generation == 0U) {
        return ESP_ERR_INVALID_STATE;
    }
    pm_config_t *candidate = allocate_config_scratch();
    if (candidate == NULL) {
        return ESP_ERR_NO_MEM;
    }
    *candidate = s_config;
    candidate->generation = s_rotation_record.candidate_config_generation;
    memcpy(candidate->device_secret, s_rotation_record.candidate_secret,
           sizeof(candidate->device_secret));
    candidate->device_secret_len = PM_CONFIG_SECRET_MAX;
    pm_config_transaction_t transaction = {0};
    esp_err_t error = pm_config_begin(candidate, &transaction);
    if (error == ESP_OK) {
        pm_rotation_record_t record = s_rotation_record;
        record.phase = PM_ROTATION_PHASE_CONFIG_STAGED;
        record.candidate_slot = transaction.candidate_slot;
        error = rotation_state_persist(&record);
        secure_zero(&record, sizeof(record));
    }
    pm_config_abort(&transaction);
    free_config_scratch(candidate);
    return error;
}

static esp_err_t rotation_persist_prepare_result(void)
{
    pm_command_t *command = find_command_by_id(s_rotation_record.prepare_command_id);
    if (command == NULL || command->type != PM_COMMAND_ROTATE_DEVICE_CREDENTIALS) {
        return ESP_ERR_NOT_FOUND;
    }
    if (command->state == PM_COMMAND_SUCCEEDED) {
        return ESP_OK;
    }
    if (command->state != PM_COMMAND_RUNNING && command->state != PM_COMMAND_ACCEPTED) {
        return ESP_ERR_INVALID_STATE;
    }
    (void)snprintf(command->evidence_json, sizeof(command->evidence_json),
                   "{\"rotation_id\":\"%s\",\"credential_fingerprint\":\"%s\",\"ready\":true}",
                   s_rotation_record.rotation_id, s_rotation_record.credential_fingerprint);
    (void)snprintf(command->result_text, sizeof(command->result_text), "credential_rotation_prepared");
    return pm_command_transition(&s_commands, command, PM_COMMAND_SUCCEEDED, 100U, ESP_OK);
}

static esp_err_t rotation_activate_candidate(void)
{
    if (s_rotation_record.phase != PM_ROTATION_PHASE_COMMIT_INTENT_SECRET_ZEROIZED) {
        return ESP_ERR_INVALID_STATE;
    }
    pm_config_t *candidate = allocate_config_scratch();
    if (candidate == NULL) {
        return ESP_ERR_NO_MEM;
    }
    esp_err_t error = pm_config_load_staged(s_rotation_record.candidate_slot,
                                            s_rotation_record.candidate_config_generation,
                                            candidate);
    if (error == ESP_OK &&
        (candidate->device_secret_len != PM_CONFIG_SECRET_MAX ||
         !rotation_fingerprint_matches(candidate->device_secret,
                                       s_rotation_record.credential_fingerprint))) {
        error = ESP_ERR_INVALID_CRC;
    }
    if (error == ESP_OK) {
        error = pm_config_activate_staged(s_rotation_record.candidate_slot,
                                          s_rotation_record.candidate_config_generation);
    }
    if (error == ESP_OK) {
        secure_zero(candidate, sizeof(*candidate));
        error = pm_config_load(candidate);
        if (error == ESP_OK &&
            (candidate->generation != s_rotation_record.candidate_config_generation ||
             candidate->device_secret_len != PM_CONFIG_SECRET_MAX ||
             !rotation_fingerprint_matches(candidate->device_secret,
                                           s_rotation_record.credential_fingerprint))) {
            error = ESP_ERR_INVALID_CRC;
        }
        if (error == ESP_OK) {
            s_config = *candidate;
            update_runtime_measurement_config(candidate);
            error = pm_network_apply_runtime_config(&s_network, candidate);
        }
    }
    if (error == ESP_OK) {
        error = rotation_persist_phase(PM_ROTATION_PHASE_CONFIG_ACTIVATED);
    }
    free_config_scratch(candidate);
    return error;
}

static esp_err_t rotation_persist_commit_result(void)
{
    pm_command_t *command = find_command_by_id(s_rotation_record.commit_command_id);
    if (command == NULL || command->type != PM_COMMAND_ROTATE_DEVICE_CREDENTIALS) {
        return ESP_ERR_NOT_FOUND;
    }
    if (command->state != PM_COMMAND_SUCCEEDED) {
        if (command->state != PM_COMMAND_RUNNING && command->state != PM_COMMAND_ACCEPTED) {
            return ESP_ERR_INVALID_STATE;
        }
        (void)snprintf(command->evidence_json, sizeof(command->evidence_json),
                       "{\"rotation_id\":\"%s\",\"credential_fingerprint\":\"%s\",\"activated\":true}",
                       s_rotation_record.rotation_id, s_rotation_record.credential_fingerprint);
        (void)snprintf(command->result_text, sizeof(command->result_text), "credential_rotation_activated");
        command->result_ack_required = true;
        const esp_err_t error = pm_command_transition(&s_commands, command, PM_COMMAND_SUCCEEDED, 100U, ESP_OK);
        if (error != ESP_OK) {
            return error;
        }
    }
    return rotation_persist_phase(PM_ROTATION_PHASE_COMMAND_RESULT_DURABLE);
}

static esp_err_t resume_rotation_transaction(void)
{
    esp_err_t error = ESP_OK;
    if (s_rotation_record.phase >= PM_ROTATION_PHASE_CANDIDATE_PERSISTED &&
        s_rotation_record.phase <= PM_ROTATION_PHASE_CONFIG_STAGED) {
        int64_t now_utc_ms = 0;
        if (!pm_time_now(&s_time, esp_timer_get_time(), &now_utc_ms) ||
            now_utc_ms > s_rotation_record.overlap_expires_utc_ms) {
            /* A rebooted prepare is dormant until UTC is trustworthy.  An
             * expired candidate is handled by rotation_expire_if_needed;
             * neither condition is authorization to progress the journal. */
            return ESP_OK;
        }
        pm_command_t *prepare = find_command_by_id(s_rotation_record.prepare_command_id);
        if (prepare == NULL) {
            return ESP_ERR_NOT_FOUND;
        }
        if (!prepare->payload_redacted || s_rotation_payload_redaction_retry) {
            error = pm_command_zeroize_payload(&s_commands, prepare);
            s_rotation_payload_redaction_retry = error != ESP_OK;
        }
    }
    if (error == ESP_OK && s_rotation_record.phase == PM_ROTATION_PHASE_CANDIDATE_PERSISTED) {
        error = rotation_stage_candidate();
    }
    if (error == ESP_OK && s_rotation_record.phase == PM_ROTATION_PHASE_CONFIG_STAGED) {
        error = rotation_persist_prepare_result();
    }
    if (error == ESP_OK && s_rotation_record.phase == PM_ROTATION_PHASE_COMMIT_INTENT_SECRET_ZEROIZED) {
        error = rotation_activate_candidate();
    }
    if (error == ESP_OK && s_rotation_record.phase == PM_ROTATION_PHASE_CONFIG_ACTIVATED) {
        error = rotation_persist_commit_result();
    }
    return error;
}

static esp_err_t rotation_state_boot_load(void)
{
    secure_zero(&s_rotation_record, sizeof(s_rotation_record));
    const esp_err_t error = rotation_state_load();
    if (error == ESP_ERR_NOT_FOUND) {
        return rotation_state_erase_persisted();
    }
    return error;
}

static esp_err_t rotation_expire_if_needed(void)
{
    if (s_rotation_record.phase < PM_ROTATION_PHASE_CANDIDATE_PERSISTED ||
        s_rotation_record.phase >= PM_ROTATION_PHASE_COMMIT_INTENT_SECRET_ZEROIZED) {
        return ESP_OK;
    }
    int64_t now_utc_ms = 0;
    if (!pm_time_now(&s_time, esp_timer_get_time(), &now_utc_ms)) {
        return ESP_OK;
    }
    if (now_utc_ms > s_rotation_record.overlap_expires_utc_ms) {
        const esp_err_t error = rotation_clear_prepared();
        if (error != ESP_OK) {
            ESP_LOGE(TAG, "expired credential candidate zeroization failed closed");
        } else {
            ESP_LOGI(TAG, "expired credential candidate was zeroized and erased");
        }
        return error;
    }
    return ESP_OK;
}

static esp_err_t rotation_cleanup_acknowledged(void)
{
    if (s_rotation_record.phase != PM_ROTATION_PHASE_RESULT_ACKNOWLEDGED) {
        return ESP_ERR_INVALID_STATE;
    }
    esp_err_t error = pm_command_acknowledge_result(&s_commands, s_rotation_record.commit_command_id);
    if (error == ESP_ERR_NOT_FOUND) {
        /* RESULT_ACKNOWLEDGED is itself durable.  The now-unpinned ledger
         * entry may have been reused after a prior partial cleanup. */
        error = ESP_OK;
    }
    if (error == ESP_OK) {
        error = pm_config_erase_inactive();
    }
    if (error == ESP_OK) {
        error = rotation_state_erase_persisted();
    }
    if (error == ESP_OK) {
        secure_zero(&s_rotation_record, sizeof(s_rotation_record));
    }
    return error;
}

static esp_err_t destructive_cleanup_acknowledged(void)
{
    if (s_prepare_record.phase != PM_PREPARE_PHASE_RESULT_ACKNOWLEDGED) {
        return ESP_ERR_INVALID_STATE;
    }
    esp_err_t error = pm_command_acknowledge_result(&s_commands, s_prepare_record.commit_command_id);
    if (error == ESP_ERR_NOT_FOUND) {
        error = ESP_OK;
    }
    if (error == ESP_OK) {
        error = prepare_state_clear();
    }
    return error;
}

static esp_err_t persist_prepare_phase(pm_prepare_phase_t phase)
{
    pm_prepare_record_t candidate = s_prepare_record;
    candidate.phase = (uint8_t)phase;
    const esp_err_t error = prepare_state_persist(&candidate);
    secure_zero(&candidate, sizeof(candidate));
    return error;
}

static esp_err_t begin_durable_commit_intent(pm_prepare_kind_t kind, pm_command_t *command)
{
    if (command == NULL || s_prepare_record.kind != (uint8_t)kind ||
        s_prepare_record.phase != PM_PREPARE_PHASE_PREPARED ||
        strlen(command->command_id) != PM_COMMAND_ID_MAX) {
        return ESP_ERR_INVALID_STATE;
    }
    pm_prepare_record_t candidate = s_prepare_record;
    candidate.phase = PM_PREPARE_PHASE_COMMIT_INTENT_TOKEN_ZEROIZED;
    (void)snprintf(candidate.commit_command_id, sizeof(candidate.commit_command_id), "%s",
                   command->command_id);
    secure_zero(candidate.token, sizeof(candidate.token));
    secure_zero(candidate.boot_session, sizeof(candidate.boot_session));
    const esp_err_t error = prepare_state_persist(&candidate);
    secure_zero(&candidate, sizeof(candidate));
    if (error == ESP_OK) {
        prepare_live_zeroize();
    }
    return error;
}

static esp_err_t persist_reset_configuration(const pm_prepare_record_t *record)
{
    if (record == NULL || record->kind != PM_PREPARE_KIND_DATA_RESET) {
        return ESP_ERR_INVALID_ARG;
    }
    if (s_config.reset_generation == record->reset_generation &&
        s_config.sequence_floor == record->internal_sequence_floor &&
        s_config.acknowledged_sequence == record->internal_sequence_floor) {
        return ESP_OK;
    }
    if (s_config.reset_generation >= record->reset_generation ||
        s_config.sequence_floor > record->internal_sequence_floor ||
        s_config.acknowledged_sequence > record->internal_sequence_floor) {
        return ESP_ERR_INVALID_STATE;
    }
    pm_config_t *candidate = allocate_config_scratch();
    if (candidate == NULL) {
        return ESP_ERR_NO_MEM;
    }
    *candidate = s_config;
    candidate->sequence_floor = record->internal_sequence_floor;
    candidate->acknowledged_sequence = record->internal_sequence_floor;
    candidate->reset_generation = record->reset_generation;
    pm_config_transaction_t transaction = {0};
    esp_err_t error = pm_config_begin(candidate, &transaction);
    if (error == ESP_OK) {
        error = pm_config_mark_network_tested(&transaction);
    }
    if (error == ESP_OK) {
        error = pm_config_commit(&transaction);
    }
    if (error == ESP_OK) {
        s_config = *candidate;
        update_runtime_measurement_config(candidate);
        error = pm_network_apply_runtime_config(&s_network, candidate);
    } else {
        pm_config_abort(&transaction);
    }
    free_config_scratch(candidate);
    return error;
}

static esp_err_t persist_destructive_command_result(pm_prepare_record_t *record, pm_command_t *command)
{
    if (record == NULL || command == NULL || strcmp(command->command_id, record->commit_command_id) != 0) {
        return ESP_ERR_INVALID_ARG;
    }
    if ((record->kind == PM_PREPARE_KIND_FORMAT_STORAGE && command->type != PM_COMMAND_FORMAT_STORAGE_COMMIT) ||
        (record->kind == PM_PREPARE_KIND_DATA_RESET && command->type != PM_COMMAND_DATA_RESET_COMMIT) ||
        (command->state != PM_COMMAND_RUNNING && command->state != PM_COMMAND_SUCCEEDED)) {
        return ESP_ERR_INVALID_STATE;
    }
    if (record->kind == PM_PREPARE_KIND_FORMAT_STORAGE) {
        (void)snprintf(command->evidence_json, sizeof(command->evidence_json),
                       "{\"prepare_command_id\":\"%s\",\"acknowledged_records_lost\":%llu,"
                       "\"unacknowledged_records_lost\":%llu,\"formatted\":true}",
                       record->prepare_command_id,
                       (unsigned long long)record->acknowledged_records_lost,
                       (unsigned long long)record->unacknowledged_records_lost);
        (void)snprintf(command->result_text, sizeof(command->result_text), "storage_formatted");
    } else {
        (void)snprintf(command->evidence_json, sizeof(command->evidence_json),
                       "{\"prepare_command_id\":\"%s\",\"reset_generation\":%lu,"
                       "\"sequence_floor\":%llu}",
                       record->prepare_command_id, (unsigned long)record->reset_generation,
                       (unsigned long long)record->internal_sequence_floor);
        (void)snprintf(command->result_text, sizeof(command->result_text), "data_reset_committed");
    }
    command->result_ack_required = true;
    return pm_command_transition(&s_commands, command, PM_COMMAND_SUCCEEDED, 100U, ESP_OK);
}

static esp_err_t resume_destructive_transaction(void)
{
    if (s_prepare_record.phase < PM_PREPARE_PHASE_COMMIT_INTENT_TOKEN_ZEROIZED ||
        s_prepare_record.phase >= PM_PREPARE_PHASE_COMMAND_RESULT_DURABLE) {
        return ESP_OK;
    }
    pm_command_t *command = find_command_by_id(s_prepare_record.commit_command_id);
    if (command == NULL) {
        return ESP_ERR_NOT_FOUND;
    }
    esp_err_t error = ESP_OK;
    if (s_prepare_record.kind == PM_PREPARE_KIND_DATA_RESET &&
        s_prepare_record.phase == PM_PREPARE_PHASE_COMMIT_INTENT_TOKEN_ZEROIZED) {
        error = pm_sequence_raise_floor(&s_sequence, s_prepare_record.internal_sequence_floor,
                                        s_prepare_record.reset_generation);
        if (error == ESP_OK) {
            s_storage.acknowledged_sequence = s_sequence.acknowledged;
            error = persist_prepare_phase(PM_PREPARE_PHASE_RESET_SEQUENCE_FLOOR_DURABLE);
        }
    }
    const bool storage_due =
        (s_prepare_record.kind == PM_PREPARE_KIND_FORMAT_STORAGE &&
         s_prepare_record.phase == PM_PREPARE_PHASE_COMMIT_INTENT_TOKEN_ZEROIZED) ||
        (s_prepare_record.kind == PM_PREPARE_KIND_DATA_RESET &&
         s_prepare_record.phase == PM_PREPARE_PHASE_RESET_SEQUENCE_FLOOR_DURABLE);
    if (error == ESP_OK && storage_due) {
        error = pm_storage_recover_authenticated_format();
        if (error == ESP_OK) {
            error = persist_prepare_phase(PM_PREPARE_PHASE_STORAGE_FORMAT_DURABLE);
        }
    }
    if (error == ESP_OK && s_prepare_record.kind == PM_PREPARE_KIND_DATA_RESET &&
        s_prepare_record.phase == PM_PREPARE_PHASE_STORAGE_FORMAT_DURABLE) {
        error = persist_reset_configuration(&s_prepare_record);
        if (error == ESP_OK) {
            error = persist_prepare_phase(PM_PREPARE_PHASE_RESET_CONFIG_DURABLE);
        }
    }
    const bool result_due =
        (s_prepare_record.kind == PM_PREPARE_KIND_FORMAT_STORAGE &&
         s_prepare_record.phase == PM_PREPARE_PHASE_STORAGE_FORMAT_DURABLE) ||
        (s_prepare_record.kind == PM_PREPARE_KIND_DATA_RESET &&
         s_prepare_record.phase == PM_PREPARE_PHASE_RESET_CONFIG_DURABLE);
    if (error == ESP_OK && result_due) {
        error = persist_destructive_command_result(&s_prepare_record, command);
        if (error == ESP_OK) {
            error = persist_prepare_phase(PM_PREPARE_PHASE_COMMAND_RESULT_DURABLE);
        }
    }
    return error;
}

static void process_authenticated_result_acknowledgements(void)
{
    if (s_result_ack_queue == NULL) {
        return;
    }
    pm_result_ack_event_t acknowledged = {0};
    while (xQueueReceive(s_result_ack_queue, &acknowledged, 0U) == pdTRUE) {
        if (s_prepare_record.phase == PM_PREPARE_PHASE_COMMAND_RESULT_DURABLE &&
            strcmp(acknowledged.command_id, s_prepare_record.commit_command_id) == 0) {
            if (persist_prepare_phase(PM_PREPARE_PHASE_RESULT_ACKNOWLEDGED) != ESP_OK ||
                destructive_cleanup_acknowledged() != ESP_OK) {
                ESP_LOGE(TAG, "authenticated destructive result acknowledgement persistence failed");
            }
        }
        if (s_rotation_record.phase == PM_ROTATION_PHASE_COMMAND_RESULT_DURABLE &&
            strcmp(acknowledged.command_id, s_rotation_record.commit_command_id) == 0) {
            if (rotation_persist_phase(PM_ROTATION_PHASE_RESULT_ACKNOWLEDGED) != ESP_OK ||
                rotation_cleanup_acknowledged() != ESP_OK) {
                ESP_LOGE(TAG, "authenticated credential-rotation result acknowledgement cleanup failed");
            }
        }
        memset(&acknowledged, 0, sizeof(acknowledged));
    }
}

static esp_err_t credential_rotation_prepare(pm_command_t *command, const cJSON *root,
                                             bool *durable_completion_pending)
{
    const cJSON *schema = cJSON_GetObjectItemCaseSensitive(root, "schema");
    const cJSON *rotation_id = cJSON_GetObjectItemCaseSensitive(root, "rotation_id");
    const cJSON *secret = cJSON_GetObjectItemCaseSensitive(root, "device_secret_hex");
    const cJSON *fingerprint = cJSON_GetObjectItemCaseSensitive(root, "credential_fingerprint");
    const cJSON *overlap = cJSON_GetObjectItemCaseSensitive(root, "overlap_expires_at");
    uint8_t decoded[PM_CONFIG_SECRET_MAX] = {0};
    int64_t overlap_expires_utc_ms = 0;
    int64_t now_utc_ms = 0;
    esp_err_t result = ESP_OK;
    if (cJSON_GetArraySize(root) != 5 || !cJSON_IsString(schema) ||
        strcmp(schema->valuestring, PM_ROTATION_CONTRACT) != 0 ||
        !cJSON_IsString(rotation_id) || !canonical_uuid_text(rotation_id->valuestring) ||
        !cJSON_IsString(secret) || !lowercase_hex_text(secret->valuestring, PM_SHA256_HEX_SIZE) ||
        !cJSON_IsString(fingerprint) ||
        !lowercase_hex_text(fingerprint->valuestring, PM_SHA256_HEX_SIZE) ||
        !cJSON_IsString(overlap) ||
        !pm_network_parse_rfc3339_ms(overlap->valuestring, &overlap_expires_utc_ms)) {
        result = ESP_ERR_INVALID_ARG;
    } else if (!pm_time_now(&s_time, esp_timer_get_time(), &now_utc_ms)) {
        result = ESP_ERR_INVALID_STATE;
    } else if (now_utc_ms > command->expires_utc_ms || overlap_expires_utc_ms <= now_utc_ms) {
        result = ESP_ERR_TIMEOUT;
    } else if (s_rotation_record.phase != PM_ROTATION_PHASE_NONE ||
               s_prepare_record.phase != PM_PREPARE_PHASE_NONE ||
               s_config.generation == UINT32_MAX) {
        result = ESP_ERR_INVALID_STATE;
    } else if (!hex_decode(secret->valuestring, decoded, sizeof(decoded)) ||
               !rotation_fingerprint_matches(decoded, fingerprint->valuestring)) {
        result = ESP_ERR_INVALID_CRC;
    } else {
        pm_rotation_record_t record = {
            .schema_version = PM_ROTATION_SCHEMA_VERSION,
            .phase = PM_ROTATION_PHASE_CANDIDATE_PERSISTED,
            .overlap_expires_utc_ms = overlap_expires_utc_ms,
            .candidate_config_generation = s_config.generation + 1U,
        };
        (void)snprintf(record.rotation_id, sizeof(record.rotation_id), "%s", rotation_id->valuestring);
        (void)snprintf(record.prepare_command_id, sizeof(record.prepare_command_id), "%s", command->command_id);
        (void)snprintf(record.credential_fingerprint, sizeof(record.credential_fingerprint), "%s",
                       fingerprint->valuestring);
        memcpy(record.candidate_secret, decoded, sizeof(record.candidate_secret));
        result = rotation_state_persist(&record);
        secure_zero(&record, sizeof(record));
        if (result == ESP_OK) {
            result = resume_rotation_transaction();
            *durable_completion_pending = result != ESP_OK;
        }
    }
    secure_zero(decoded, sizeof(decoded));
    return result;
}

static esp_err_t credential_rotation_commit(pm_command_t *command, const cJSON *root,
                                            bool *durable_completion_pending)
{
    const cJSON *schema = cJSON_GetObjectItemCaseSensitive(root, "schema");
    const cJSON *rotation_id = cJSON_GetObjectItemCaseSensitive(root, "rotation_id");
    const cJSON *fingerprint = cJSON_GetObjectItemCaseSensitive(root, "credential_fingerprint");
    int64_t now_utc_ms = 0;
    if (cJSON_GetArraySize(root) != 3 || !cJSON_IsString(schema) ||
        strcmp(schema->valuestring, PM_ROTATION_CONTRACT) != 0 ||
        !cJSON_IsString(rotation_id) || !canonical_uuid_text(rotation_id->valuestring) ||
        !cJSON_IsString(fingerprint) ||
        !lowercase_hex_text(fingerprint->valuestring, PM_SHA256_HEX_SIZE)) {
        return ESP_ERR_INVALID_ARG;
    }
    if (!pm_time_now(&s_time, esp_timer_get_time(), &now_utc_ms)) {
        return ESP_ERR_INVALID_STATE;
    }
    if (now_utc_ms > command->expires_utc_ms || now_utc_ms > s_rotation_record.overlap_expires_utc_ms) {
        if (s_rotation_record.phase > PM_ROTATION_PHASE_NONE &&
            s_rotation_record.phase < PM_ROTATION_PHASE_COMMIT_INTENT_SECRET_ZEROIZED) {
            (void)rotation_clear_prepared();
        }
        return ESP_ERR_TIMEOUT;
    }
    if (s_rotation_record.phase != PM_ROTATION_PHASE_CONFIG_STAGED ||
        !pm_constant_time_equal((const uint8_t *)rotation_id->valuestring,
                                (const uint8_t *)s_rotation_record.rotation_id,
                                PM_COMMAND_ID_MAX) ||
        !pm_constant_time_equal((const uint8_t *)fingerprint->valuestring,
                                (const uint8_t *)s_rotation_record.credential_fingerprint,
                                PM_SHA256_HEX_SIZE)) {
        return ESP_ERR_INVALID_CRC;
    }
    pm_config_t *staged = allocate_config_scratch();
    if (staged == NULL) {
        return ESP_ERR_NO_MEM;
    }
    esp_err_t result = pm_config_load_staged(s_rotation_record.candidate_slot,
                                             s_rotation_record.candidate_config_generation,
                                             staged);
    if (result == ESP_OK &&
        (staged->device_secret_len != PM_CONFIG_SECRET_MAX ||
         !rotation_fingerprint_matches(staged->device_secret,
                                       s_rotation_record.credential_fingerprint))) {
        result = ESP_ERR_INVALID_CRC;
    }
    free_config_scratch(staged);
    if (result != ESP_OK) {
        return result;
    }
    pm_rotation_record_t intent = s_rotation_record;
    intent.phase = PM_ROTATION_PHASE_COMMIT_INTENT_SECRET_ZEROIZED;
    (void)snprintf(intent.commit_command_id, sizeof(intent.commit_command_id), "%s", command->command_id);
    secure_zero(intent.candidate_secret, sizeof(intent.candidate_secret));
    result = rotation_state_persist(&intent);
    secure_zero(&intent, sizeof(intent));
    if (result == ESP_OK) {
        result = resume_rotation_transaction();
        *durable_completion_pending = result != ESP_OK;
    }
    return result;
}

static esp_err_t credential_rotation_cancel(pm_command_t *command, const cJSON *root)
{
    const cJSON *schema = cJSON_GetObjectItemCaseSensitive(root, "schema");
    const cJSON *rotation_id = cJSON_GetObjectItemCaseSensitive(root, "rotation_id");
    const cJSON *cancelled = cJSON_GetObjectItemCaseSensitive(root, "cancelled");
    if (cJSON_GetArraySize(root) != 3 || !cJSON_IsString(schema) ||
        strcmp(schema->valuestring, PM_ROTATION_CONTRACT) != 0 ||
        !cJSON_IsString(rotation_id) || !canonical_uuid_text(rotation_id->valuestring) ||
        !cJSON_IsTrue(cancelled)) {
        return ESP_ERR_INVALID_ARG;
    }
    if (s_rotation_record.phase < PM_ROTATION_PHASE_CANDIDATE_PERSISTED ||
        s_rotation_record.phase >= PM_ROTATION_PHASE_COMMIT_INTENT_SECRET_ZEROIZED ||
        !pm_constant_time_equal((const uint8_t *)rotation_id->valuestring,
                                (const uint8_t *)s_rotation_record.rotation_id,
                                PM_COMMAND_ID_MAX)) {
        return ESP_ERR_INVALID_STATE;
    }
    const esp_err_t result = rotation_clear_prepared();
    if (result == ESP_OK) {
        (void)snprintf(command->evidence_json, sizeof(command->evidence_json),
                       "{\"rotation_id\":\"%s\",\"cancelled\":true}", rotation_id->valuestring);
        (void)snprintf(command->result_text, sizeof(command->result_text), "credential_rotation_cancelled");
    }
    return result;
}

static void ota_progress(uint8_t percent, pm_ota_stage_t stage, void *context)
{
    pm_command_t *command = (pm_command_t *)context;
    if (command != NULL && pm_commands_lock() == ESP_OK) {
        (void)snprintf(command->result_text, sizeof(command->result_text), "ota_stage=%u", (unsigned)stage);
        (void)pm_command_transition(&s_commands, command, PM_COMMAND_RUNNING, percent, ESP_OK);
        pm_commands_unlock();
    }
}

static void ota_task(void *argument)
{
    pm_ota_task_context_t *task = (pm_ota_task_context_t *)argument;
    if (task == NULL || task->command == NULL) {
        free_ota_task_context(task);
        release_ota_task();
        vTaskDelete(NULL);
        return;
    }
    pm_command_t *command = task->command;
    pm_ota_manifest_t manifest;
    int64_t utc_ms = 0;
    esp_err_t result = pm_ota_manifest_parse_payload(command->payload, task->auth.server_origin,
                                                     task->auth.device_id_text, &manifest);
    if (result == ESP_OK && !pm_time_now(&s_time, esp_timer_get_time(), &utc_ms)) {
        result = ESP_ERR_INVALID_STATE;
    }
    if (result == ESP_OK) {
        result = pm_ota_install(&manifest, task->auth.ca_pem, task->auth.device_to_server_key,
                                task->auth.server_to_device_key, utc_ms, ota_progress, command);
    }
    if (result == ESP_OK) {
        result = pm_storage_flush(3000U);
    }
    if (result == ESP_OK) {
        result = pm_command_transition(&s_commands, command, PM_COMMAND_AWAITING_REBOOT, 100U, ESP_OK);
    }
    if (result == ESP_OK) {
        free_ota_task_context(task);
        vTaskDelay(pdMS_TO_TICKS(500));
        esp_restart();
    } else {
        const esp_err_t cancellation = pm_ota_cancel_pending_boot(result);
        if (cancellation != ESP_OK) {
            ESP_LOGE(TAG, "OTA boot-selection cancellation failed; no intentional reboot: %s",
                     esp_err_to_name(cancellation));
        }
        pm_network_health_update(&s_network, PM_HEALTH_OTA_FAILED, true);
        (void)pm_command_transition(&s_commands, command, PM_COMMAND_FAILED, command->progress_percent, result);
        free_ota_task_context(task);
        release_ota_task();
    }
    vTaskDelete(NULL);
}

static void execute_command(pm_command_t *command)
{
    if (command == NULL || pm_commands_lock() != ESP_OK) {
        return;
    }
    process_authenticated_result_acknowledgements();
    (void)pm_command_transition(&s_commands, command, PM_COMMAND_RUNNING, 1U, ESP_OK);
    esp_err_t result = ESP_OK;
    bool durable_completion_pending = false;
    switch (command->type) {
    case PM_COMMAND_REBOOT:
        result = pm_storage_flush(3000U);
        if (result == ESP_OK) {
            result = pm_command_transition(&s_commands, command, PM_COMMAND_AWAITING_REBOOT, 100U, ESP_OK);
        }
        if (result == ESP_OK) {
            vTaskDelay(pdMS_TO_TICKS(500));
            esp_restart();
        }
        break;
    case PM_COMMAND_MAINTENANCE_SLEEP: {
        unsigned long seconds = strtoul(command->payload, NULL, 10);
        if (seconds < 10U || seconds > 3600U) {
            result = ESP_ERR_INVALID_ARG;
            break;
        }
        result = pm_storage_flush(3000U);
        if (result == ESP_OK) {
            result = pm_command_transition(&s_commands, command, PM_COMMAND_AWAITING_HEARTBEAT, 100U, ESP_OK);
        }
        if (result == ESP_OK) {
            esp_sleep_enable_timer_wakeup((uint64_t)seconds * UINT64_C(1000000));
            esp_deep_sleep_start();
        }
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
        cJSON *root = cJSON_Parse(command->payload);
        const cJSON *token = root == NULL ? NULL : cJSON_GetObjectItemCaseSensitive(root, "confirmation_token");
        uint8_t decoded[16] = {0};
        uint64_t acknowledged_lost = 0U;
        uint64_t unacknowledged_lost = 0U;
        const bool durable_transaction_active =
            s_prepare_record.phase >= PM_PREPARE_PHASE_COMMIT_INTENT_TOKEN_ZEROIZED ||
            s_rotation_record.phase != PM_ROTATION_PHASE_NONE;
        const esp_err_t clear_error = durable_transaction_active ? ESP_ERR_INVALID_STATE : prepare_state_clear();
        if (root == NULL || cJSON_GetArraySize(root) != 1 || !cJSON_IsString(token) ||
            !hex_decode(token->valuestring, decoded, sizeof(decoded))) {
            result = ESP_ERR_INVALID_ARG;
        } else if (clear_error != ESP_OK) {
            result = clear_error;
        } else {
            const uint64_t now_us = (uint64_t)esp_timer_get_time();
            const uint64_t expires_us = now_us + PM_PREPARE_EXPIRY_US;
            result = pm_storage_prepare_format(now_us, expires_us, decoded, &s_format);
            acknowledged_lost = s_format.acknowledged_records_lost;
            unacknowledged_lost = s_format.unacknowledged_records_lost;
            if (result == ESP_OK) {
                (void)snprintf(s_format_prepare_command_id, sizeof(s_format_prepare_command_id), "%s",
                               command->command_id);
                pm_prepare_record_t record = {
                    .schema = PM_PREPARE_SCHEMA,
                    .kind = PM_PREPARE_KIND_FORMAT_STORAGE,
                    .phase = PM_PREPARE_PHASE_PREPARED,
                    .expires_monotonic_us = expires_us,
                    .acknowledged_records_lost = acknowledged_lost,
                    .unacknowledged_records_lost = unacknowledged_lost,
                };
                memcpy(record.boot_session, s_prepare_boot_session, sizeof(record.boot_session));
                memcpy(record.token, decoded, sizeof(record.token));
                (void)snprintf(record.prepare_command_id, sizeof(record.prepare_command_id), "%s",
                               command->command_id);
                result = prepare_state_persist(&record);
    secure_zero(&record, sizeof(record));
            }
        }
        if (result == ESP_OK) {
            (void)snprintf(s_format_prepare_command_id, sizeof(s_format_prepare_command_id), "%s",
                           command->command_id);
            (void)snprintf(command->evidence_json, sizeof(command->evidence_json),
                           "{\"prepare_command_id\":\"%s\",\"acknowledged_records_lost\":%llu,"
                           "\"unacknowledged_records_lost\":%llu,\"ready\":true}",
                           command->command_id, (unsigned long long)acknowledged_lost,
                           (unsigned long long)unacknowledged_lost);
            (void)snprintf(command->result_text, sizeof(command->result_text), "format_prepare_ready");
        } else {
            if (!durable_transaction_active) {
                (void)prepare_state_clear();
            }
            (void)snprintf(command->evidence_json, sizeof(command->evidence_json),
                           "{\"prepare_command_id\":\"%s\",\"ready\":false,\"reason\":\"%s\"}",
                           command->command_id,
                           result == ESP_ERR_INVALID_ARG ? "invalid_payload" :
                           durable_transaction_active ? "durable_commit_active" : "prepare_state_io_failed");
        }
        secure_zero(decoded, sizeof(decoded));
        zeroize_json_string(root, "confirmation_token");
        cJSON_Delete(root);
        break;
    }
    case PM_COMMAND_FORMAT_STORAGE_COMMIT: {
        cJSON *root = cJSON_Parse(command->payload);
        const cJSON *prepare_id = root == NULL ? NULL : cJSON_GetObjectItemCaseSensitive(root, "prepare_command_id");
        const cJSON *token = root == NULL ? NULL : cJSON_GetObjectItemCaseSensitive(root, "confirmation_token");
        uint8_t decoded[16] = {0};
        char evidence_prepare_id[PM_COMMAND_ID_MAX + 1U] = {0};
        const int64_t now_us = esp_timer_get_time();
        const char *reason = "authorization_failed";
        bool intent_durable = false;
        const bool prior_durable_transaction =
            s_prepare_record.phase >= PM_PREPARE_PHASE_COMMIT_INTENT_TOKEN_ZEROIZED;
        if (cJSON_IsString(prepare_id) && strlen(prepare_id->valuestring) == PM_COMMAND_ID_MAX) {
            (void)snprintf(evidence_prepare_id, sizeof(evidence_prepare_id), "%s", prepare_id->valuestring);
        } else if (s_prepare_record.prepare_command_id[0] != '\0') {
            (void)snprintf(evidence_prepare_id, sizeof(evidence_prepare_id), "%s",
                           s_prepare_record.prepare_command_id);
        }
        if (root == NULL || cJSON_GetArraySize(root) != 2 || !cJSON_IsString(prepare_id) ||
            strlen(prepare_id->valuestring) != PM_COMMAND_ID_MAX || !cJSON_IsString(token) ||
            !hex_decode(token->valuestring, decoded, sizeof(decoded))) {
            result = ESP_ERR_INVALID_ARG;
            reason = "invalid_payload";
        } else if (s_prepare_record.kind != PM_PREPARE_KIND_FORMAT_STORAGE ||
                   s_prepare_record.phase != PM_PREPARE_PHASE_PREPARED ||
                   s_format.state != PM_FORMAT_PREPARED || s_format_prepare_command_id[0] == '\0') {
            result = ESP_ERR_INVALID_STATE;
            reason = "not_prepared";
        } else if (now_us < 0 || (uint64_t)now_us > s_prepare_record.expires_monotonic_us) {
            result = ESP_ERR_TIMEOUT;
            reason = "expired";
        } else if (strcmp(prepare_id->valuestring, s_prepare_record.prepare_command_id) != 0 ||
                   !pm_constant_time_equal(s_prepare_record.boot_session, s_prepare_boot_session,
                                           sizeof(s_prepare_boot_session)) ||
                   !pm_constant_time_equal(s_prepare_record.token, decoded, sizeof(decoded))) {
            result = ESP_ERR_INVALID_CRC;
        } else {
            result = begin_durable_commit_intent(PM_PREPARE_KIND_FORMAT_STORAGE, command);
            if (result == ESP_OK) {
                intent_durable = true;
                result = resume_destructive_transaction();
                durable_completion_pending = result != ESP_OK;
                reason = "durable_recovery_pending";
            } else {
                reason = "prepare_state_io_failed";
            }
        }
        if (result != ESP_OK && !intent_durable) {
            if (!prior_durable_transaction) {
                (void)prepare_state_clear();
            }
            (void)snprintf(command->evidence_json, sizeof(command->evidence_json),
                           "{\"prepare_command_id\":\"%s\",\"ready\":false,\"reason\":\"%s\"}",
                           evidence_prepare_id, reason);
        }
        secure_zero(decoded, sizeof(decoded));
        secure_zero(evidence_prepare_id, sizeof(evidence_prepare_id));
        zeroize_json_string(root, "confirmation_token");
        cJSON_Delete(root);
        break;
    }
    case PM_COMMAND_OTA_INSTALL:
        {
            pm_ota_task_context_t *ota = NULL;
            result = claim_ota_task() ? ESP_OK : ESP_ERR_INVALID_STATE;
            if (result == ESP_OK) {
                ota = allocate_ota_task_context();
                result = ota == NULL ? ESP_ERR_NO_MEM :
                         pm_network_capture_auth_snapshot(&s_network, &ota->auth);
            }
            if (result == ESP_OK) {
                ota->command = command;
                if (xTaskCreate(ota_task, "pm_ota", 16384U, ota, 6U, NULL) == pdPASS) {
                    pm_commands_unlock();
                    return;
                }
                result = ESP_ERR_NO_MEM;
            }
            free_ota_task_context(ota);
            if (result != ESP_ERR_INVALID_STATE || ota != NULL) {
                release_ota_task();
            }
        }
        break;
    case PM_COMMAND_DATA_RESET_PREPARE: {
        cJSON *root = cJSON_Parse(command->payload);
        const cJSON *token = root == NULL ? NULL : cJSON_GetObjectItemCaseSensitive(root, "confirmation_token");
        uint64_t generation = 0U;
        uint64_t server_floor = 0U;
        uint64_t internal_floor = 0U;
        uint8_t decoded[16] = {0};
        const bool durable_transaction_active =
            s_prepare_record.phase >= PM_PREPARE_PHASE_COMMIT_INTENT_TOKEN_ZEROIZED ||
            s_rotation_record.phase != PM_ROTATION_PHASE_NONE;
        const esp_err_t clear_error = durable_transaction_active ? ESP_ERR_INVALID_STATE : prepare_state_clear();
        if (root == NULL || cJSON_GetArraySize(root) != 3 || !cJSON_IsString(token) ||
            !hex_decode(token->valuestring, decoded, sizeof(decoded)) ||
            !json_u64(root, "reset_generation", &generation) ||
            !json_u64(root, "server_sequence_floor", &server_floor) || s_sequence.reset_generation == UINT32_MAX ||
            generation != (uint64_t)s_sequence.reset_generation + 1U) {
            result = ESP_ERR_INVALID_ARG;
        } else if (clear_error != ESP_OK) {
            result = clear_error;
        } else {
            const int64_t now_us = esp_timer_get_time();
            const uint64_t expires_us = (uint64_t)now_us + PM_PREPARE_EXPIRY_US;
            internal_floor = server_floor > s_sequence.maximum_seen ? server_floor : s_sequence.maximum_seen;
            memcpy(s_reset.token, decoded, sizeof(s_reset.token));
            (void)snprintf(s_reset.prepare_command_id, sizeof(s_reset.prepare_command_id), "%s",
                           command->command_id);
            s_reset.expires_us = (int64_t)expires_us;
            s_reset.generation = (uint32_t)generation;
            s_reset.server_floor = server_floor;
            s_reset.floor = internal_floor;
            result = pm_storage_prepare_format((uint64_t)now_us, expires_us, s_reset.token,
                                               &s_reset.storage_format);
            s_reset.prepared = result == ESP_OK;
            if (result == ESP_OK) {
                pm_prepare_record_t record = {
                    .schema = PM_PREPARE_SCHEMA,
                    .kind = PM_PREPARE_KIND_DATA_RESET,
                    .phase = PM_PREPARE_PHASE_PREPARED,
                    .expires_monotonic_us = expires_us,
                    .reset_generation = s_reset.generation,
                    .server_sequence_floor = server_floor,
                    .internal_sequence_floor = internal_floor,
                    .acknowledged_records_lost = s_reset.storage_format.acknowledged_records_lost,
                    .unacknowledged_records_lost = s_reset.storage_format.unacknowledged_records_lost,
                };
                memcpy(record.boot_session, s_prepare_boot_session, sizeof(record.boot_session));
                memcpy(record.token, decoded, sizeof(record.token));
                (void)snprintf(record.prepare_command_id, sizeof(record.prepare_command_id), "%s",
                               command->command_id);
                result = prepare_state_persist(&record);
                secure_zero(&record, sizeof(record));
            }
        }
        if (result == ESP_OK) {
            (void)snprintf(command->evidence_json, sizeof(command->evidence_json),
                           "{\"prepare_command_id\":\"%s\",\"reset_generation\":%llu,"
                           "\"server_sequence_floor\":%llu,\"sequence_floor\":%llu,\"ready\":true}",
                           command->command_id, (unsigned long long)generation,
                           (unsigned long long)server_floor, (unsigned long long)internal_floor);
            (void)snprintf(command->result_text, sizeof(command->result_text), "data_reset_prepare_ready");
        } else {
            if (!durable_transaction_active) {
                (void)prepare_state_clear();
            }
            (void)snprintf(command->evidence_json, sizeof(command->evidence_json),
                           "{\"prepare_command_id\":\"%s\",\"ready\":false,\"reason\":\"%s\"}",
                           command->command_id,
                           result == ESP_ERR_INVALID_ARG ? "invalid_payload" :
                           durable_transaction_active ? "durable_commit_active" : "prepare_state_io_failed");
        }
        secure_zero(decoded, sizeof(decoded));
        zeroize_json_string(root, "confirmation_token");
        cJSON_Delete(root);
        break;
    }
    case PM_COMMAND_DATA_RESET_CANCEL: {
        cJSON *root = cJSON_Parse(command->payload);
        const cJSON *prepare_id = root == NULL ? NULL : cJSON_GetObjectItemCaseSensitive(root,
                                                                                        "prepare_command_id");
        char evidence_prepare_id[PM_COMMAND_ID_MAX + 1U] = {0};
        if (cJSON_IsString(prepare_id) && strlen(prepare_id->valuestring) == PM_COMMAND_ID_MAX) {
            (void)snprintf(evidence_prepare_id, sizeof(evidence_prepare_id), "%s", prepare_id->valuestring);
        }
        if (root == NULL || cJSON_GetArraySize(root) != 1 || !cJSON_IsString(prepare_id) ||
            strlen(prepare_id->valuestring) != PM_COMMAND_ID_MAX) {
            result = ESP_ERR_INVALID_ARG;
            (void)snprintf(command->evidence_json, sizeof(command->evidence_json),
                           "{\"prepare_command_id\":\"%s\",\"cancelled\":false,"
                           "\"reason\":\"invalid_payload\"}", evidence_prepare_id);
        } else if (!s_reset.prepared || s_prepare_record.kind != PM_PREPARE_KIND_DATA_RESET ||
                   s_prepare_record.phase != PM_PREPARE_PHASE_PREPARED ||
                   strcmp(prepare_id->valuestring, s_reset.prepare_command_id) != 0 ||
                   strcmp(prepare_id->valuestring, s_prepare_record.prepare_command_id) != 0 ||
                   !pm_constant_time_equal(s_prepare_record.boot_session, s_prepare_boot_session,
                                           sizeof(s_prepare_boot_session))) {
            result = ESP_ERR_INVALID_STATE;
            (void)snprintf(command->evidence_json, sizeof(command->evidence_json),
                           "{\"prepare_command_id\":\"%s\",\"cancelled\":false,"
                           "\"reason\":\"not_prepared\"}", evidence_prepare_id);
        } else if (esp_timer_get_time() > s_reset.expires_us ||
                   (uint64_t)esp_timer_get_time() > s_prepare_record.expires_monotonic_us) {
            result = ESP_ERR_TIMEOUT;
            (void)prepare_state_clear();
            (void)snprintf(command->evidence_json, sizeof(command->evidence_json),
                           "{\"prepare_command_id\":\"%s\",\"cancelled\":false,"
                           "\"reason\":\"expired\"}", evidence_prepare_id);
        } else {
            result = prepare_state_clear();
            if (result == ESP_OK) {
                (void)snprintf(command->evidence_json, sizeof(command->evidence_json),
                               "{\"prepare_command_id\":\"%s\",\"cancelled\":true}",
                               evidence_prepare_id);
            } else {
                (void)snprintf(command->evidence_json, sizeof(command->evidence_json),
                               "{\"prepare_command_id\":\"%s\",\"cancelled\":false,"
                               "\"reason\":\"prepare_state_io_failed\"}", evidence_prepare_id);
            }
        }
        secure_zero(evidence_prepare_id, sizeof(evidence_prepare_id));
        cJSON_Delete(root);
        break;
    }
    case PM_COMMAND_DATA_RESET_COMMIT: {
        cJSON *root = cJSON_Parse(command->payload);
        const cJSON *prepare_id = root == NULL ? NULL : cJSON_GetObjectItemCaseSensitive(root,
                                                                                        "prepare_command_id");
        const cJSON *token = root == NULL ? NULL : cJSON_GetObjectItemCaseSensitive(root, "confirmation_token");
        uint64_t generation = 0U;
        uint64_t floor = 0U;
        uint8_t decoded[16] = {0};
        char evidence_prepare_id[PM_COMMAND_ID_MAX + 1U] = {0};
        const int64_t now_us = esp_timer_get_time();
        const char *reason = "authorization_failed";
        bool intent_durable = false;
        const bool prior_durable_transaction =
            s_prepare_record.phase >= PM_PREPARE_PHASE_COMMIT_INTENT_TOKEN_ZEROIZED;
        if (cJSON_IsString(prepare_id) && strlen(prepare_id->valuestring) == PM_COMMAND_ID_MAX) {
            (void)snprintf(evidence_prepare_id, sizeof(evidence_prepare_id), "%s", prepare_id->valuestring);
        } else if (s_prepare_record.prepare_command_id[0] != '\0') {
            (void)snprintf(evidence_prepare_id, sizeof(evidence_prepare_id), "%s",
                           s_prepare_record.prepare_command_id);
        }
        if (root == NULL || cJSON_GetArraySize(root) != 4 || !cJSON_IsString(prepare_id) ||
            strlen(prepare_id->valuestring) != PM_COMMAND_ID_MAX || !cJSON_IsString(token) ||
            !hex_decode(token->valuestring, decoded, sizeof(decoded)) ||
            !json_u64(root, "reset_generation", &generation) || !json_u64(root, "sequence_floor", &floor)) {
            result = ESP_ERR_INVALID_ARG;
            reason = "invalid_payload";
        } else if (!s_reset.prepared || s_prepare_record.kind != PM_PREPARE_KIND_DATA_RESET ||
                   s_prepare_record.phase != PM_PREPARE_PHASE_PREPARED ||
                   s_reset.prepare_command_id[0] == '\0') {
            result = ESP_ERR_INVALID_STATE;
            reason = "not_prepared";
        } else if (now_us < 0 || (uint64_t)now_us > s_prepare_record.expires_monotonic_us) {
            result = ESP_ERR_TIMEOUT;
            reason = "expired";
        } else if (strcmp(prepare_id->valuestring, s_prepare_record.prepare_command_id) != 0 ||
                   generation != s_prepare_record.reset_generation ||
                   floor != s_prepare_record.internal_sequence_floor ||
                   !pm_constant_time_equal(s_prepare_record.boot_session, s_prepare_boot_session,
                                           sizeof(s_prepare_boot_session)) ||
                   !pm_constant_time_equal(s_prepare_record.token, decoded, sizeof(decoded))) {
            result = ESP_ERR_INVALID_CRC;
        } else {
            result = begin_durable_commit_intent(PM_PREPARE_KIND_DATA_RESET, command);
            if (result == ESP_OK) {
                intent_durable = true;
                result = resume_destructive_transaction();
                durable_completion_pending = result != ESP_OK;
                reason = "durable_recovery_pending";
            } else {
                reason = "prepare_state_io_failed";
            }
        }
        if (result != ESP_OK && !intent_durable) {
            if (!prior_durable_transaction) {
                (void)prepare_state_clear();
            }
            (void)snprintf(command->evidence_json, sizeof(command->evidence_json),
                           "{\"prepare_command_id\":\"%s\",\"ready\":false,\"reason\":\"%s\"}",
                           evidence_prepare_id, reason);
        }
        secure_zero(decoded, sizeof(decoded));
        secure_zero(evidence_prepare_id, sizeof(evidence_prepare_id));
        zeroize_json_string(root, "confirmation_token");
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
        if (s_rotation_record.phase != PM_ROTATION_PHASE_NONE) {
            result = ESP_ERR_INVALID_STATE;
        } else if (!cJSON_IsString(name) || strlen(name->valuestring) > PM_CONFIG_NAME_MAX || !cJSON_IsString(timezone) ||
            strlen(timezone->valuestring) > PM_CONFIG_TIMEZONE_MAX || !cJSON_IsNumber(ct) || ct->valuedouble < 1.0 ||
            ct->valuedouble > 100.0 || cJSON_GetArraySize(root) != 3) {
            result = ESP_ERR_INVALID_ARG;
        } else if (s_config.generation == UINT32_MAX) {
            result = ESP_ERR_INVALID_STATE;
        } else {
            pm_config_t *candidate = allocate_config_scratch();
            if (candidate == NULL) {
                result = ESP_ERR_NO_MEM;
            } else {
                *candidate = s_config;
                candidate->generation++;
                (void)snprintf(candidate->friendly_name, sizeof(candidate->friendly_name), "%s", name->valuestring);
                (void)snprintf(candidate->timezone, sizeof(candidate->timezone), "%s", timezone->valuestring);
                candidate->ct_rating_a = (uint16_t)ct->valuedouble;
                pm_config_transaction_t transaction = {0};
                result = pm_config_begin(candidate, &transaction);
                if (result == ESP_OK) {
                    result = pm_config_mark_network_tested(&transaction);
                }
                if (result == ESP_OK) {
                    result = pm_config_commit(&transaction);
                }
                if (result == ESP_OK) {
                    s_config = *candidate;
                    update_runtime_measurement_config(candidate);
                    result = pm_network_apply_runtime_config(&s_network, candidate);
                } else {
                    pm_config_abort(&transaction);
                }
                free_config_scratch(candidate);
            }
        }
        cJSON_Delete(root);
        break;
    }
    case PM_COMMAND_ROTATE_DEVICE_CREDENTIALS: {
        cJSON *root = cJSON_Parse(command->payload);
        const cJSON *secret = root == NULL ? NULL : cJSON_GetObjectItemCaseSensitive(root,
                                                                                     "device_secret_hex");
        const cJSON *cancelled = root == NULL ? NULL : cJSON_GetObjectItemCaseSensitive(root, "cancelled");
        if (!cJSON_IsObject(root)) {
            result = ESP_ERR_INVALID_ARG;
        } else if (secret != NULL) {
            result = credential_rotation_prepare(command, root, &durable_completion_pending);
        } else if (cancelled != NULL) {
            result = credential_rotation_cancel(command, root);
        } else {
            result = credential_rotation_commit(command, root, &durable_completion_pending);
        }
        zeroize_json_string(root, "device_secret_hex");
        cJSON_Delete(root);
        break;
    }
    default:
        result = ESP_ERR_NOT_SUPPORTED;
        break;
    }
    if (durable_completion_pending) {
        (void)snprintf(command->result_text, sizeof(command->result_text), "durable_recovery_pending");
        (void)pm_command_transition(&s_commands, command, PM_COMMAND_RUNNING,
                                    command->progress_percent, result);
    } else {
        (void)pm_command_transition(&s_commands, command,
                                    result == ESP_OK ? PM_COMMAND_SUCCEEDED : PM_COMMAND_FAILED,
                                    result == ESP_OK ? 100U : command->progress_percent, result);
    }
    pm_commands_unlock();
}

static void control_task(void *argument)
{
    (void)argument;
    if (!begin_runtime_task(PM_CONTROL_READY_BIT)) {
        vTaskDelete(NULL);
        return;
    }
    for (;;) {
        if (pm_commands_lock() != ESP_OK) {
            vTaskDelay(pdMS_TO_TICKS(100));
            continue;
        }
        prepare_state_expire_if_needed();
        if (rotation_expire_if_needed() != ESP_OK) {
            ESP_LOGE(TAG, "credential rotation expiry cleanup remains failed closed");
        }
        if (s_prepare_record.phase >= PM_PREPARE_PHASE_COMMIT_INTENT_TOKEN_ZEROIZED &&
            s_prepare_record.phase < PM_PREPARE_PHASE_COMMAND_RESULT_DURABLE) {
            const esp_err_t recovery_error = resume_destructive_transaction();
            if (recovery_error != ESP_OK) {
                ESP_LOGW(TAG, "durable destructive recovery pending: %s",
                         esp_err_to_name(recovery_error));
            }
        } else if (s_prepare_record.phase == PM_PREPARE_PHASE_RESULT_ACKNOWLEDGED) {
            if (destructive_cleanup_acknowledged() != ESP_OK) {
                ESP_LOGE(TAG, "acknowledged destructive journal cleanup failed");
            }
        }
        if ((s_rotation_record.phase >= PM_ROTATION_PHASE_CANDIDATE_PERSISTED &&
             s_rotation_record.phase <= PM_ROTATION_PHASE_CONFIG_STAGED) ||
            (s_rotation_record.phase >= PM_ROTATION_PHASE_COMMIT_INTENT_SECRET_ZEROIZED &&
             s_rotation_record.phase < PM_ROTATION_PHASE_COMMAND_RESULT_DURABLE)) {
            const esp_err_t recovery_error = resume_rotation_transaction();
            if (recovery_error != ESP_OK) {
                ESP_LOGW(TAG, "durable credential rotation recovery pending: %s",
                         esp_err_to_name(recovery_error));
            }
        } else if (s_rotation_record.phase == PM_ROTATION_PHASE_RESULT_ACKNOWLEDGED &&
                   rotation_cleanup_acknowledged() != ESP_OK) {
            ESP_LOGE(TAG, "acknowledged credential rotation cleanup failed");
        }
        process_authenticated_result_acknowledgements();
        pm_commands_unlock();
        pm_command_t *command = NULL;
        if (xQueueReceive(s_command_queue, &command, pdMS_TO_TICKS(1000)) == pdTRUE) {
            execute_command(command);
        }
        (void)esp_task_wdt_reset();
    }
}

static void authenticated_result_acknowledged(const char command_id[PM_COMMAND_ID_MAX + 1U], void *context)
{
    (void)context;
    if (command_id == NULL || strlen(command_id) != PM_COMMAND_ID_MAX || s_result_ack_queue == NULL) {
        return;
    }
    pm_result_ack_event_t event = {0};
    (void)snprintf(event.command_id, sizeof(event.command_id), "%s", command_id);
    if (xQueueSend(s_result_ack_queue, &event, 0U) != pdTRUE) {
        ESP_LOGE(TAG, "authenticated result acknowledgement queue full");
    }
    memset(&event, 0, sizeof(event));
}

static void command_received(const pm_command_t *command, void *context)
{
    (void)context;
    pm_command_t *mutable_command = (pm_command_t *)command;
    if (xQueueSend(s_command_queue, &mutable_command, 0U) != pdTRUE) {
        ESP_LOGE(TAG, "bounded command queue full");
    }
}

static bool command_owned_by_durable_journal(const pm_command_t *command)
{
    if (command == NULL) {
        return false;
    }
    if (command->type == PM_COMMAND_ROTATE_DEVICE_CREDENTIALS &&
        s_rotation_record.phase != PM_ROTATION_PHASE_NONE) {
        return strcmp(command->command_id, s_rotation_record.prepare_command_id) == 0 ||
               strcmp(command->command_id, s_rotation_record.commit_command_id) == 0;
    }
    if ((command->type == PM_COMMAND_FORMAT_STORAGE_COMMIT ||
         command->type == PM_COMMAND_DATA_RESET_COMMIT) &&
        s_prepare_record.phase >= PM_PREPARE_PHASE_COMMIT_INTENT_TOKEN_ZEROIZED) {
        return strcmp(command->command_id, s_prepare_record.commit_command_id) == 0;
    }
    return false;
}

static esp_err_t reconcile_interrupted_commands(const pm_ota_checkpoint_t *ota_checkpoint)
{
    if (ota_checkpoint == NULL || pm_commands_lock() != ESP_OK) {
        return ESP_ERR_INVALID_ARG;
    }
    esp_err_t error = ESP_OK;
    for (size_t i = 0U; i < PM_COMMAND_LEDGER_SIZE; ++i) {
        pm_command_t *command = &s_commands.entries[i];
        if (command->command_id[0] == '\0' || command_owned_by_durable_journal(command)) {
            continue;
        }
        switch (pm_command_boot_action(command)) {
        case PM_COMMAND_BOOT_REQUEUE:
            if (xQueueSend(s_command_queue, &command, 0U) != pdTRUE) {
                error = ESP_ERR_NO_MEM;
            }
            break;
        case PM_COMMAND_BOOT_FAIL_INTERRUPTED:
            error = pm_command_reconcile_boot(&s_commands, command, PM_COMMAND_FAILED,
                                              ESP_ERR_INVALID_STATE, "interrupted_by_reboot");
            break;
        case PM_COMMAND_BOOT_COMPLETE_REBOOT:
            error = pm_command_reconcile_boot(&s_commands, command, PM_COMMAND_SUCCEEDED,
                                              ESP_OK, "reboot_observed");
            break;
        case PM_COMMAND_BOOT_COMPLETE_WAKE:
            error = pm_command_reconcile_boot(&s_commands, command, PM_COMMAND_SUCCEEDED,
                                              ESP_OK, "wake_observed");
            break;
        case PM_COMMAND_BOOT_RECONCILE_OTA:
            if (ota_checkpoint->stage == PM_OTA_VALID) {
                error = pm_command_reconcile_boot(&s_commands, command, PM_COMMAND_SUCCEEDED,
                                                  ESP_OK, "ota_post_boot_valid");
            } else if (ota_checkpoint->stage == PM_OTA_ROLLED_BACK) {
                const int32_t result_code = ota_checkpoint->last_error == ESP_OK ?
                                            ESP_ERR_INVALID_STATE : ota_checkpoint->last_error;
                error = pm_command_reconcile_boot(&s_commands, command, PM_COMMAND_ROLLED_BACK,
                                                  result_code, "ota_rolled_back");
            } else {
                const int32_t result_code = ota_checkpoint->last_error == ESP_OK ?
                                            ESP_ERR_INVALID_STATE : ota_checkpoint->last_error;
                error = pm_command_reconcile_boot(&s_commands, command, PM_COMMAND_FAILED,
                                                  result_code,
                                                  ota_checkpoint->stage == PM_OTA_FAILED ?
                                                      "ota_post_boot_failed" : "ota_outcome_unavailable");
            }
            break;
        case PM_COMMAND_BOOT_IGNORE:
        default:
            break;
        }
        if (error != ESP_OK) {
            break;
        }
    }
    pm_commands_unlock();
    return error;
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

static esp_err_t flush_storage_for_reboot(void *context, uint32_t timeout_ms)
{
    (void)context;
    return pm_storage_flush(timeout_ms);
}

static esp_err_t prepare_safe_reboot_from_com(void *context)
{
    (void)context;
    const esp_err_t error = pm_provisioning_prepare_reboot_barrier(
        s_storage_flush_available, flush_storage_for_reboot, NULL, 3000U);
    if (error != ESP_OK) {
        ESP_LOGE(TAG, "storage flush failed; USB-requested reboot cancelled: %s", esp_err_to_name(error));
    } else if (!s_storage_flush_available) {
        ESP_LOGW(TAG, "storage worker unavailable; no recovery-mode producers to flush");
    }
    return error;
}

static bool wait_for_physical_recovery_request(bool provisioned)
{
    const gpio_config_t recovery_button = {
        .pin_bit_mask = UINT64_C(1) << PM_USB_RECOVERY_BUTTON,
        .mode = GPIO_MODE_INPUT,
        .pull_up_en = GPIO_PULLUP_ENABLE,
        .pull_down_en = GPIO_PULLDOWN_DISABLE,
        .intr_type = GPIO_INTR_DISABLE,
    };
    if (gpio_config(&recovery_button) != ESP_OK || !provisioned) {
        return false;
    }

    ESP_LOGI(TAG, "physical recovery window open for %u ms; press BOOT now",
             (unsigned)PM_RECOVERY_WINDOW_MS);
    const int64_t deadline_us = esp_timer_get_time() + (int64_t)PM_RECOVERY_WINDOW_MS * 1000;
    uint32_t low_samples = 0U;
    while (esp_timer_get_time() < deadline_us) {
        if (gpio_get_level(PM_USB_RECOVERY_BUTTON) == 0) {
            low_samples++;
            if (low_samples >= PM_RECOVERY_DEBOUNCE_SAMPLES) {
                ESP_LOGW(TAG, "debounced physical recovery request accepted");
                return true;
            }
        } else {
            low_samples = 0U;
        }
        vTaskDelay(pdMS_TO_TICKS(PM_RECOVERY_SAMPLE_MS));
    }
    ESP_LOGI(TAG, "physical recovery window closed; continuing normal boot");
    return false;
}

static void supervisor_task(void *argument)
{
    (void)argument;
    if (!begin_runtime_task(PM_SUPERVISOR_READY_BIT)) {
        vTaskDelete(NULL);
        return;
    }
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
    if (prepare_state_boot_load() != ESP_OK) {
        ESP_LOGE(TAG, "destructive transaction journal recovery failed closed");
        (void)pm_state_transition(&s_state, PM_EVENT_SELF_TEST_FAILED, esp_timer_get_time());
        return;
    }
    error = pm_config_load(&s_config);
    const bool provisioned = error == ESP_OK;
    if (!provisioned) {
        secure_zero(&s_config, sizeof(s_config));
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
    update_runtime_measurement_config(&s_config);

    pm_time_init(&s_time, esp_timer_get_time());
    (void)pm_time_load_checkpoint(&s_time, esp_timer_get_time());
    if (rotation_state_boot_load() != ESP_OK || rotation_expire_if_needed() != ESP_OK) {
        ESP_LOGE(TAG, "credential rotation journal recovery failed closed");
        (void)pm_state_transition(&s_state, PM_EVENT_SELF_TEST_FAILED, esp_timer_get_time());
        return;
    }
    if ((s_rotation_record.phase >= PM_ROTATION_PHASE_CANDIDATE_PERSISTED &&
         s_rotation_record.phase <= PM_ROTATION_PHASE_CONFIG_STAGED) ||
        (s_rotation_record.phase >= PM_ROTATION_PHASE_COMMIT_INTENT_SECRET_ZEROIZED &&
         s_rotation_record.phase < PM_ROTATION_PHASE_COMMAND_RESULT_DURABLE)) {
        const esp_err_t recovery_error = resume_rotation_transaction();
        if (recovery_error != ESP_OK) {
            ESP_LOGE(TAG, "credential rotation could not resume: %s", esp_err_to_name(recovery_error));
            (void)pm_state_transition(&s_state, PM_EVENT_SELF_TEST_FAILED, esp_timer_get_time());
            return;
        }
    } else if (s_rotation_record.phase == PM_ROTATION_PHASE_RESULT_ACKNOWLEDGED &&
               rotation_cleanup_acknowledged() != ESP_OK) {
        ESP_LOGE(TAG, "credential rotation acknowledged cleanup failed closed");
        (void)pm_state_transition(&s_state, PM_EVENT_SELF_TEST_FAILED, esp_timer_get_time());
        return;
    }
    const bool physical_recovery = wait_for_physical_recovery_request(provisioned);

    error = pm_storage_start(s_config.device_id, &s_storage);
    s_storage_flush_available = error == ESP_OK;
    s_storage.acknowledged_sequence = s_sequence.acknowledged;
    if (error != ESP_OK) {
        set_degraded(PM_EVENT_STORAGE_FAILED);
    }
    if (s_prepare_record.phase >= PM_PREPARE_PHASE_COMMIT_INTENT_TOKEN_ZEROIZED &&
        s_prepare_record.phase < PM_PREPARE_PHASE_COMMAND_RESULT_DURABLE) {
        const esp_err_t recovery_error = resume_destructive_transaction();
        if (recovery_error != ESP_OK) {
            ESP_LOGE(TAG, "committed destructive transaction could not yet resume: %s",
                     esp_err_to_name(recovery_error));
            (void)pm_state_transition(&s_state, PM_EVENT_SELF_TEST_FAILED, esp_timer_get_time());
            return;
        }
    }

    /* Provisioning and physically authorized recovery run as an isolated
     * maintenance boot.  The storage worker is available for the safe-reboot
     * durability barrier, but no measurement, command, network, or OTA
     * producer is started while candidate Wi-Fi/configuration is being tested.
     * A committed configuration becomes the only runtime configuration after
     * the requested reboot. */
    pm_provisioning_session_init(&s_provisioning, &s_config, physical_recovery || !provisioned,
                                 pm_network_provisioning_test, factory_reset_config_only,
                                 prepare_safe_reboot_from_com, NULL);
    if (!provisioned || physical_recovery) {
        (void)pm_state_transition(&s_state, !provisioned ? PM_EVENT_CONFIG_MISSING : PM_EVENT_PHYSICAL_RECOVERY,
                                  esp_timer_get_time());
        error = pm_provisioning_start_usb(&s_provisioning);
        if (error != ESP_OK) {
            ESP_LOGE(TAG, "USB provisioning task failed to start: %s", esp_err_to_name(error));
            (void)pm_state_transition(&s_state, PM_EVENT_SELF_TEST_FAILED, esp_timer_get_time());
        }
        return;
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
    s_result_ack_queue = xQueueCreateStatic(PM_RESULT_ACK_QUEUE_DEPTH, sizeof(pm_result_ack_event_t),
                                            s_result_ack_queue_storage, &s_result_ack_queue_buffer);
    s_runtime_start_gate = xEventGroupCreateStatic(&s_runtime_start_gate_storage);
    if (s_sample_queue == NULL || s_command_queue == NULL || s_result_ack_queue == NULL ||
        s_runtime_start_gate == NULL) {
        ESP_LOGE(TAG, "static queue/start-gate creation failed");
        return;
    }
    (void)xEventGroupClearBits(s_runtime_start_gate,
                               PM_RUNTIME_START_BIT | PM_NETWORK_START_BIT |
                               PM_RUNTIME_READY_BITS | PM_RUNTIME_TASK_FAILED_BIT);

    s_network.sequence = &s_sequence;
    s_network.storage = &s_storage;
    s_network.commands = &s_commands;
    s_network.command_callback = command_received;
    s_network.result_ack_callback = authenticated_result_acknowledged;
    s_network.start_gate = s_runtime_start_gate;
    s_network.start_bit = PM_NETWORK_START_BIT;
    error = pm_network_apply_runtime_config(&s_network, &s_config);
    if (error != ESP_OK) {
        ESP_LOGE(TAG, "runtime credential initialization failed: %s", esp_err_to_name(error));
        (void)pm_state_transition(&s_state, PM_EVENT_SELF_TEST_FAILED, esp_timer_get_time());
        return;
    }
    const pm_runtime_task_spec_t runtime_tasks[] = {
        {measurement_task, "pm_measurement", 4096U, NULL, 12U, &s_measurement_task},
        {interval_task, "pm_interval", 4096U, NULL, 9U, &s_interval_task},
        {control_task, "pm_control", 8192U, NULL, 6U, &s_control_task},
        {supervisor_task, "pm_supervisor", 4096U, NULL, 5U, &s_supervisor_task},
    };
    error = pm_runtime_create_task_set(runtime_tasks,
                                       sizeof(runtime_tasks) / sizeof(runtime_tasks[0]));
    if (error != ESP_OK) {
        ESP_LOGE(TAG, "required gated runtime task allocation failed; all siblings deleted");
        (void)pm_state_transition(&s_state, PM_EVENT_SELF_TEST_FAILED, esp_timer_get_time());
        return;
    }

    const esp_err_t network_start_error = pm_network_start(&s_network);
    (void)xEventGroupSetBits(s_runtime_start_gate, PM_RUNTIME_START_BIT);
    const EventBits_t ready = xEventGroupWaitBits(s_runtime_start_gate, PM_RUNTIME_READY_BITS,
                                                  pdFALSE, pdTRUE, pdMS_TO_TICKS(5000));
    const bool runtime_ready = (ready & PM_RUNTIME_READY_BITS) == PM_RUNTIME_READY_BITS &&
                               (xEventGroupGetBits(s_runtime_start_gate) &
                                PM_RUNTIME_TASK_FAILED_BIT) == 0U;
    if (!runtime_ready) {
        ESP_LOGE(TAG, "runtime task watchdog/start readiness failed before OTA validation");
        (void)pm_state_transition(&s_state, PM_EVENT_SELF_TEST_FAILED, esp_timer_get_time());
        esp_restart();
    }

    error = pm_ota_post_boot_validate(provisioned, runtime_ready, runtime_ready,
                                      true, network_start_error == ESP_OK);
    if (error != ESP_OK) {
        ESP_LOGE(TAG, "OTA post-boot validation failed before command reconciliation: %s",
                 esp_err_to_name(error));
        (void)pm_storage_flush(3000U);
        esp_restart();
    }
    pm_ota_checkpoint_t ota_checkpoint = {0};
    error = pm_ota_load_checkpoint(&ota_checkpoint);
    if (error != ESP_OK || reconcile_interrupted_commands(&ota_checkpoint) != ESP_OK) {
        ESP_LOGE(TAG, "durable command boot reconciliation failed closed");
        (void)pm_state_transition(&s_state, PM_EVENT_SELF_TEST_FAILED, esp_timer_get_time());
        (void)pm_storage_flush(3000U);
        esp_restart();
    }
    pm_network_health_update(&s_network, PM_HEALTH_OTA_FAILED, ota_checkpoint.stage == PM_OTA_FAILED);
    pm_network_health_update(&s_network, PM_HEALTH_OTA_ROLLED_BACK,
                             ota_checkpoint.stage == PM_OTA_ROLLED_BACK);
    (void)xEventGroupSetBits(s_runtime_start_gate, PM_NETWORK_START_BIT);

    if (network_start_error == ESP_OK) {
        (void)pm_state_transition(&s_state, PM_EVENT_SELF_TEST_OK, esp_timer_get_time());
    } else {
        set_degraded(PM_EVENT_WIFI_FAILED);
    }
}
