#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "driver/gpio.h"
#include "esp_heap_caps.h"
#include "esp_log.h"
#include "esp_random.h"
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
#include "pm_meter.h"
#include "pm_network.h"
#include "pm_ota.h"
#include "pm_protocol.h"
#include "pm_provisioning.h"
#include "pm_state.h"
#include "runtime_startup.h"

#if CONFIG_PM_PRODUCTION_RELEASE && (!CONFIG_PM_METER_VARIANT_PZEM004T_V4_CLASSIC || !CONFIG_PM_HARDWARE_IDENTITY_VERIFIED)
#error "Stable production firmware requires an explicit PZEM variant and machine-readable hardware identity evidence"
#endif

#if CONFIG_PM_PRODUCTION_RELEASE && !CONFIG_NVS_ENCRYPTION
#error "Stable production firmware requires NVS encryption backed by a deliberately provisioned device HMAC key"
#endif

#define PM_COMMAND_QUEUE_DEPTH PM_COMMAND_LEDGER_SIZE
#define PM_RESULT_ACK_QUEUE_DEPTH PM_COMMAND_LEDGER_SIZE
#define PM_RECOVERY_WINDOW_MS 3000U
#define PM_RECOVERY_DEBOUNCE_SAMPLES 5U
#define PM_RECOVERY_SAMPLE_MS 20U
#define PM_RUNTIME_START_BIT BIT0
#define PM_NETWORK_START_BIT BIT1
#define PM_MEASUREMENT_READY_BIT BIT2
#define PM_CONTROL_READY_BIT BIT3
#define PM_SUPERVISOR_READY_BIT BIT4
#define PM_RUNTIME_TASK_FAILED_BIT BIT5
#define PM_RUNTIME_READY_BITS (PM_MEASUREMENT_READY_BIT | PM_CONTROL_READY_BIT | PM_SUPERVISOR_READY_BIT)

#ifdef CONFIG_PM_HARDWARE_IDENTITY_VERIFIED
#define PM_BUILD_PZEM_LIVE_READS true
#elif defined(CONFIG_PM_PZEM_LIVE_VALIDATION)
#define PM_BUILD_PZEM_LIVE_READS true
#else
#define PM_BUILD_PZEM_LIVE_READS false
#endif

#ifdef CONFIG_PM_SIMULATED_METER
#define PM_BUILD_SIMULATED_METER true
#else
#define PM_BUILD_SIMULATED_METER false
#endif

static const char *const TAG = "power_meter";
static StaticQueue_t s_command_queue_buffer;
static uint8_t s_command_queue_storage[PM_COMMAND_QUEUE_DEPTH * sizeof(pm_command_t *)];
static QueueHandle_t s_command_queue;
typedef struct { char command_id[PM_COMMAND_ID_MAX + 1U]; } pm_result_ack_event_t;
static StaticQueue_t s_result_ack_queue_buffer;
static uint8_t s_result_ack_queue_storage[PM_RESULT_ACK_QUEUE_DEPTH * sizeof(pm_result_ack_event_t)];
static QueueHandle_t s_result_ack_queue;
static StaticEventGroup_t s_runtime_start_gate_storage;
static EventGroupHandle_t s_runtime_start_gate;
static TaskHandle_t s_measurement_task;
static TaskHandle_t s_control_task;
static TaskHandle_t s_supervisor_task;
static pm_meter_driver_t s_meter;
static pm_command_ledger_t s_commands;
static pm_config_t s_config;
static pm_state_machine_t s_state;
static pm_time_state_t s_time;
static pm_network_context_t s_network;
static pm_provisioning_session_t s_provisioning;
static portMUX_TYPE s_state_lock = portMUX_INITIALIZER_UNLOCKED;
static bool s_ota_task_active;

typedef struct {
    pm_command_t *command;
    pm_network_auth_snapshot_t auth;
} pm_ota_task_context_t;

typedef struct {
    uint8_t device_id[16];
    uint32_t generation;
    uint32_t crc32;
} local_identity_t;

static void secure_zero(void *value, size_t length)
{
    volatile uint8_t *bytes = (volatile uint8_t *)value;
    while (length-- > 0U) *bytes++ = 0U;
}

static bool begin_runtime_task(EventBits_t ready_bit)
{
    if (s_runtime_start_gate == NULL ||
        (xEventGroupWaitBits(s_runtime_start_gate, PM_RUNTIME_START_BIT, pdFALSE, pdTRUE,
                             portMAX_DELAY) & PM_RUNTIME_START_BIT) == 0U) return false;
    if (esp_task_wdt_add(NULL) != ESP_OK) {
        (void)xEventGroupSetBits(s_runtime_start_gate, PM_RUNTIME_TASK_FAILED_BIT);
        return false;
    }
    (void)xEventGroupSetBits(s_runtime_start_gate, ready_bit);
    return true;
}

static void set_degraded(pm_state_event_t event)
{
    taskENTER_CRITICAL(&s_state_lock);
    (void)pm_state_transition(&s_state, event, esp_timer_get_time());
    taskEXIT_CRITICAL(&s_state_lock);
}

static esp_err_t load_or_create_identity(uint8_t device_id[16])
{
    nvs_handle_t handle = 0;
    esp_err_t error = nvs_open("pm_identity", NVS_READWRITE, &handle);
    if (error != ESP_OK) return error;
    local_identity_t identity = {0};
    size_t size = sizeof(identity);
    error = nvs_get_blob(handle, "identity", &identity, &size);
    if (error == ESP_ERR_NVS_NOT_FOUND) {
        esp_fill_random(identity.device_id, sizeof(identity.device_id));
        identity.device_id[6] = (uint8_t)((identity.device_id[6] & 0x0FU) | 0x40U);
        identity.device_id[8] = (uint8_t)((identity.device_id[8] & 0x3FU) | 0x80U);
        identity.generation = 1U;
        identity.crc32 = pm_crc32_ieee(&identity, offsetof(local_identity_t, crc32));
        error = nvs_set_blob(handle, "identity", &identity, sizeof(identity));
        if (error == ESP_OK) error = nvs_commit(handle);
    } else if (error == ESP_OK &&
               (size != sizeof(identity) || identity.generation == 0U ||
                identity.crc32 != pm_crc32_ieee(&identity,
                                                offsetof(local_identity_t, crc32)))) {
        error = ESP_ERR_INVALID_CRC;
    }
    nvs_close(handle);
    if (error == ESP_OK) memcpy(device_id, identity.device_id, sizeof(identity.device_id));
    secure_zero(&identity, sizeof(identity));
    return error;
}

static esp_err_t persist_identity(const uint8_t device_id[16])
{
    nvs_handle_t handle = 0;
    esp_err_t error = nvs_open("pm_identity", NVS_READWRITE, &handle);
    if (error != ESP_OK) return error;
    local_identity_t prior = {0};
    size_t size = sizeof(prior);
    const esp_err_t prior_error = nvs_get_blob(handle, "identity", &prior, &size);
    if (prior_error != ESP_OK || size != sizeof(prior) || prior.generation == 0U ||
        prior.generation == UINT32_MAX ||
        prior.crc32 != pm_crc32_ieee(&prior, offsetof(local_identity_t, crc32))) {
        nvs_close(handle); secure_zero(&prior, sizeof(prior));
        return prior_error == ESP_OK ? ESP_ERR_INVALID_CRC : prior_error;
    }
    local_identity_t identity = {.generation = prior.generation + 1U};
    memcpy(identity.device_id, device_id, sizeof(identity.device_id));
    identity.crc32 = pm_crc32_ieee(&identity, offsetof(local_identity_t, crc32));
    error = nvs_set_blob(handle, "identity", &identity, sizeof(identity));
    if (error == ESP_OK) error = nvs_commit(handle);
    nvs_close(handle);
    secure_zero(&prior, sizeof(prior)); secure_zero(&identity, sizeof(identity));
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
    if (gpio_config(&recovery_button) != ESP_OK || !provisioned) return false;
    uint32_t low_samples = 0U;
    const int64_t deadline = esp_timer_get_time() + (int64_t)PM_RECOVERY_WINDOW_MS * 1000;
    while (esp_timer_get_time() < deadline) {
        low_samples = gpio_get_level(PM_USB_RECOVERY_BUTTON) == 0 ? low_samples + 1U : 0U;
        if (low_samples >= PM_RECOVERY_DEBOUNCE_SAMPLES) return true;
        vTaskDelay(pdMS_TO_TICKS(PM_RECOVERY_SAMPLE_MS));
    }
    return false;
}

static esp_err_t prepare_safe_reboot_from_com(void *context)
{
    (void)context;
    return pm_provisioning_prepare_reboot_barrier();
}

static void measurement_task(void *argument)
{
    (void)argument;
    if (!begin_runtime_task(PM_MEASUREMENT_READY_BIT)) { vTaskDelete(NULL); return; }
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
        if (error != ESP_OK) set_degraded(PM_EVENT_METER_FAILED);
        else set_degraded(PM_EVENT_METER_RECOVERED);
        if (pm_network_publish_live(&sample) != ESP_OK)
            ESP_LOGW(TAG, "latest telemetry sample could not be offered");
        (void)esp_task_wdt_reset();
        xTaskDelayUntil(&last_wake, pdMS_TO_TICKS(CONFIG_PM_METER_SAMPLE_MS));
    }
}

static bool claim_ota_task(void)
{
    taskENTER_CRITICAL(&s_state_lock);
    const bool claimed = !s_ota_task_active;
    if (claimed) s_ota_task_active = true;
    taskEXIT_CRITICAL(&s_state_lock);
    return claimed;
}

static void release_ota_task(void)
{
    taskENTER_CRITICAL(&s_state_lock); s_ota_task_active = false; taskEXIT_CRITICAL(&s_state_lock);
}

static pm_ota_task_context_t *allocate_ota_task_context(void)
{
    pm_ota_task_context_t *task = (pm_ota_task_context_t *)heap_caps_calloc(
        1U, sizeof(*task), MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if (task == NULL) task = (pm_ota_task_context_t *)heap_caps_calloc(
        1U, sizeof(*task), MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
    return task;
}

static void free_ota_task_context(pm_ota_task_context_t *task)
{
    if (task != NULL) {
        pm_network_clear_auth_snapshot(&task->auth);
        secure_zero(task, sizeof(*task)); heap_caps_free(task);
    }
}

static void ota_progress(uint8_t percent, pm_ota_stage_t stage, void *context)
{
    pm_command_t *command = (pm_command_t *)context;
    if (command != NULL && pm_commands_lock() == ESP_OK) {
        (void)snprintf(command->result_text, sizeof(command->result_text),
                       "ota_stage=%u", (unsigned)stage);
        (void)pm_command_transition(&s_commands, command, PM_COMMAND_RUNNING, percent, ESP_OK);
        pm_commands_unlock();
    }
}

static void ota_task(void *argument)
{
    pm_ota_task_context_t *task = (pm_ota_task_context_t *)argument;
    if (task == NULL || task->command == NULL) {
        free_ota_task_context(task); release_ota_task(); vTaskDelete(NULL); return;
    }
    pm_command_t *command = task->command;
    pm_ota_manifest_t manifest;
    int64_t utc_ms = 0;
    esp_err_t result = pm_ota_manifest_parse_payload(command->payload, task->auth.server_origin,
                                                     task->auth.device_id_text, &manifest);
    if (result == ESP_OK && !pm_time_now(&s_time, esp_timer_get_time(), &utc_ms))
        result = ESP_ERR_INVALID_STATE;
    if (result == ESP_OK)
        result = pm_ota_install(&manifest, task->auth.ca_pem, task->auth.device_to_server_key,
                                task->auth.server_to_device_key, utc_ms, ota_progress, command);
    if (result == ESP_OK)
        result = pm_command_transition(&s_commands, command, PM_COMMAND_AWAITING_REBOOT,
                                       100U, ESP_OK);
    if (result == ESP_OK) {
        free_ota_task_context(task); vTaskDelay(pdMS_TO_TICKS(500)); esp_restart();
    }
    const esp_err_t cancellation = pm_ota_cancel_pending_boot(result);
    if (cancellation != ESP_OK)
        ESP_LOGE(TAG, "OTA boot-selection cancellation failed: %s", esp_err_to_name(cancellation));
    pm_network_health_update(&s_network, PM_HEALTH_OTA_FAILED, true);
    (void)pm_command_transition(&s_commands, command, PM_COMMAND_FAILED,
                                command->progress_percent, result);
    free_ota_task_context(task); release_ota_task(); vTaskDelete(NULL);
}

static void process_result_acknowledgements(void)
{
    pm_result_ack_event_t accepted = {0};
    while (xQueueReceive(s_result_ack_queue, &accepted, 0U) == pdTRUE) {
        const esp_err_t error = pm_command_acknowledge_result(&s_commands, accepted.command_id);
        if (error != ESP_OK && error != ESP_ERR_NOT_FOUND)
            ESP_LOGE(TAG, "command result acknowledgement failed: %s", esp_err_to_name(error));
        secure_zero(&accepted, sizeof(accepted));
    }
}

static void execute_command(pm_command_t *command)
{
    if (command == NULL || pm_commands_lock() != ESP_OK) return;
    (void)pm_command_transition(&s_commands, command, PM_COMMAND_RUNNING, 1U, ESP_OK);
    esp_err_t result = ESP_OK;
    switch (command->type) {
    case PM_COMMAND_REBOOT:
        result = pm_command_transition(&s_commands, command, PM_COMMAND_AWAITING_REBOOT,
                                       100U, ESP_OK);
        if (result == ESP_OK) { pm_commands_unlock(); vTaskDelay(pdMS_TO_TICKS(500)); esp_restart(); }
        break;
    case PM_COMMAND_DIAGNOSTICS_SNAPSHOT: {
        pm_diagnostics_snapshot_t snapshot = {0};
        pm_diagnostics_capture(&snapshot);
        (void)snprintf(command->result_text, sizeof(command->result_text),
                       "heap=%lu,min=%lu,largest=%lu,psram=%lu,reset=%lu",
                       (unsigned long)snapshot.free_internal_heap,
                       (unsigned long)snapshot.minimum_free_internal_heap,
                       (unsigned long)snapshot.largest_internal_block,
                       (unsigned long)snapshot.free_psram,
                       (unsigned long)snapshot.reboot_reason);
        break;
    }
    case PM_COMMAND_NETWORK_SELF_TEST:
        (void)snprintf(command->result_text, sizeof(command->result_text),
                       "outbound_telemetry_retry_active");
        break;
    case PM_COMMAND_METER_SELF_TEST: {
        pm_meter_sample_t sample = {0}; bool present = false;
        result = pm_network_copy_live(&sample, &present);
        if (result == ESP_OK && (!present || sample.status != PM_PZEM_OK))
            result = ESP_ERR_INVALID_RESPONSE;
        (void)snprintf(command->result_text, sizeof(command->result_text), "pzem_status=%s",
                       present ? pm_pzem_status_name(sample.status) : "absent");
        break;
    }
    case PM_COMMAND_OTA_INSTALL: {
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
                pm_commands_unlock(); return;
            }
            result = ESP_ERR_NO_MEM;
        }
        free_ota_task_context(ota); release_ota_task();
        break;
    }
    default:
        result = ESP_ERR_NOT_SUPPORTED;
        break;
    }
    (void)pm_command_transition(&s_commands, command,
                                result == ESP_OK ? PM_COMMAND_SUCCEEDED : PM_COMMAND_FAILED,
                                result == ESP_OK ? 100U : command->progress_percent, result);
    pm_commands_unlock();
}

static void control_task(void *argument)
{
    (void)argument;
    if (!begin_runtime_task(PM_CONTROL_READY_BIT)) { vTaskDelete(NULL); return; }
    for (;;) {
        if (pm_commands_lock() == ESP_OK) {
            process_result_acknowledgements();
            pm_commands_unlock();
        }
        pm_command_t *command = NULL;
        if (xQueueReceive(s_command_queue, &command, pdMS_TO_TICKS(1000)) == pdTRUE)
            execute_command(command);
        (void)esp_task_wdt_reset();
    }
}

static void authenticated_result_acknowledged(const char command_id[PM_COMMAND_ID_MAX + 1U],
                                               void *context)
{
    (void)context;
    if (command_id == NULL || strlen(command_id) != PM_COMMAND_ID_MAX) return;
    pm_result_ack_event_t event = {0};
    (void)snprintf(event.command_id, sizeof(event.command_id), "%s", command_id);
    if (xQueueSend(s_result_ack_queue, &event, 0U) != pdTRUE)
        ESP_LOGE(TAG, "bounded result acknowledgement queue full");
    secure_zero(&event, sizeof(event));
}

static void command_received(const pm_command_t *command, void *context)
{
    (void)context;
    pm_command_t *mutable_command = (pm_command_t *)command;
    if (xQueueSend(s_command_queue, &mutable_command, 0U) != pdTRUE)
        ESP_LOGE(TAG, "bounded command queue full");
}

static esp_err_t reconcile_interrupted_commands(const pm_ota_checkpoint_t *checkpoint)
{
    if (checkpoint == NULL || pm_commands_lock() != ESP_OK) return ESP_ERR_INVALID_ARG;
    esp_err_t error = ESP_OK;
    for (size_t i = 0U; i < PM_COMMAND_LEDGER_SIZE && error == ESP_OK; ++i) {
        pm_command_t *command = &s_commands.entries[i];
        if (command->command_id[0] == '\0') continue;
        switch (pm_command_boot_action(command)) {
        case PM_COMMAND_BOOT_FAIL_INTERRUPTED:
            error = pm_command_reconcile_boot(&s_commands, command, PM_COMMAND_FAILED,
                                              ESP_ERR_INVALID_STATE, "interrupted_by_reboot"); break;
        case PM_COMMAND_BOOT_COMPLETE_REBOOT:
            error = pm_command_reconcile_boot(&s_commands, command, PM_COMMAND_SUCCEEDED,
                                              ESP_OK, "reboot_observed"); break;
        case PM_COMMAND_BOOT_RECONCILE_OTA:
            if (checkpoint->stage == PM_OTA_VALID)
                error = pm_command_reconcile_boot(&s_commands, command, PM_COMMAND_SUCCEEDED,
                                                  ESP_OK, "ota_post_boot_valid");
            else if (checkpoint->stage == PM_OTA_ROLLED_BACK)
                error = pm_command_reconcile_boot(&s_commands, command, PM_COMMAND_ROLLED_BACK,
                                                  checkpoint->last_error == ESP_OK ?
                                                      ESP_ERR_INVALID_STATE : checkpoint->last_error,
                                                  "ota_rolled_back");
            else
                error = pm_command_reconcile_boot(&s_commands, command, PM_COMMAND_FAILED,
                                                  checkpoint->last_error == ESP_OK ?
                                                      ESP_ERR_INVALID_STATE : checkpoint->last_error,
                                                  "ota_outcome_unavailable");
            break;
        case PM_COMMAND_BOOT_REQUEUE:
            if (xQueueSend(s_command_queue, &command, 0U) != pdTRUE) error = ESP_ERR_NO_MEM;
            break;
        default: break;
        }
    }
    pm_commands_unlock();
    return error;
}

static void supervisor_task(void *argument)
{
    (void)argument;
    if (!begin_runtime_task(PM_SUPERVISOR_READY_BIT)) { vTaskDelete(NULL); return; }
    int64_t last_checkpoint = 0;
    for (;;) {
        const int64_t now_us = esp_timer_get_time();
        if (!s_time.trusted || now_us - last_checkpoint >= INT64_C(3600000000)) {
            const int64_t utc_ms = (int64_t)time(NULL) * 1000;
            if (utc_ms >= INT64_C(1704067200000) &&
                pm_time_observe(&s_time, PM_TIME_SNTP, utc_ms, now_us) == ESP_OK)
                last_checkpoint = now_us;
        }
        (void)esp_task_wdt_reset(); vTaskDelay(pdMS_TO_TICKS(5000));
    }
}

void app_main(void)
{
    pm_state_init(&s_state, esp_timer_get_time());
    (void)pm_state_transition(&s_state, PM_EVENT_BOOTSTRAP, esp_timer_get_time());
    esp_err_t error = nvs_flash_init();
    if (error != ESP_OK) {
        ESP_LOGE(TAG, "NVS initialization failed without destructive erase: %s", esp_err_to_name(error));
        return;
    }
    uint8_t identity[16] = {0};
    if (load_or_create_identity(identity) != ESP_OK || pm_commands_load(&s_commands) != ESP_OK) {
        ESP_LOGE(TAG, "identity/command recovery failed closed"); return;
    }
    error = pm_config_load(&s_config);
    const bool provisioned = error == ESP_OK;
    if (!provisioned) {
        secure_zero(&s_config, sizeof(s_config));
        s_config.schema_version = PM_CONFIG_SCHEMA_VERSION;
        memcpy(s_config.device_id, identity, sizeof(identity));
        s_config.ct_rating_a = 100U;
        s_config.meter_variant = PM_METER_PZEM004T_V4_CLASSIC;
    } else if (memcmp(s_config.device_id, identity, sizeof(identity)) != 0) {
        if (persist_identity(s_config.device_id) != ESP_OK) {
            ESP_LOGE(TAG, "enrolled identity checkpoint failed"); return;
        }
        memcpy(identity, s_config.device_id, sizeof(identity));
    }
    pm_time_init(&s_time, esp_timer_get_time());
    (void)pm_time_load_checkpoint(&s_time, esp_timer_get_time());
    const bool physical_recovery = wait_for_physical_recovery_request(provisioned);
    pm_provisioning_session_init(&s_provisioning, &s_config,
                                 physical_recovery || !provisioned,
                                 pm_network_provisioning_test, NULL,
                                 prepare_safe_reboot_from_com, NULL);
    if (!provisioned || physical_recovery) {
        (void)pm_state_transition(&s_state, !provisioned ? PM_EVENT_CONFIG_MISSING :
                                                             PM_EVENT_PHYSICAL_RECOVERY,
                                  esp_timer_get_time());
        error = pm_provisioning_start_usb(&s_provisioning);
        if (error != ESP_OK) ESP_LOGE(TAG, "USB provisioning task failed: %s", esp_err_to_name(error));
        return;
    }
    error = pm_meter_create(&s_meter, PM_METER_PZEM004T_V4_CLASSIC,
                            PM_BUILD_PZEM_LIVE_READS, PM_BUILD_SIMULATED_METER);
    if (error != ESP_OK) set_degraded(PM_EVENT_METER_FAILED);
    s_command_queue = xQueueCreateStatic(PM_COMMAND_QUEUE_DEPTH, sizeof(pm_command_t *),
                                         s_command_queue_storage, &s_command_queue_buffer);
    s_result_ack_queue = xQueueCreateStatic(PM_RESULT_ACK_QUEUE_DEPTH,
                                            sizeof(pm_result_ack_event_t),
                                            s_result_ack_queue_storage,
                                            &s_result_ack_queue_buffer);
    s_runtime_start_gate = xEventGroupCreateStatic(&s_runtime_start_gate_storage);
    if (s_command_queue == NULL || s_result_ack_queue == NULL || s_runtime_start_gate == NULL) {
        ESP_LOGE(TAG, "static runtime allocation failed"); return;
    }
    s_network.commands = &s_commands;
    s_network.command_callback = command_received;
    s_network.result_ack_callback = authenticated_result_acknowledged;
    s_network.start_gate = s_runtime_start_gate;
    s_network.start_bit = PM_NETWORK_START_BIT;
    error = pm_network_apply_runtime_config(&s_network, &s_config);
    if (error != ESP_OK) { ESP_LOGE(TAG, "runtime credential initialization failed"); return; }
    const pm_runtime_task_spec_t tasks[] = {
        {measurement_task, "pm_measurement", 4096U, NULL, 12U, &s_measurement_task},
        {control_task, "pm_control", 6144U, NULL, 6U, &s_control_task},
        {supervisor_task, "pm_supervisor", 4096U, NULL, 5U, &s_supervisor_task},
    };
    error = pm_runtime_create_task_set(tasks, sizeof(tasks) / sizeof(tasks[0]));
    if (error != ESP_OK) { ESP_LOGE(TAG, "runtime task allocation failed"); return; }
    const esp_err_t network_error = pm_network_start(&s_network);
    (void)xEventGroupSetBits(s_runtime_start_gate, PM_RUNTIME_START_BIT);
    const EventBits_t ready = xEventGroupWaitBits(s_runtime_start_gate, PM_RUNTIME_READY_BITS,
                                                  pdFALSE, pdTRUE, pdMS_TO_TICKS(5000));
    const bool runtime_ready = (ready & PM_RUNTIME_READY_BITS) == PM_RUNTIME_READY_BITS &&
        (xEventGroupGetBits(s_runtime_start_gate) & PM_RUNTIME_TASK_FAILED_BIT) == 0U;
    if (!runtime_ready) { ESP_LOGE(TAG, "runtime readiness failed"); esp_restart(); }
    /* This local ESP-IDF rollback gate proves only that the runtime and its bounded
     * network retry task were created.  The server separately keeps an OTA deployment
     * pending until authenticated telemetry reports the expected version and complete
     * 64-character build identifier. */
    error = pm_ota_post_boot_validate(provisioned, runtime_ready, runtime_ready, true,
                                      network_error == ESP_OK);
    if (error != ESP_OK) { ESP_LOGE(TAG, "OTA post-boot validation failed"); esp_restart(); }
    pm_ota_checkpoint_t checkpoint = {0};
    error = pm_ota_load_checkpoint(&checkpoint);
    if (error != ESP_OK || reconcile_interrupted_commands(&checkpoint) != ESP_OK) {
        ESP_LOGE(TAG, "command boot reconciliation failed closed"); esp_restart();
    }
    pm_network_health_update(&s_network, PM_HEALTH_OTA_FAILED,
                             checkpoint.stage == PM_OTA_FAILED);
    pm_network_health_update(&s_network, PM_HEALTH_OTA_ROLLED_BACK,
                             checkpoint.stage == PM_OTA_ROLLED_BACK);
    (void)xEventGroupSetBits(s_runtime_start_gate, PM_NETWORK_START_BIT);
    (void)pm_state_transition(&s_state, network_error == ESP_OK ? PM_EVENT_SELF_TEST_OK :
                                                                  PM_EVENT_WIFI_FAILED,
                              esp_timer_get_time());
}
