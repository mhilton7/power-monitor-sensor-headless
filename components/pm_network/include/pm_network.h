#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "esp_err.h"
#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"
#include "freertos/semphr.h"
#include "pm_commands.h"
#include "pm_config.h"
#include "pm_meter.h"
#include "pm_provisioning.h"
#include "pm_protocol.h"
#include "pm_storage.h"

#ifdef __cplusplus
extern "C" {
#endif

#define PM_NETWORK_RESPONSE_MAX 4096U
#define PM_NETWORK_BODY_MAX 8192U
#define PM_ENROLL_ENDPOINT "/api/v1/devices/enroll"
#define PM_HEARTBEAT_ENDPOINT "/api/v1/device/heartbeat"
#define PM_READINGS_ENDPOINT "/api/v1/device/readings"
#define PM_PERMANENT_LOSS_ENDPOINT "/api/v1/device/permanent-loss"

typedef enum {
    PM_TLS_ERROR_NONE = 0,
    PM_TLS_ERROR_DNS,
    PM_TLS_ERROR_CONNECT_TIMEOUT,
    PM_TLS_ERROR_HANDSHAKE,
    PM_TLS_ERROR_CA,
    PM_TLS_ERROR_HOSTNAME,
    PM_TLS_ERROR_SEND,
    PM_TLS_ERROR_RECEIVE,
    PM_TLS_ERROR_SERVER_RESET,
    PM_TLS_ERROR_HTTP_STATUS,
    PM_TLS_ERROR_RESPONSE_LIMIT,
} pm_tls_error_class_t;

typedef struct {
    int64_t next_heartbeat_us;
    int64_t heartbeat_period_us;
    int64_t last_heartbeat_us;
    uint32_t consecutive_missed;
    uint32_t adaptive_batch_records;
    bool request_in_progress;
} pm_network_scheduler_t;

typedef void (*pm_network_command_fn)(const pm_command_t *command, void *context);
typedef void (*pm_network_result_ack_fn)(const char command_id[PM_COMMAND_ID_MAX + 1U], void *context);

typedef enum {
    PM_HEALTH_TLS_VALIDATION_FAILURE = 1U << 0,
    PM_HEALTH_WIFI_REPEATED_FAILURE = 1U << 1,
    PM_HEALTH_OTA_FAILED = 1U << 2,
    PM_HEALTH_OTA_ROLLED_BACK = 1U << 3,
} pm_network_health_flag_t;

/* Immutable credentials captured for exactly one outbound HTTP/OTA operation.
 * The live context mutex is never held while performing network or flash I/O. */
typedef struct {
    char server_origin[PM_CONFIG_ORIGIN_MAX + 1U];
    char ca_pem[PM_CONFIG_CA_MAX + 1U];
    char device_id_text[37];
    uint8_t device_to_server_key[32];
    uint8_t server_to_device_key[32];
    uint32_t config_generation;
} pm_network_auth_snapshot_t;

typedef struct {
    pm_config_t config;
    char device_id_text[37];
    uint8_t device_to_server_key[32];
    uint8_t server_to_device_key[32];
    pm_sequence_state_t *sequence;
    pm_storage_health_t *storage;
    pm_command_ledger_t *commands;
    pm_network_command_fn command_callback;
    void *command_context;
    pm_network_result_ack_fn result_ack_callback;
    void *result_ack_context;
    char boot_id[37];
    pm_nonce_cache_t response_nonce_cache;
    uint32_t health_flags;
    uint64_t permanent_loss_reported_through;
    pm_tls_error_class_t last_request_error;
    StaticSemaphore_t credential_mutex_storage;
    SemaphoreHandle_t credential_mutex;
    EventGroupHandle_t start_gate;
    EventBits_t start_bit;
} pm_network_context_t;

void pm_network_scheduler_init(pm_network_scheduler_t *scheduler, int64_t now_us, uint32_t heartbeat_seconds);
bool pm_network_heartbeat_due(const pm_network_scheduler_t *scheduler, int64_t now_us);
bool pm_network_backlog_allowed(const pm_network_scheduler_t *scheduler, int64_t now_us,
                                int64_t worst_case_request_us);
void pm_network_heartbeat_complete(pm_network_scheduler_t *scheduler, int64_t now_us, bool success);
uint32_t pm_network_reconnect_delay_ms(uint32_t attempt, uint32_t random_value);
pm_tls_error_class_t pm_network_classify_error(esp_err_t error, int http_status);
esp_err_t pm_network_publish_live(const pm_meter_sample_t *sample);
void pm_network_request_sync(void);
void pm_network_health_update(pm_network_context_t *context, pm_network_health_flag_t flag, bool active);
esp_err_t pm_network_serialize_heartbeat(pm_network_context_t *context, const pm_meter_sample_t *sample,
                                        bool sample_present, char *body, size_t body_size);
esp_err_t pm_network_serialize_reading_batch(const pm_storage_batch_t *batch, char *body, size_t body_size);
esp_err_t pm_network_serialize_permanent_loss(const pm_storage_health_t *storage, char *body, size_t body_size);
esp_err_t pm_network_apply_runtime_config(pm_network_context_t *context, const pm_config_t *config);
esp_err_t pm_network_capture_auth_snapshot(pm_network_context_t *context, pm_network_auth_snapshot_t *snapshot);
void pm_network_clear_auth_snapshot(pm_network_auth_snapshot_t *snapshot);
esp_err_t pm_network_start(pm_network_context_t *context);
esp_err_t pm_network_provisioning_test(pm_provisioning_test_stage_t stage, pm_config_t *candidate,
                                       const char *enrollment_token, void *context);
bool pm_network_parse_rfc3339_ms(const char *value, int64_t *utc_ms);

#ifdef __cplusplus
}
#endif
