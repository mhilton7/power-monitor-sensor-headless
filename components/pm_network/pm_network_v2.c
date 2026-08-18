#include "pm_network.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "cJSON.h"
#include "esp_app_desc.h"
#include "esp_event.h"
#include "esp_heap_caps.h"
#include "esp_http_client.h"
#include "esp_log.h"
#include "esp_mac.h"
#include "esp_netif.h"
#include "esp_netif_sntp.h"
#include "esp_random.h"
#include "esp_timer.h"
#include "esp_wifi.h"
#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"
#include "freertos/task.h"
#include "lwip/inet.h"
#include "mbedtls/base64.h"
#include "pm_command_envelope.h"
#include "pm_diagnostics.h"
#include "pm_http_response.h"

#define PM_WIFI_CONNECTED_BIT BIT0
#define PM_WIFI_FAILED_BIT BIT1
#define PM_NETWORK_TASK_STACK 16384U
#define PM_REQUEST_TIMEOUT_MS 12000
#define PM_TELEMETRY_MIN_SECONDS 2U
#define PM_TELEMETRY_MAX_SECONDS 60U

static const char *const TAG = "pm_network";
static EventGroupHandle_t s_wifi_events;
static pm_telemetry_slot_t s_telemetry;
static portMUX_TYPE s_telemetry_lock = portMUX_INITIALIZER_UNLOCKED;
static portMUX_TYPE s_credential_mutex_init_lock = portMUX_INITIALIZER_UNLOCKED;

typedef struct {
    char body[PM_NETWORK_BODY_MAX + 1U];
    char response[PM_NETWORK_RESPONSE_MAX];
    pm_network_auth_snapshot_t auth;
} pm_network_io_workspace_t;

typedef struct {
    pm_network_context_t *network;
    pm_network_io_workspace_t io;
    pm_config_t startup_config;
} pm_network_task_context_t;

static void secure_zero_memory(void *value, size_t length)
{
    volatile uint8_t *bytes = (volatile uint8_t *)value;
    while (length-- > 0U) {
        *bytes++ = 0U;
    }
}

static esp_err_t ensure_credential_mutex(pm_network_context_t *context)
{
    if (context == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    if (context->credential_mutex == NULL) {
        taskENTER_CRITICAL(&s_credential_mutex_init_lock);
        if (context->credential_mutex == NULL) {
            context->credential_mutex = xSemaphoreCreateMutexStatic(&context->credential_mutex_storage);
        }
        taskEXIT_CRITICAL(&s_credential_mutex_init_lock);
    }
    return context->credential_mutex == NULL ? ESP_ERR_NO_MEM : ESP_OK;
}

static void format_device_id(const uint8_t id[PM_CONFIG_DEVICE_ID_LEN], char output[37])
{
    (void)snprintf(output, 37U,
                   "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
                   id[0], id[1], id[2], id[3], id[4], id[5], id[6], id[7],
                   id[8], id[9], id[10], id[11], id[12], id[13], id[14], id[15]);
}

esp_err_t pm_network_apply_runtime_config(pm_network_context_t *context, const pm_config_t *config)
{
    if (context == NULL || config == NULL || config->device_secret_len < 16U ||
        config->device_secret_len > PM_CONFIG_SECRET_MAX ||
        strnlen(config->server_origin, sizeof(config->server_origin)) >= sizeof(config->server_origin) ||
        strnlen(config->ca_pem, sizeof(config->ca_pem)) >= sizeof(config->ca_pem)) {
        return ESP_ERR_INVALID_ARG;
    }
    char device_id_text[37] = {0};
    uint8_t device_to_server_key[32] = {0};
    uint8_t server_to_device_key[32] = {0};
    format_device_id(config->device_id, device_id_text);
    esp_err_t error = pm_hkdf_directional_keys(config->device_secret, config->device_secret_len,
                                               device_id_text, device_to_server_key,
                                               server_to_device_key);
    if (error == ESP_OK) {
        error = ensure_credential_mutex(context);
    }
    if (error == ESP_OK && xSemaphoreTake(context->credential_mutex, portMAX_DELAY) != pdTRUE) {
        error = ESP_ERR_TIMEOUT;
    } else if (error == ESP_OK) {
        context->config = *config;
        memcpy(context->device_id_text, device_id_text, sizeof(context->device_id_text));
        memcpy(context->device_to_server_key, device_to_server_key,
               sizeof(context->device_to_server_key));
        memcpy(context->server_to_device_key, server_to_device_key,
               sizeof(context->server_to_device_key));
        (void)xSemaphoreGive(context->credential_mutex);
    }
    secure_zero_memory(device_id_text, sizeof(device_id_text));
    secure_zero_memory(device_to_server_key, sizeof(device_to_server_key));
    secure_zero_memory(server_to_device_key, sizeof(server_to_device_key));
    return error;
}

esp_err_t pm_network_capture_auth_snapshot(pm_network_context_t *context,
                                           pm_network_auth_snapshot_t *snapshot)
{
    if (context == NULL || snapshot == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    secure_zero_memory(snapshot, sizeof(*snapshot));
    esp_err_t error = ensure_credential_mutex(context);
    if (error != ESP_OK) {
        return error;
    }
    if (xSemaphoreTake(context->credential_mutex, portMAX_DELAY) != pdTRUE) {
        return ESP_ERR_TIMEOUT;
    }
    memcpy(snapshot->server_origin, context->config.server_origin,
           sizeof(snapshot->server_origin));
    memcpy(snapshot->ca_pem, context->config.ca_pem, sizeof(snapshot->ca_pem));
    memcpy(snapshot->device_id_text, context->device_id_text,
           sizeof(snapshot->device_id_text));
    memcpy(snapshot->device_to_server_key, context->device_to_server_key,
           sizeof(snapshot->device_to_server_key));
    memcpy(snapshot->server_to_device_key, context->server_to_device_key,
           sizeof(snapshot->server_to_device_key));
    snapshot->config_generation = context->config.generation;
    (void)xSemaphoreGive(context->credential_mutex);
    if (snapshot->server_origin[0] == '\0' || snapshot->ca_pem[0] == '\0' ||
        strlen(snapshot->device_id_text) != 36U) {
        secure_zero_memory(snapshot, sizeof(*snapshot));
        return ESP_ERR_INVALID_STATE;
    }
    return ESP_OK;
}

void pm_network_clear_auth_snapshot(pm_network_auth_snapshot_t *snapshot)
{
    if (snapshot != NULL) {
        secure_zero_memory(snapshot, sizeof(*snapshot));
    }
}

void pm_network_scheduler_init(pm_network_scheduler_t *scheduler, int64_t now_us,
                               uint32_t telemetry_seconds)
{
    if (scheduler == NULL) {
        return;
    }
    const uint32_t bounded = telemetry_seconds < PM_TELEMETRY_MIN_SECONDS ?
                                 PM_TELEMETRY_MIN_SECONDS :
                             telemetry_seconds > PM_TELEMETRY_MAX_SECONDS ?
                                 PM_TELEMETRY_MAX_SECONDS : telemetry_seconds;
    *scheduler = (pm_network_scheduler_t){
        .next_telemetry_us = now_us,
        .telemetry_period_us = (int64_t)bounded * INT64_C(1000000),
    };
    pm_telemetry_backoff_reset(&scheduler->server_backoff, now_us);
}

bool pm_network_telemetry_due(const pm_network_scheduler_t *scheduler, int64_t now_us)
{
    return scheduler != NULL && !scheduler->request_in_progress &&
           now_us >= scheduler->next_telemetry_us &&
           pm_telemetry_backoff_due(&scheduler->server_backoff, now_us);
}

void pm_network_telemetry_complete(pm_network_scheduler_t *scheduler, int64_t now_us,
                                   bool success, uint32_t random_value)
{
    if (scheduler == NULL) {
        return;
    }
    scheduler->request_in_progress = false;
    if (success) {
        pm_telemetry_backoff_reset(&scheduler->server_backoff, now_us);
        scheduler->next_telemetry_us = pm_telemetry_next_fixed_deadline(
            scheduler->next_telemetry_us, now_us, scheduler->telemetry_period_us);
    } else {
        const uint32_t delay = pm_telemetry_backoff_fail(&scheduler->server_backoff,
                                                         now_us, random_value);
        scheduler->next_telemetry_us = now_us + (int64_t)delay * INT64_C(1000);
    }
}

uint32_t pm_network_reconnect_delay_ms(uint32_t attempt, uint32_t random_value)
{
    pm_telemetry_backoff_t backoff = {.failures = attempt};
    return pm_telemetry_backoff_fail(&backoff, 0, random_value);
}

pm_tls_error_class_t pm_network_classify_error(esp_err_t error, int http_status)
{
    if (error == ESP_OK && http_status >= 200 && http_status < 300) {
        return PM_TLS_ERROR_NONE;
    }
    if (http_status != 0 && (http_status < 200 || http_status >= 300)) {
        return PM_TLS_ERROR_HTTP_STATUS;
    }
    if (error == ESP_ERR_TIMEOUT) {
        return PM_TLS_ERROR_CONNECT_TIMEOUT;
    }
    if (error == ESP_ERR_HTTP_CONNECT) {
        return PM_TLS_ERROR_HANDSHAKE;
    }
    if (error == ESP_ERR_HTTP_WRITE_DATA) {
        return PM_TLS_ERROR_SEND;
    }
    if (error == ESP_ERR_HTTP_INCOMPLETE_DATA) {
        return PM_TLS_ERROR_RECEIVE;
    }
    return PM_TLS_ERROR_SERVER_RESET;
}

esp_err_t pm_network_publish_live(const pm_meter_sample_t *sample)
{
    if (sample == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    taskENTER_CRITICAL(&s_telemetry_lock);
    const esp_err_t error = pm_telemetry_offer(&s_telemetry, sample, NULL);
    taskEXIT_CRITICAL(&s_telemetry_lock);
    return error;
}

esp_err_t pm_network_copy_live(pm_meter_sample_t *sample, bool *present)
{
    if (sample == NULL || present == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    taskENTER_CRITICAL(&s_telemetry_lock);
    if (s_telemetry.pending_present) {
        *sample = s_telemetry.pending.measurement;
        *present = true;
    } else if (s_telemetry.in_flight_present) {
        *sample = s_telemetry.in_flight.measurement;
        *present = true;
    } else {
        memset(sample, 0, sizeof(*sample));
        *present = false;
    }
    taskEXIT_CRITICAL(&s_telemetry_lock);
    return ESP_OK;
}

size_t pm_network_resident_telemetry_samples(void)
{
    taskENTER_CRITICAL(&s_telemetry_lock);
    const size_t count = pm_telemetry_resident_samples(&s_telemetry);
    taskEXIT_CRITICAL(&s_telemetry_lock);
    return count;
}

void pm_network_health_update(pm_network_context_t *context, pm_network_health_flag_t flag,
                              bool active)
{
    if (context != NULL) {
        if (active) {
            context->health_flags |= (uint32_t)flag;
        } else {
            context->health_flags &= ~(uint32_t)flag;
        }
    }
}

static bool json_add_u64(cJSON *object, const char *name, uint64_t value)
{
    char number[24];
    if (snprintf(number, sizeof(number), "%llu", (unsigned long long)value) < 0) {
        return false;
    }
    cJSON *raw = cJSON_CreateRaw(number);
    return raw != NULL && cJSON_AddItemToObject(object, name, raw);
}

static bool json_add_decimal_milli(cJSON *object, const char *name, int32_t milli)
{
    char value[32];
    const int64_t magnitude = milli < 0 ? -(int64_t)milli : (int64_t)milli;
    const int written = snprintf(value, sizeof(value), "%s%lld.%03lld", milli < 0 ? "-" : "",
                                 (long long)(magnitude / 1000),
                                 (long long)(magnitude % 1000));
    return written > 0 && (size_t)written < sizeof(value) &&
           cJSON_AddStringToObject(object, name, value) != NULL;
}

static bool format_rfc3339_ms(int64_t utc_ms, char output[32])
{
    if (utc_ms < INT64_C(1704067200000)) {
        return false;
    }
    const time_t seconds = (time_t)(utc_ms / 1000);
    struct tm utc = {0};
    if (gmtime_r(&seconds, &utc) == NULL) {
        return false;
    }
    const int written = snprintf(output, 32U, "%04d-%02d-%02dT%02d:%02d:%02d.%03lldZ",
                                 utc.tm_year + 1900, utc.tm_mon + 1, utc.tm_mday,
                                 utc.tm_hour, utc.tm_min, utc.tm_sec,
                                 (long long)(utc_ms % 1000));
    return written == 24;
}

static const char *contract_pzem_status(pm_pzem_status_t status)
{
    switch (status) {
    case PM_PZEM_OK: return "ok";
    case PM_PZEM_TIMEOUT: return "timeout";
    case PM_PZEM_SHORT_FRAME: return "short_frame";
    case PM_PZEM_BAD_CRC: return "bad_crc";
    case PM_PZEM_WRONG_SLAVE: return "wrong_address";
    case PM_PZEM_NOT_VERIFIED: return "absent";
    default: return "invalid";
    }
}

static bool command_result_state(pm_command_state_t state)
{
    return state == PM_COMMAND_ACCEPTED || state == PM_COMMAND_RUNNING ||
           state == PM_COMMAND_SUCCEEDED || state == PM_COMMAND_FAILED ||
           state == PM_COMMAND_AWAITING_REBOOT || state == PM_COMMAND_ROLLED_BACK;
}

static const char *command_result_code(const pm_command_t *command, char output[32])
{
    if (command->state == PM_COMMAND_ACCEPTED) return "accepted";
    if (command->state == PM_COMMAND_RUNNING) return "in_progress";
    if (command->state == PM_COMMAND_AWAITING_REBOOT) return "awaiting_reboot";
    if (command->state == PM_COMMAND_ROLLED_BACK) return "rolled_back";
    if (command->state == PM_COMMAND_SUCCEEDED && command->result_code == ESP_OK) return "ok";
    esp_err_to_name_r((esp_err_t)command->result_code, output, 32U);
    return output;
}

static esp_err_t append_command_results(pm_network_context_t *context, cJSON *results)
{
    for (size_t i = 0U; i < PM_COMMAND_LEDGER_SIZE; ++i) {
        const pm_command_t *command = &context->commands->entries[i];
        if (strlen(command->command_id) != PM_COMMAND_ID_MAX ||
            !command_result_state(command->state)) {
            continue;
        }
        cJSON *result = cJSON_CreateObject();
        cJSON *evidence = cJSON_CreateObject();
        if (result == NULL || evidence == NULL) {
            cJSON_Delete(result);
            cJSON_Delete(evidence);
            return ESP_ERR_NO_MEM;
        }
        char result_code[32];
        cJSON_AddStringToObject(result, "command_id", command->command_id);
        cJSON_AddStringToObject(result, "state", pm_command_state_name(command->state));
        cJSON_AddNumberToObject(result, "progress_percent", command->progress_percent);
        cJSON_AddStringToObject(result, "result_code",
                               command_result_code(command, result_code));
        cJSON_AddNumberToObject(evidence, "attempt", command->attempt);
        if (command->result_text[0] != '\0') {
            char redacted[PM_COMMAND_RESULT_MAX + 1U];
            pm_diagnostics_redact(command->result_text, redacted, sizeof(redacted));
            cJSON_AddStringToObject(evidence, "detail", redacted);
        }
        cJSON_AddItemToObject(result, "evidence", evidence);
        cJSON_AddItemToArray(results, result);
    }
    return ESP_OK;
}

esp_err_t pm_network_serialize_telemetry(pm_network_context_t *context,
                                        const pm_telemetry_sample_t *sample,
                                        char *body, size_t body_size)
{
    if (context == NULL || context->commands == NULL || sample == NULL ||
        sample->sample_sequence == 0U || context->boot_id[0] == '\0' ||
        body == NULL || body_size < 3U) {
        return ESP_ERR_INVALID_ARG;
    }
    const pm_meter_sample_t *measurement = &sample->measurement;
    const bool valid = measurement->status == PM_PZEM_OK;
    const bool trusted = valid && measurement->time_trusted;
    cJSON *root = cJSON_CreateObject();
    cJSON *results = cJSON_CreateArray();
    if (root == NULL || results == NULL) {
        cJSON_Delete(root);
        cJSON_Delete(results);
        return ESP_ERR_NO_MEM;
    }
    cJSON_AddStringToObject(root, "telemetry_protocol", PM_TELEMETRY_PROTOCOL_ID);
    cJSON_AddStringToObject(root, "sensor_id", context->device_id_text);
    cJSON_AddStringToObject(root, "boot_id", context->boot_id);
    json_add_u64(root, "sample_sequence", sample->sample_sequence);
    char timestamp[32];
    if (trusted && format_rfc3339_ms(measurement->sample_timestamp_utc_ms, timestamp)) {
        cJSON_AddStringToObject(root, "sampled_at", timestamp);
    } else {
        cJSON_AddNullToObject(root, "sampled_at");
    }
    json_add_u64(root, "uptime_ms", measurement->sample_monotonic_us > 0 ?
                                      (uint64_t)measurement->sample_monotonic_us / 1000U : 0U);
    if (valid) {
        json_add_decimal_milli(root, "voltage_v", measurement->voltage_mv);
        json_add_decimal_milli(root, "current_a", measurement->current_ma);
        json_add_decimal_milli(root, "active_power_w", measurement->active_power_mw);
        json_add_decimal_milli(root, "frequency_hz", measurement->frequency_mhz);
        json_add_decimal_milli(root, "power_factor", measurement->power_factor_milli);
        json_add_u64(root, "pzem_energy_wh", measurement->energy_wh);
    } else {
        cJSON_AddNullToObject(root, "voltage_v");
        cJSON_AddNullToObject(root, "current_a");
        cJSON_AddNullToObject(root, "active_power_w");
        cJSON_AddNullToObject(root, "frequency_hz");
        cJSON_AddNullToObject(root, "power_factor");
        cJSON_AddNullToObject(root, "pzem_energy_wh");
    }
    cJSON_AddStringToObject(root, "pzem_status", contract_pzem_status(measurement->status));
    const esp_app_desc_t *description = esp_app_get_description();
    cJSON_AddStringToObject(root, "firmware_version", description->version);
    char build_id[PM_SHA256_HEX_SIZE + 1U];
    pm_hex_lower((const uint8_t *)description->app_elf_sha256,
                 sizeof(description->app_elf_sha256), build_id, sizeof(build_id));
    cJSON_AddStringToObject(root, "firmware_build_id", build_id);
    cJSON_AddStringToObject(root, "time_status", trusted ? "trusted" : "untrusted");
    wifi_ap_record_t access_point = {0};
    if (esp_wifi_sta_get_ap_info(&access_point) == ESP_OK) {
        cJSON_AddNumberToObject(root, "wifi_rssi", access_point.rssi);
    } else {
        cJSON_AddNullToObject(root, "wifi_rssi");
    }
    esp_err_t error = append_command_results(context, results);
    if (error == ESP_OK) {
        cJSON_AddItemToObject(root, "command_results", results);
        results = NULL;
        error = cJSON_PrintPreallocated(root, body, (int)body_size, false) ?
                    ESP_OK : ESP_ERR_INVALID_SIZE;
    }
    secure_zero_memory(build_id, sizeof(build_id));
    cJSON_Delete(results);
    cJSON_Delete(root);
    return error;
}

static esp_err_t capture_response_header_event(esp_http_client_event_t *event)
{
    if (event == NULL || event->user_data == NULL) return ESP_ERR_INVALID_ARG;
    if (event->event_id != HTTP_EVENT_ON_HEADER) return ESP_OK;
    return pm_http_response_capture_header((pm_http_response_capture_t *)event->user_data,
                                           event->header_key, event->header_value);
}

static esp_err_t signed_request(pm_network_context_t *context,
                                pm_network_auth_snapshot_t *auth_snapshot,
                                const char *path, const char *body,
                                char *response, size_t response_size, int *status)
{
    if (context == NULL || auth_snapshot == NULL || path == NULL || body == NULL ||
        response == NULL || status == NULL || strlen(body) > PM_NETWORK_BODY_MAX) {
        return ESP_ERR_INVALID_ARG;
    }
    esp_err_t error = pm_network_capture_auth_snapshot(context, auth_snapshot);
    if (error != ESP_OK) return error;
    char url[PM_CONFIG_ORIGIN_MAX + 96U];
    if (snprintf(url, sizeof(url), "%s%s", auth_snapshot->server_origin, path) >=
        (int)sizeof(url)) {
        pm_network_clear_auth_snapshot(auth_snapshot);
        return ESP_ERR_INVALID_SIZE;
    }
    const int64_t utc_ms = (int64_t)time(NULL) * 1000;
    if (utc_ms < INT64_C(1704067200000)) {
        pm_network_clear_auth_snapshot(auth_snapshot);
        return ESP_ERR_INVALID_STATE;
    }
    uint8_t nonce[PM_NONCE_SIZE];
    esp_fill_random(nonce, sizeof(nonce));
    pm_auth_headers_t auth;
    error = pm_sign_request(auth_snapshot->device_to_server_key,
                            auth_snapshot->device_id_text, "POST", path, NULL,
                            utc_ms, nonce, (const uint8_t *)body, strlen(body), &auth);
    if (error != ESP_OK) {
        pm_network_clear_auth_snapshot(auth_snapshot);
        return error;
    }
    pm_http_response_capture_t response_headers;
    pm_http_response_capture_init(&response_headers);
    const esp_http_client_config_t config = {
        .url = url,
        .cert_pem = auth_snapshot->ca_pem,
        .timeout_ms = PM_REQUEST_TIMEOUT_MS,
        .buffer_size = 2048,
        .buffer_size_tx = 2048,
        .keep_alive_enable = true,
        .disable_auto_redirect = true,
        .event_handler = capture_response_header_event,
        .user_data = &response_headers,
    };
    esp_http_client_handle_t client = esp_http_client_init(&config);
    if (client == NULL) {
        pm_network_clear_auth_snapshot(auth_snapshot);
        return ESP_ERR_NO_MEM;
    }
    esp_http_client_set_method(client, HTTP_METHOD_POST);
    esp_http_client_set_header(client, "Content-Type", "application/json");
    esp_http_client_set_header(client, "X-PM-Protocol", auth.protocol);
    esp_http_client_set_header(client, "X-PM-Device-ID", auth.device_id);
    esp_http_client_set_header(client, "X-PM-Timestamp", auth.timestamp);
    esp_http_client_set_header(client, "X-PM-Nonce", auth.nonce);
    esp_http_client_set_header(client, "X-PM-Content-SHA256", auth.content_sha256);
    esp_http_client_set_header(client, "X-PM-Signature", auth.signature);
    const size_t body_length = strlen(body);
    error = esp_http_client_open(client, (int)body_length);
    if (error == ESP_OK && esp_http_client_write(client, body, (int)body_length) !=
                           (int)body_length) {
        error = ESP_ERR_HTTP_WRITE_DATA;
    }
    int64_t content_length = -1;
    if (error == ESP_OK) {
        content_length = esp_http_client_fetch_headers(client);
        *status = esp_http_client_get_status_code(client);
        if (content_length < 0) error = ESP_ERR_HTTP_INCOMPLETE_DATA;
        else if (content_length > (int64_t)response_size - 1) error = ESP_ERR_INVALID_SIZE;
    }
    if (error == ESP_OK && *status >= 200 && *status < 300) {
        error = pm_http_response_capture_validate(&response_headers, false);
    }
    size_t used = 0U;
    while (error == ESP_OK && used + 1U < response_size) {
        const int read = esp_http_client_read(client, &response[used], response_size - used - 1U);
        if (read < 0) { error = ESP_ERR_HTTP_INCOMPLETE_DATA; break; }
        if (read == 0) break;
        used += (size_t)read;
    }
    response[used] = '\0';
    if (error == ESP_OK && used + 1U == response_size &&
        !esp_http_client_is_complete_data_received(client)) {
        error = ESP_ERR_INVALID_SIZE;
    }
    if (error == ESP_OK && (*status < 200 || *status >= 300)) {
        error = ESP_ERR_INVALID_RESPONSE;
    } else if (error == ESP_OK) {
        error = pm_verify_response(auth_snapshot->server_to_device_key,
                                   auth_snapshot->device_id_text, path, NULL, utc_ms,
                                   &response_headers.auth, (const uint8_t *)response, used,
                                   &context->response_nonce_cache);
    }
    context->last_request_error = pm_network_classify_error(error, *status);
    pm_network_health_update(context, PM_HEALTH_TLS_VALIDATION_FAILURE,
                             context->last_request_error == PM_TLS_ERROR_HANDSHAKE ||
                             context->last_request_error == PM_TLS_ERROR_CA ||
                             context->last_request_error == PM_TLS_ERROR_HOSTNAME);
    esp_http_client_close(client);
    esp_http_client_cleanup(client);
    pm_network_clear_auth_snapshot(auth_snapshot);
    return error;
}

static int64_t days_from_civil(int year, unsigned int month, unsigned int day)
{
    year -= month <= 2U ? 1 : 0;
    const int era = (year >= 0 ? year : year - 399) / 400;
    const unsigned int yoe = (unsigned int)(year - era * 400);
    const unsigned int doy = (153U * (month > 2U ? month - 3U : month + 9U) + 2U) /
                                 5U + day - 1U;
    const unsigned int doe = yoe * 365U + yoe / 4U - yoe / 100U + doy;
    return (int64_t)era * 146097 + (int64_t)doe - 719468;
}

bool pm_network_parse_rfc3339_ms(const char *value, int64_t *utc_ms)
{
    if (value == NULL || utc_ms == NULL || strlen(value) < 20U) return false;
    int year, month, day, hour, minute, second, consumed = 0;
    if (sscanf(value, "%4d-%2d-%2dT%2d:%2d:%2d%n", &year, &month, &day, &hour,
               &minute, &second, &consumed) != 6 || consumed != 19 || year < 1970 ||
        year > 9999 || month < 1 || month > 12 || hour < 0 || hour > 23 ||
        minute < 0 || minute > 59 || second < 0 || second > 60) return false;
    static const uint8_t mdays[] = {31U,28U,31U,30U,31U,30U,31U,31U,30U,31U,30U,31U};
    const bool leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    const unsigned int maximum = month == 2 ? mdays[1] + (leap ? 1U : 0U) : mdays[month - 1];
    if (day < 1 || (unsigned int)day > maximum) return false;
    const char *cursor = &value[19];
    int64_t milliseconds = 0;
    if (*cursor == '.') {
        cursor++;
        unsigned int digits = 0U;
        while (*cursor >= '0' && *cursor <= '9') {
            if (digits < 3U) milliseconds = milliseconds * 10 + (*cursor - '0');
            digits++; cursor++;
        }
        if (digits == 0U) return false;
        while (digits++ < 3U) milliseconds *= 10;
    }
    int offset_seconds = 0;
    if (*cursor == 'Z' && cursor[1] == '\0') cursor++;
    else if ((*cursor == '+' || *cursor == '-') && strlen(cursor) == 6U && cursor[3] == ':') {
        int oh, om;
        const int sign = *cursor == '+' ? 1 : -1;
        if (sscanf(cursor + 1, "%2d:%2d", &oh, &om) != 2 || oh > 23 || om > 59)
            return false;
        offset_seconds = sign * (oh * 3600 + om * 60);
        cursor += 6;
    } else return false;
    if (*cursor != '\0') return false;
    const int64_t seconds = days_from_civil(year, (unsigned int)month, (unsigned int)day) *
                                86400 + hour * 3600 + minute * 60 +
                                (second == 60 ? 59 : second) - offset_seconds;
    *utc_ms = seconds * 1000 + milliseconds;
    return true;
}

static bool command_supported(const pm_command_type_t type)
{
    return type == PM_COMMAND_REBOOT || type == PM_COMMAND_DIAGNOSTICS_SNAPSHOT ||
           type == PM_COMMAND_NETWORK_SELF_TEST || type == PM_COMMAND_METER_SELF_TEST ||
           type == PM_COMMAND_OTA_INSTALL;
}

static bool capability_supported(const cJSON *capability)
{
    if (cJSON_IsNull(capability)) {
        return true;
    }
    return cJSON_IsString(capability) &&
           (strcmp(capability->valuestring, PM_PROTOCOL_ID) == 0 ||
            strcmp(capability->valuestring, "headless-command-v1") == 0 ||
            strcmp(capability->valuestring, "esp-idf-ota-v1") == 0 ||
            strcmp(capability->valuestring, "ota_v1") == 0);
}

static void parse_commands(pm_network_context_t *context, const char *response)
{
    cJSON *root = cJSON_Parse(response);
    cJSON *commands = root == NULL ? NULL : cJSON_GetObjectItemCaseSensitive(root, "commands");
    const cJSON *item = NULL;
    cJSON_ArrayForEach(item, commands) {
        pm_command_t command = {0};
        uint8_t normalized_attempt = 0U;
        const cJSON *id = cJSON_GetObjectItemCaseSensitive(item, "command_id");
        const cJSON *idempotency = cJSON_GetObjectItemCaseSensitive(item, "idempotency_key");
        const cJSON *type = cJSON_GetObjectItemCaseSensitive(item, "command_type");
        const cJSON *not_before = cJSON_GetObjectItemCaseSensitive(item, "not_before");
        const cJSON *expires = cJSON_GetObjectItemCaseSensitive(item, "expires_at");
        const cJSON *attempt = cJSON_GetObjectItemCaseSensitive(item, "attempt");
        const cJSON *capability = cJSON_GetObjectItemCaseSensitive(
            item, "required_firmware_capability");
        const cJSON *payload = cJSON_GetObjectItemCaseSensitive(item, "payload");
        if (!cJSON_IsString(id) || strlen(id->valuestring) != PM_COMMAND_ID_MAX ||
            !cJSON_IsString(idempotency) || strlen(idempotency->valuestring) == 0U ||
            strlen(idempotency->valuestring) > PM_IDEMPOTENCY_KEY_MAX ||
            !cJSON_IsString(type) || !cJSON_IsString(not_before) || !cJSON_IsString(expires) ||
            !cJSON_IsNumber(attempt) ||
            !pm_command_attempt_from_json_number(attempt->valuedouble, &normalized_attempt) ||
            !capability_supported(capability) || !cJSON_IsObject(payload) ||
            !pm_command_type_from_name(type->valuestring, &command.type) ||
            !command_supported(command.type) ||
            !pm_network_parse_rfc3339_ms(not_before->valuestring, &command.not_before_utc_ms) ||
            !pm_network_parse_rfc3339_ms(expires->valuestring, &command.expires_utc_ms) ||
            command.expires_utc_ms <= command.not_before_utc_ms) continue;
        (void)snprintf(command.command_id, sizeof(command.command_id), "%s", id->valuestring);
        (void)snprintf(command.idempotency_key, sizeof(command.idempotency_key), "%s",
                       idempotency->valuestring);
        command.issued_utc_ms = (int64_t)time(NULL) * 1000;
        command.attempt = normalized_attempt;
        char *serialized = cJSON_PrintUnformatted(payload);
        if (serialized == NULL || strlen(serialized) > PM_COMMAND_PAYLOAD_MAX) {
            if (serialized != NULL) secure_zero_memory(serialized, strlen(serialized));
            cJSON_free(serialized);
            continue;
        }
        (void)snprintf(command.payload, sizeof(command.payload), "%s", serialized);
        secure_zero_memory(serialized, strlen(serialized));
        cJSON_free(serialized);
        if (command.issued_utc_ms >= command.not_before_utc_ms) {
            pm_command_t *stored = NULL;
            bool duplicate = false;
            if (pm_command_accept(context->commands, &command, command.issued_utc_ms,
                                  &stored, &duplicate) == ESP_OK && !duplicate &&
                context->command_callback != NULL) {
                context->command_callback(stored, context->command_context);
            }
        }
        secure_zero_memory(&command, sizeof(command));
    }
    cJSON_Delete(root);
}

static void notify_result_acceptance(pm_network_context_t *context, const char *body)
{
    if (context->result_ack_callback == NULL) return;
    cJSON *root = cJSON_Parse(body);
    const cJSON *results = root == NULL ? NULL : cJSON_GetObjectItemCaseSensitive(root, "command_results");
    const cJSON *item = NULL;
    cJSON_ArrayForEach(item, results) {
        const cJSON *id = cJSON_GetObjectItemCaseSensitive(item, "command_id");
        if (cJSON_IsString(id) && strlen(id->valuestring) == PM_COMMAND_ID_MAX)
            context->result_ack_callback(id->valuestring, context->result_ack_context);
    }
    cJSON_Delete(root);
}

static bool telemetry_period_is_supported(uint32_t seconds)
{
    return seconds == 2U || seconds == 5U || seconds == 10U || seconds == 15U ||
           seconds == 30U || seconds == 60U;
}

static esp_err_t validate_telemetry_response(pm_network_context_t *context,
                                             const pm_telemetry_sample_t *sample,
                                             const char *response,
                                             uint32_t *telemetry_seconds)
{
    cJSON *root = cJSON_Parse(response);
    const cJSON *protocol = root == NULL ? NULL : cJSON_GetObjectItemCaseSensitive(root, "protocol_id");
    const cJSON *telemetry = root == NULL ? NULL : cJSON_GetObjectItemCaseSensitive(root, "telemetry_protocol");
    const cJSON *status = root == NULL ? NULL : cJSON_GetObjectItemCaseSensitive(root, "status");
    const cJSON *received = root == NULL ? NULL : cJSON_GetObjectItemCaseSensitive(root, "server_received_at");
    const cJSON *identity = root == NULL ? NULL : cJSON_GetObjectItemCaseSensitive(root, "sample");
    const cJSON *sensor = identity == NULL ? NULL : cJSON_GetObjectItemCaseSensitive(identity, "sensor_id");
    const cJSON *boot = identity == NULL ? NULL : cJSON_GetObjectItemCaseSensitive(identity, "boot_id");
    const cJSON *sequence = identity == NULL ? NULL : cJSON_GetObjectItemCaseSensitive(identity, "sample_sequence");
    const cJSON *timestamp_source = root == NULL ? NULL : cJSON_GetObjectItemCaseSensitive(root, "timestamp_source");
    const cJSON *commands = root == NULL ? NULL : cJSON_GetObjectItemCaseSensitive(root, "commands");
    int64_t received_ms = 0;
    esp_err_t error = ESP_OK;
    if (!cJSON_IsString(protocol) || strcmp(protocol->valuestring, PM_PROTOCOL_ID) != 0 ||
        !cJSON_IsString(telemetry) || strcmp(telemetry->valuestring, PM_TELEMETRY_PROTOCOL_ID) != 0 ||
        !cJSON_IsString(status) ||
        (strcmp(status->valuestring, "accepted") != 0 && strcmp(status->valuestring, "duplicate") != 0) ||
        !cJSON_IsString(received) || !pm_network_parse_rfc3339_ms(received->valuestring, &received_ms) ||
        !cJSON_IsObject(identity) || !cJSON_IsString(sensor) ||
        strcmp(sensor->valuestring, context->device_id_text) != 0 ||
        !cJSON_IsString(boot) || strcmp(boot->valuestring, context->boot_id) != 0 ||
        !cJSON_IsNumber(sequence) || sequence->valuedouble != (double)sample->sample_sequence ||
        !cJSON_IsString(timestamp_source) ||
        (strcmp(timestamp_source->valuestring, "sensor") != 0 &&
         strcmp(timestamp_source->valuestring, "server") != 0) || !cJSON_IsArray(commands)) {
        error = ESP_ERR_INVALID_RESPONSE;
    }
    const cJSON *configuration = root == NULL ? NULL : cJSON_GetObjectItemCaseSensitive(root, "configuration");
    const cJSON *version = cJSON_IsObject(configuration) ?
                               cJSON_GetObjectItemCaseSensitive(configuration, "version") : NULL;
    const cJSON *period = cJSON_IsObject(configuration) ?
                              cJSON_GetObjectItemCaseSensitive(configuration,
                                                               "telemetry_interval_seconds") : NULL;
    if (error == ESP_OK &&
        (!cJSON_IsObject(configuration) || !cJSON_IsNumber(version) ||
         version->valuedouble < 1.0 || version->valuedouble > (double)UINT32_MAX ||
         version->valuedouble != (double)(uint32_t)version->valuedouble ||
         !cJSON_IsNumber(period) || period->valuedouble < PM_TELEMETRY_MIN_SECONDS ||
         period->valuedouble > PM_TELEMETRY_MAX_SECONDS ||
         period->valuedouble != (double)(uint32_t)period->valuedouble ||
         !telemetry_period_is_supported((uint32_t)period->valuedouble))) {
        error = ESP_ERR_INVALID_RESPONSE;
    } else if (error == ESP_OK) {
        *telemetry_seconds = (uint32_t)period->valuedouble;
    }
    cJSON_Delete(root);
    return error;
}

static esp_err_t send_current_telemetry(pm_network_context_t *context,
                                        pm_network_io_workspace_t *io,
                                        uint32_t *telemetry_seconds)
{
    pm_telemetry_sample_t sample = {0};
    taskENTER_CRITICAL(&s_telemetry_lock);
    const bool present = pm_telemetry_begin_send(&s_telemetry, &sample);
    taskEXIT_CRITICAL(&s_telemetry_lock);
    if (!present) return ESP_ERR_NOT_FOUND;
    esp_err_t error = pm_commands_lock();
    if (error == ESP_OK) {
        error = pm_network_serialize_telemetry(context, &sample, io->body, sizeof(io->body));
        pm_commands_unlock();
    }
    int status = 0;
    if (error == ESP_OK) {
        error = signed_request(context, &io->auth, PM_TELEMETRY_ENDPOINT, io->body,
                               io->response, sizeof(io->response), &status);
    }
    if (error == ESP_OK) {
        error = validate_telemetry_response(context, &sample, io->response,
                                            telemetry_seconds);
    }
    if (error == ESP_OK) {
        notify_result_acceptance(context, io->body);
        parse_commands(context, io->response);
    }
    taskENTER_CRITICAL(&s_telemetry_lock);
    const esp_err_t complete_error = pm_telemetry_complete_send(
        &s_telemetry, sample.sample_sequence, error == ESP_OK);
    taskEXIT_CRITICAL(&s_telemetry_lock);
    secure_zero_memory(&sample, sizeof(sample));
    return error == ESP_OK ? complete_error : error;
}

static void wifi_event(void *argument, esp_event_base_t base, int32_t id, void *data)
{
    (void)argument; (void)data;
    if (base == WIFI_EVENT && id == WIFI_EVENT_STA_DISCONNECTED) {
        xEventGroupClearBits(s_wifi_events, PM_WIFI_CONNECTED_BIT);
        xEventGroupSetBits(s_wifi_events, PM_WIFI_FAILED_BIT);
    } else if (base == IP_EVENT && id == IP_EVENT_STA_GOT_IP) {
        xEventGroupClearBits(s_wifi_events, PM_WIFI_FAILED_BIT);
        xEventGroupSetBits(s_wifi_events, PM_WIFI_CONNECTED_BIT);
    }
}

static esp_err_t configure_wifi(const pm_config_t *config)
{
    if (config == NULL) return ESP_ERR_INVALID_ARG;
    if (s_wifi_events == NULL) s_wifi_events = xEventGroupCreate();
    if (s_wifi_events == NULL) return ESP_ERR_NO_MEM;
    esp_err_t error = esp_netif_init();
    if (error != ESP_OK && error != ESP_ERR_INVALID_STATE) return error;
    error = esp_event_loop_create_default();
    if (error != ESP_OK && error != ESP_ERR_INVALID_STATE) return error;
    esp_netif_t *netif = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
    if (netif == NULL) netif = esp_netif_create_default_wifi_sta();
    wifi_init_config_t init = WIFI_INIT_CONFIG_DEFAULT();
    error = esp_wifi_init(&init);
    if (error != ESP_OK && error != ESP_ERR_WIFI_INIT_STATE) return error;
    static bool handlers_registered;
    if (!handlers_registered) {
        ESP_ERROR_CHECK_WITHOUT_ABORT(esp_event_handler_register(WIFI_EVENT, ESP_EVENT_ANY_ID,
                                                                 wifi_event, NULL));
        ESP_ERROR_CHECK_WITHOUT_ABORT(esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP,
                                                                 wifi_event, NULL));
        handlers_registered = true;
    }
    wifi_config_t wifi = {0};
    memcpy(wifi.sta.ssid, config->wifi_ssid, strlen(config->wifi_ssid));
    memcpy(wifi.sta.password, config->wifi_password, strlen(config->wifi_password));
    wifi.sta.threshold.authmode = WIFI_AUTH_WPA2_PSK;
    wifi.sta.pmf_cfg.capable = true;
    if (config->ipv4_mode == PM_IPV4_STATIC) {
        (void)esp_netif_dhcpc_stop(netif);
        esp_netif_ip_info_t ip = {.ip.addr = config->ipv4_address,
                                  .gw.addr = config->ipv4_gateway,
                                  .netmask.addr = config->ipv4_netmask};
        error = esp_netif_set_ip_info(netif, &ip);
        if (error != ESP_OK) goto cleanup;
        esp_netif_dns_info_t dns = {.ip.type = ESP_IPADDR_TYPE_V4};
        dns.ip.u_addr.ip4.addr = config->dns_primary;
        error = esp_netif_set_dns_info(netif, ESP_NETIF_DNS_MAIN, &dns);
        if (error != ESP_OK) goto cleanup;
    }
    error = esp_wifi_set_mode(WIFI_MODE_STA);
    if (error == ESP_OK) error = esp_wifi_set_config(WIFI_IF_STA, &wifi);
    if (error == ESP_OK) error = esp_wifi_start();
cleanup:
    secure_zero_memory(&wifi, sizeof(wifi));
    return error == ESP_ERR_WIFI_CONN ? ESP_OK : error;
}

static esp_err_t connect_wifi_bounded(void)
{
    xEventGroupClearBits(s_wifi_events, PM_WIFI_CONNECTED_BIT | PM_WIFI_FAILED_BIT);
    esp_err_t error = esp_wifi_connect();
    if (error != ESP_OK) return error;
    const EventBits_t bits = xEventGroupWaitBits(
        s_wifi_events, PM_WIFI_CONNECTED_BIT | PM_WIFI_FAILED_BIT,
        pdFALSE, pdFALSE, pdMS_TO_TICKS(15000));
    return (bits & PM_WIFI_CONNECTED_BIT) != 0U ? ESP_OK : ESP_ERR_TIMEOUT;
}

static pm_network_task_context_t *allocate_network_task_context(void)
{
    pm_network_task_context_t *task = (pm_network_task_context_t *)heap_caps_calloc(
        1U, sizeof(*task), MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if (task == NULL) task = (pm_network_task_context_t *)heap_caps_calloc(
        1U, sizeof(*task), MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
    return task;
}

static void network_task(void *argument)
{
    pm_network_task_context_t *task = (pm_network_task_context_t *)argument;
    pm_network_context_t *context = task->network;
    if (context->start_gate != NULL &&
        (xEventGroupWaitBits(context->start_gate, context->start_bit, pdFALSE, pdTRUE,
                             portMAX_DELAY) & context->start_bit) == 0U) {
        secure_zero_memory(task, sizeof(*task)); heap_caps_free(task); vTaskDelete(NULL); return;
    }
    pm_network_scheduler_t scheduler;
    pm_network_scheduler_init(&scheduler, esp_timer_get_time(),
                              CONFIG_PM_TELEMETRY_INTERVAL_SECONDS);
    pm_telemetry_backoff_t wifi_backoff;
    pm_telemetry_backoff_reset(&wifi_backoff, esp_timer_get_time());
    bool connected = false;
    bool sntp_initialized = false;
    for (;;) {
        const int64_t now = esp_timer_get_time();
        if (!connected) {
            if (!pm_telemetry_backoff_due(&wifi_backoff, now)) {
                vTaskDelay(pdMS_TO_TICKS(100)); continue;
            }
            const esp_err_t wifi_error = connect_wifi_bounded();
            connected = wifi_error == ESP_OK;
            if (!connected) {
                const uint32_t delay = pm_telemetry_backoff_fail(&wifi_backoff,
                                                                 esp_timer_get_time(),
                                                                 esp_random());
                pm_network_health_update(context, PM_HEALTH_WIFI_REPEATED_FAILURE,
                                         wifi_backoff.failures >= 3U);
                ESP_LOGW(TAG, "wifi reconnect failed class=%s delay_ms=%u",
                         esp_err_to_name(wifi_error), (unsigned)delay);
                continue;
            }
            pm_telemetry_backoff_reset(&wifi_backoff, esp_timer_get_time());
            pm_telemetry_backoff_reset(&scheduler.server_backoff, esp_timer_get_time());
            scheduler.next_telemetry_us = esp_timer_get_time();
            pm_network_health_update(context, PM_HEALTH_WIFI_REPEATED_FAILURE, false);
            if (!sntp_initialized) {
                esp_sntp_config_t time_config = ESP_NETIF_SNTP_DEFAULT_CONFIG("pool.ntp.org");
                if (esp_netif_sntp_init(&time_config) == ESP_OK) sntp_initialized = true;
            }
        }
        if ((xEventGroupGetBits(s_wifi_events) & PM_WIFI_CONNECTED_BIT) == 0U) {
            connected = false; continue;
        }
        if (pm_network_telemetry_due(&scheduler, esp_timer_get_time())) {
            scheduler.request_in_progress = true;
            secure_zero_memory(&task->io, sizeof(task->io));
            uint32_t telemetry_seconds = (uint32_t)(scheduler.telemetry_period_us /
                                                    INT64_C(1000000));
            const esp_err_t error = send_current_telemetry(context, &task->io,
                                                           &telemetry_seconds);
            secure_zero_memory(&task->io, sizeof(task->io));
            if (error == ESP_OK && telemetry_seconds >= PM_TELEMETRY_MIN_SECONDS &&
                telemetry_seconds <= PM_TELEMETRY_MAX_SECONDS) {
                scheduler.telemetry_period_us = (int64_t)telemetry_seconds * INT64_C(1000000);
            }
            const bool success = error == ESP_OK || error == ESP_ERR_NOT_FOUND;
            pm_network_telemetry_complete(&scheduler, esp_timer_get_time(), success,
                                          esp_random());
            pm_network_health_update(context, PM_HEALTH_SERVER_UNAVAILABLE,
                                     !success);
            if (!success) {
                ESP_LOGW(TAG, "telemetry delivery failed class=%u retry_failures=%u",
                         (unsigned)context->last_request_error,
                         (unsigned)scheduler.server_backoff.failures);
            }
        }
        vTaskDelay(pdMS_TO_TICKS(100));
    }
}

esp_err_t pm_network_start(pm_network_context_t *context)
{
    if (context == NULL || context->commands == NULL) return ESP_ERR_INVALID_ARG;
    uint8_t boot_id[16];
    esp_fill_random(boot_id, sizeof(boot_id));
    boot_id[6] = (uint8_t)((boot_id[6] & 0x0FU) | 0x40U);
    boot_id[8] = (uint8_t)((boot_id[8] & 0x3FU) | 0x80U);
    (void)snprintf(context->boot_id, sizeof(context->boot_id),
                   "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
                   boot_id[0], boot_id[1], boot_id[2], boot_id[3], boot_id[4], boot_id[5],
                   boot_id[6], boot_id[7], boot_id[8], boot_id[9], boot_id[10], boot_id[11],
                   boot_id[12], boot_id[13], boot_id[14], boot_id[15]);
    taskENTER_CRITICAL(&s_telemetry_lock);
    pm_telemetry_slot_init(&s_telemetry);
    taskEXIT_CRITICAL(&s_telemetry_lock);
    pm_network_task_context_t *task = allocate_network_task_context();
    if (task == NULL) return ESP_ERR_NO_MEM;
    esp_err_t error = pm_network_capture_auth_snapshot(context, &task->io.auth);
    if (error == ESP_OK && xSemaphoreTake(context->credential_mutex, portMAX_DELAY) != pdTRUE)
        error = ESP_ERR_TIMEOUT;
    else if (error == ESP_OK) {
        task->startup_config = context->config;
        (void)xSemaphoreGive(context->credential_mutex);
        error = configure_wifi(&task->startup_config);
    }
    secure_zero_memory(&task->startup_config, sizeof(task->startup_config));
    pm_network_clear_auth_snapshot(&task->io.auth);
    if (error != ESP_OK) {
        secure_zero_memory(task, sizeof(*task)); heap_caps_free(task); return error;
    }
    task->network = context;
    if (xTaskCreate(network_task, "pm_network", PM_NETWORK_TASK_STACK, task, 7U, NULL) != pdPASS) {
        secure_zero_memory(task, sizeof(*task)); heap_caps_free(task); return ESP_ERR_NO_MEM;
    }
    return ESP_OK;
}

static int hex_nibble(char value)
{
    if (value >= '0' && value <= '9') return value - '0';
    if (value >= 'a' && value <= 'f') return value - 'a' + 10;
    if (value >= 'A' && value <= 'F') return value - 'A' + 10;
    return -1;
}

static bool parse_uuid(const char *value, uint8_t output[16])
{
    if (value == NULL || output == NULL || strlen(value) != 36U || value[8] != '-' ||
        value[13] != '-' || value[18] != '-' || value[23] != '-') return false;
    size_t source = 0U;
    for (size_t destination = 0U; destination < 16U; ++destination) {
        if (source == 8U || source == 13U || source == 18U || source == 23U) source++;
        const int high = hex_nibble(value[source++]);
        const int low = hex_nibble(value[source++]);
        if (high < 0 || low < 0) return false;
        output[destination] = (uint8_t)((high << 4U) | low);
    }
    return true;
}

static void zeroize_json_string(cJSON *object, const char *name)
{
    cJSON *item = object == NULL ? NULL : cJSON_GetObjectItemCaseSensitive(object, name);
    if (cJSON_IsString(item) && item->valuestring != NULL)
        secure_zero_memory(item->valuestring, strlen(item->valuestring));
}

esp_err_t pm_network_provisioning_test(pm_provisioning_test_stage_t stage,
                                       pm_config_t *candidate,
                                       const char *enrollment_token, void *context)
{
    (void)context;
    if (candidate == NULL) return ESP_ERR_INVALID_ARG;
    if (stage == PM_PROVISIONING_TEST_WIFI) {
        esp_err_t error = configure_wifi(candidate);
        return error == ESP_OK ? connect_wifi_bounded() : error;
    }
    if (stage == PM_PROVISIONING_TEST_IPV4) {
        esp_netif_ip_info_t info = {0};
        esp_netif_t *netif = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
        return netif != NULL && esp_netif_get_ip_info(netif, &info) == ESP_OK &&
               info.ip.addr != 0U ? ESP_OK : ESP_ERR_INVALID_STATE;
    }
    if (stage == PM_PROVISIONING_TEST_DNS) return ESP_OK;
    char url[PM_CONFIG_ORIGIN_MAX + 32U];
    (void)snprintf(url, sizeof(url), "%s%s", candidate->server_origin, PM_ENROLL_ENDPOINT);
    const esp_http_client_config_t config = {.url = url, .cert_pem = candidate->ca_pem,
        .timeout_ms = PM_REQUEST_TIMEOUT_MS, .buffer_size = 1024, .disable_auto_redirect = true};
    esp_http_client_handle_t client = esp_http_client_init(&config);
    if (client == NULL) return ESP_ERR_NO_MEM;
    esp_err_t error = ESP_OK;
    if (stage == PM_PROVISIONING_TEST_TLS) {
        esp_http_client_set_method(client, HTTP_METHOD_HEAD);
        error = esp_http_client_perform(client);
        const int status = esp_http_client_get_status_code(client);
        if (error == ESP_OK && (status < 200 || status >= 500)) error = ESP_ERR_INVALID_RESPONSE;
    } else if (stage == PM_PROVISIONING_TEST_ENROLLMENT) {
        if (enrollment_token == NULL || enrollment_token[0] == '\0') error = ESP_ERR_INVALID_ARG;
        else {
            char body[768] = {0}; char response[768] = {0};
            cJSON *enrollment = cJSON_CreateObject();
            if (enrollment == NULL) error = ESP_ERR_NO_MEM;
            else {
                cJSON_AddStringToObject(enrollment, "enrollment_token", enrollment_token);
                cJSON_AddStringToObject(enrollment, "protocol_id", PM_PROTOCOL_ID);
                cJSON_AddStringToObject(enrollment, "firmware_version",
                                       esp_app_get_description()->version);
                uint8_t mac[6]; char fingerprint[32];
                if (esp_efuse_mac_get_default(mac) != ESP_OK) error = ESP_FAIL;
                else {
                    (void)snprintf(fingerprint, sizeof(fingerprint),
                                   "esp32s3-%02x%02x%02x%02x%02x%02x", mac[0], mac[1],
                                   mac[2], mac[3], mac[4], mac[5]);
                    cJSON_AddStringToObject(enrollment, "hardware_fingerprint", fingerprint);
                }
            }
            if (error == ESP_OK && !cJSON_PrintPreallocated(enrollment, body, sizeof(body), false))
                error = ESP_ERR_INVALID_SIZE;
            zeroize_json_string(enrollment, "enrollment_token"); cJSON_Delete(enrollment);
            if (error == ESP_OK) {
                const int length = (int)strlen(body);
                esp_http_client_set_method(client, HTTP_METHOD_POST);
                esp_http_client_set_header(client, "Content-Type", "application/json");
                error = esp_http_client_open(client, length);
                if (error == ESP_OK && esp_http_client_write(client, body, length) != length)
                    error = ESP_ERR_HTTP_WRITE_DATA;
                int read = -1;
                if (error == ESP_OK) {
                    const int64_t response_length = esp_http_client_fetch_headers(client);
                    if (response_length < 0 || response_length >= (int64_t)sizeof(response))
                        error = ESP_ERR_INVALID_SIZE;
                    else read = esp_http_client_read_response(client, response, sizeof(response) - 1U);
                }
                if (error != ESP_OK || read <= 0 || esp_http_client_get_status_code(client) != 201)
                    error = ESP_ERR_INVALID_RESPONSE;
                else {
                    response[read] = '\0'; cJSON *root = cJSON_Parse(response);
                    const cJSON *protocol = root == NULL ? NULL : cJSON_GetObjectItemCaseSensitive(root, "protocol_id");
                    const cJSON *device_id = root == NULL ? NULL : cJSON_GetObjectItemCaseSensitive(root, "device_id");
                    const cJSON *secret = root == NULL ? NULL : cJSON_GetObjectItemCaseSensitive(root, "device_secret");
                    const cJSON *fingerprint = root == NULL ? NULL : cJSON_GetObjectItemCaseSensitive(root, "credential_fingerprint");
                    size_t decoded = 0U; uint8_t parsed_id[16] = {0};
                    uint8_t parsed_secret[PM_CONFIG_SECRET_MAX] = {0};
                    uint8_t digest[PM_SHA256_SIZE] = {0}; char expected[PM_SHA256_HEX_SIZE + 1U] = {0};
                    bool valid = cJSON_IsString(protocol) && strcmp(protocol->valuestring, PM_PROTOCOL_ID) == 0 &&
                        cJSON_IsString(device_id) && parse_uuid(device_id->valuestring, parsed_id) &&
                        cJSON_IsString(secret) && cJSON_IsString(fingerprint) &&
                        mbedtls_base64_decode(parsed_secret, sizeof(parsed_secret), &decoded,
                            (const uint8_t *)secret->valuestring, strlen(secret->valuestring)) == 0 &&
                        decoded == PM_CONFIG_SECRET_MAX;
                    if (valid) {
                        pm_sha256(parsed_secret, decoded, digest);
                        pm_hex_lower(digest, sizeof(digest), expected, sizeof(expected));
                        valid = strlen(fingerprint->valuestring) == PM_SHA256_HEX_SIZE &&
                            pm_constant_time_equal((const uint8_t *)expected,
                                (const uint8_t *)fingerprint->valuestring, PM_SHA256_HEX_SIZE);
                    }
                    if (!valid) error = ESP_ERR_INVALID_RESPONSE;
                    else {
                        memcpy(candidate->device_id, parsed_id, sizeof(candidate->device_id));
                        memcpy(candidate->device_secret, parsed_secret, sizeof(candidate->device_secret));
                        candidate->device_secret_len = (uint8_t)decoded;
                    }
                    secure_zero_memory(parsed_id, sizeof(parsed_id));
                    secure_zero_memory(parsed_secret, sizeof(parsed_secret));
                    secure_zero_memory(digest, sizeof(digest)); secure_zero_memory(expected, sizeof(expected));
                    zeroize_json_string(root, "device_secret"); cJSON_Delete(root);
                }
            }
            secure_zero_memory(response, sizeof(response)); secure_zero_memory(body, sizeof(body));
        }
    }
    esp_http_client_cleanup(client);
    return error;
}
