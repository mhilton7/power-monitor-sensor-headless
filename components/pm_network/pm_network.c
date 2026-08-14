#include "pm_network.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "cJSON.h"
#include "esp_event.h"
#include "esp_app_desc.h"
#include "esp_http_client.h"
#include "esp_mac.h"
#include "esp_netif.h"
#include "esp_random.h"
#include "esp_netif_sntp.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "esp_wifi.h"
#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"
#include "freertos/task.h"
#include "lwip/inet.h"
#include "mbedtls/base64.h"
#include "pm_diagnostics.h"
#include "pm_protocol.h"

#define PM_WIFI_CONNECTED_BIT BIT0
#define PM_WIFI_FAILED_BIT BIT1
#define PM_NETWORK_TASK_STACK 10240U
#define PM_REQUEST_TIMEOUT_MS 12000

static EventGroupHandle_t s_wifi_events;
static pm_meter_sample_t s_live;
static portMUX_TYPE s_live_lock = portMUX_INITIALIZER_UNLOCKED;
static bool s_live_present;
static volatile bool s_sync_requested;

void pm_network_scheduler_init(pm_network_scheduler_t *scheduler, int64_t now_us, uint32_t heartbeat_seconds)
{
    if (scheduler != NULL) {
        *scheduler = (pm_network_scheduler_t){
            .next_heartbeat_us = now_us,
            .heartbeat_period_us = (int64_t)heartbeat_seconds * INT64_C(1000000),
            .adaptive_batch_records = PM_STORAGE_BATCH_MAX,
        };
    }
}

bool pm_network_heartbeat_due(const pm_network_scheduler_t *scheduler, int64_t now_us)
{
    return scheduler != NULL && now_us >= scheduler->next_heartbeat_us;
}

bool pm_network_backlog_allowed(const pm_network_scheduler_t *scheduler, int64_t now_us,
                                int64_t worst_case_request_us)
{
    return scheduler != NULL && !scheduler->request_in_progress &&
           now_us + worst_case_request_us < scheduler->next_heartbeat_us;
}

void pm_network_heartbeat_complete(pm_network_scheduler_t *scheduler, int64_t now_us, bool success)
{
    if (scheduler == NULL) {
        return;
    }
    scheduler->request_in_progress = false;
    if (success) {
        scheduler->last_heartbeat_us = now_us;
        scheduler->consecutive_missed = 0U;
    } else {
        scheduler->consecutive_missed++;
    }
    do {
        scheduler->next_heartbeat_us += scheduler->heartbeat_period_us;
    } while (scheduler->next_heartbeat_us <= now_us);
}

uint32_t pm_network_reconnect_delay_ms(uint32_t attempt, uint32_t random_value)
{
    const uint32_t bounded_attempt = attempt > 6U ? 6U : attempt;
    const uint32_t base = 1000U << bounded_attempt;
    const uint32_t capped = base > 60000U ? 60000U : base;
    const uint32_t jitter = random_value % (capped / 4U + 1U);
    return capped - capped / 8U + jitter;
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
    taskENTER_CRITICAL(&s_live_lock);
    s_live = *sample;
    s_live_present = true;
    taskEXIT_CRITICAL(&s_live_lock);
    return ESP_OK;
}

void pm_network_request_sync(void)
{
    s_sync_requested = true;
}

static void wifi_event(void *argument, esp_event_base_t base, int32_t id, void *data)
{
    (void)argument;
    (void)data;
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
    if (config == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    if (s_wifi_events == NULL) {
        s_wifi_events = xEventGroupCreate();
    }
    if (s_wifi_events == NULL) {
        return ESP_ERR_NO_MEM;
    }
    esp_err_t error = esp_netif_init();
    if (error != ESP_OK && error != ESP_ERR_INVALID_STATE) {
        return error;
    }
    error = esp_event_loop_create_default();
    if (error != ESP_OK && error != ESP_ERR_INVALID_STATE) {
        return error;
    }
    esp_netif_t *netif = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
    if (netif == NULL) {
        netif = esp_netif_create_default_wifi_sta();
    }
    wifi_init_config_t wifi_init = WIFI_INIT_CONFIG_DEFAULT();
    error = esp_wifi_init(&wifi_init);
    if (error != ESP_OK && error != ESP_ERR_WIFI_INIT_STATE) {
        return error;
    }
    static bool handlers_registered;
    if (!handlers_registered) {
        ESP_ERROR_CHECK_WITHOUT_ABORT(esp_event_handler_register(WIFI_EVENT, ESP_EVENT_ANY_ID, wifi_event, NULL));
        ESP_ERROR_CHECK_WITHOUT_ABORT(esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP, wifi_event, NULL));
        handlers_registered = true;
    }
    wifi_config_t wifi = {0};
    memcpy(wifi.sta.ssid, config->wifi_ssid, strlen(config->wifi_ssid));
    memcpy(wifi.sta.password, config->wifi_password, strlen(config->wifi_password));
    wifi.sta.threshold.authmode = WIFI_AUTH_WPA2_PSK;
    wifi.sta.pmf_cfg.capable = true;
    wifi.sta.pmf_cfg.required = false;
    if (config->ipv4_mode == PM_IPV4_STATIC) {
        (void)esp_netif_dhcpc_stop(netif);
        esp_netif_ip_info_t ip = {
            .ip.addr = config->ipv4_address,
            .gw.addr = config->ipv4_gateway,
            .netmask.addr = config->ipv4_netmask,
        };
        error = esp_netif_set_ip_info(netif, &ip);
        if (error != ESP_OK) {
            return error;
        }
        esp_netif_dns_info_t dns = {.ip.type = ESP_IPADDR_TYPE_V4};
        dns.ip.u_addr.ip4.addr = config->dns_primary;
        error = esp_netif_set_dns_info(netif, ESP_NETIF_DNS_MAIN, &dns);
        if (error != ESP_OK) {
            return error;
        }
    }
    error = esp_wifi_set_mode(WIFI_MODE_STA);
    if (error == ESP_OK) {
        error = esp_wifi_set_config(WIFI_IF_STA, &wifi);
    }
    if (error == ESP_OK) {
        error = esp_wifi_start();
    }
    return error == ESP_ERR_WIFI_CONN ? ESP_OK : error;
}

static esp_err_t connect_wifi_bounded(void)
{
    xEventGroupClearBits(s_wifi_events, PM_WIFI_CONNECTED_BIT | PM_WIFI_FAILED_BIT);
    esp_err_t error = esp_wifi_connect();
    if (error != ESP_OK) {
        return error;
    }
    const EventBits_t result = xEventGroupWaitBits(s_wifi_events, PM_WIFI_CONNECTED_BIT | PM_WIFI_FAILED_BIT,
                                                   pdFALSE, pdFALSE, pdMS_TO_TICKS(15000));
    return (result & PM_WIFI_CONNECTED_BIT) != 0U ? ESP_OK : ESP_ERR_TIMEOUT;
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

static bool json_add_i64(cJSON *object, const char *name, int64_t value)
{
    char number[24];
    if (snprintf(number, sizeof(number), "%lld", (long long)value) < 0) {
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
                                 (long long)(magnitude / 1000), (long long)(magnitude % 1000));
    return written > 0 && (size_t)written < sizeof(value) && cJSON_AddStringToObject(object, name, value) != NULL;
}

static bool json_add_null(cJSON *object, const char *name)
{
    return cJSON_AddNullToObject(object, name) != NULL;
}

static esp_err_t render_json(cJSON *root, char *body, size_t body_size)
{
    if (root == NULL || body == NULL || body_size < 3U || !cJSON_PrintPreallocated(root, body, (int)body_size, false)) {
        return ESP_ERR_INVALID_SIZE;
    }
    return ESP_OK;
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
    const int64_t milliseconds = utc_ms % 1000;
    const int written = snprintf(output, 32U, "%04d-%02d-%02dT%02d:%02d:%02d.%03lldZ",
                                 utc.tm_year + 1900, utc.tm_mon + 1, utc.tm_mday, utc.tm_hour, utc.tm_min,
                                 utc.tm_sec, (long long)milliseconds);
    return written == 24;
}

static const char *contract_pzem_status(pm_pzem_status_t status)
{
    switch (status) {
    case PM_PZEM_OK:
        return "ok";
    case PM_PZEM_TIMEOUT:
        return "timeout";
    case PM_PZEM_SHORT_FRAME:
        return "short_frame";
    case PM_PZEM_BAD_CRC:
        return "bad_crc";
    case PM_PZEM_WRONG_SLAVE:
        return "wrong_address";
    case PM_PZEM_NOT_VERIFIED:
        return "absent";
    case PM_PZEM_WRONG_FUNCTION:
    case PM_PZEM_INVALID_RANGE:
    case PM_PZEM_UART_ERROR:
    default:
        return "invalid";
    }
}

static const char *contract_storage_status(pm_storage_status_t status)
{
    switch (status) {
    case PM_STORAGE_READY:
        return "ok";
    case PM_STORAGE_MISSING:
        return "missing";
    case PM_STORAGE_READ_ONLY:
        return "read_only";
    case PM_STORAGE_FULL:
        return "full";
    case PM_STORAGE_CORRUPT:
        return "corrupt";
    case PM_STORAGE_UNINITIALIZED:
    case PM_STORAGE_IO_ERROR:
    default:
        return "degraded";
    }
}

static const char *reset_reason_name(esp_reset_reason_t reason)
{
    switch (reason) {
    case ESP_RST_POWERON:
        return "power_on";
    case ESP_RST_SW:
        return "software";
    case ESP_RST_PANIC:
        return "panic";
    case ESP_RST_INT_WDT:
        return "interrupt_watchdog";
    case ESP_RST_TASK_WDT:
        return "task_watchdog";
    case ESP_RST_WDT:
        return "watchdog";
    case ESP_RST_DEEPSLEEP:
        return "deep_sleep";
    case ESP_RST_BROWNOUT:
        return "brownout";
    case ESP_RST_SDIO:
        return "sdio";
    case ESP_RST_USB:
        return "usb";
    case ESP_RST_JTAG:
        return "jtag";
    case ESP_RST_EFUSE:
        return "efuse";
    case ESP_RST_PWR_GLITCH:
        return "power_glitch";
    case ESP_RST_CPU_LOCKUP:
        return "cpu_lockup";
    case ESP_RST_UNKNOWN:
    default:
        return "unknown";
    }
}

static bool command_result_state(pm_command_state_t state)
{
    return state == PM_COMMAND_ACCEPTED || state == PM_COMMAND_RUNNING || state == PM_COMMAND_SUCCEEDED ||
           state == PM_COMMAND_FAILED || state == PM_COMMAND_AWAITING_REBOOT ||
           state == PM_COMMAND_AWAITING_HEARTBEAT || state == PM_COMMAND_ROLLED_BACK;
}

static const char *command_result_code(const pm_command_t *command, char output[32])
{
    if (command->state == PM_COMMAND_ACCEPTED) {
        return "accepted";
    }
    if (command->state == PM_COMMAND_RUNNING) {
        return "in_progress";
    }
    if (command->state == PM_COMMAND_AWAITING_REBOOT) {
        return "awaiting_reboot";
    }
    if (command->state == PM_COMMAND_AWAITING_HEARTBEAT) {
        return "awaiting_heartbeat";
    }
    if (command->state == PM_COMMAND_ROLLED_BACK) {
        return "rolled_back";
    }
    if (command->state == PM_COMMAND_SUCCEEDED && command->result_code == ESP_OK) {
        return "ok";
    }
    esp_err_to_name_r((esp_err_t)command->result_code, output, 32U);
    return output;
}

static bool append_health_flag(cJSON *array, const char *flag)
{
    return cJSON_AddItemToArray(array, cJSON_CreateString(flag));
}

void pm_network_health_update(pm_network_context_t *context, pm_network_health_flag_t flag, bool active)
{
    if (context == NULL) {
        return;
    }
    if (active) {
        context->health_flags |= (uint32_t)flag;
    } else {
        context->health_flags &= ~(uint32_t)flag;
    }
}

esp_err_t pm_network_serialize_heartbeat(pm_network_context_t *context, const pm_meter_sample_t *sample,
                                        bool sample_present, char *body, size_t body_size)
{
    if (context == NULL || context->sequence == NULL || context->storage == NULL || context->commands == NULL ||
        body == NULL || context->boot_id[0] == '\0') {
        return ESP_ERR_INVALID_ARG;
    }
    cJSON *root = cJSON_CreateObject();
    cJSON *measurement = cJSON_CreateObject();
    cJSON *watermarks = cJSON_CreateObject();
    cJSON *health = cJSON_CreateArray();
    cJSON *results = cJSON_CreateArray();
    if (root == NULL || measurement == NULL || watermarks == NULL || health == NULL || results == NULL) {
        cJSON_Delete(root);
        cJSON_Delete(measurement);
        cJSON_Delete(watermarks);
        cJSON_Delete(health);
        cJSON_Delete(results);
        return ESP_ERR_NO_MEM;
    }
    const pm_pzem_status_t pzem_status = sample_present && sample != NULL ? sample->status : PM_PZEM_NOT_VERIFIED;
    const bool valid_electrical = sample_present && sample != NULL && pzem_status == PM_PZEM_OK;
    const bool time_trusted = valid_electrical && sample->time_trusted;
    char timestamp[32];
    if (time_trusted && format_rfc3339_ms(sample->sample_timestamp_utc_ms, timestamp)) {
        cJSON_AddStringToObject(measurement, "measured_at", timestamp);
    } else {
        json_add_null(measurement, "measured_at");
    }
    json_add_i64(measurement, "monotonic_us",
                 sample_present && sample != NULL && sample->sample_monotonic_us >= 0 ? sample->sample_monotonic_us :
                                                                                       esp_timer_get_time());
    if (valid_electrical) {
        json_add_decimal_milli(measurement, "voltage_v", sample->voltage_mv);
        json_add_decimal_milli(measurement, "current_a", sample->current_ma);
        json_add_decimal_milli(measurement, "active_power_w", sample->active_power_mw);
        json_add_decimal_milli(measurement, "frequency_hz", sample->frequency_mhz);
        json_add_decimal_milli(measurement, "power_factor", sample->power_factor_milli);
        json_add_u64(measurement, "pzem_energy_wh", sample->energy_wh);
    } else {
        json_add_null(measurement, "voltage_v");
        json_add_null(measurement, "current_a");
        json_add_null(measurement, "active_power_w");
        json_add_null(measurement, "frequency_hz");
        json_add_null(measurement, "power_factor");
        json_add_null(measurement, "pzem_energy_wh");
    }
    cJSON_AddStringToObject(measurement, "pzem_status", contract_pzem_status(pzem_status));
    if (pzem_status == PM_PZEM_OK) {
        json_add_null(measurement, "pzem_error_code");
    } else {
        char error_code[80];
        (void)snprintf(error_code, sizeof(error_code), "%s:%u", pm_pzem_status_name(pzem_status),
                       sample_present && sample != NULL ? sample->error_code : 0U);
        cJSON_AddStringToObject(measurement, "pzem_error_code", error_code);
    }

    cJSON_AddStringToObject(root, "protocol_id", PM_PROTOCOL_ID);
    cJSON_AddStringToObject(root, "boot_id", context->boot_id);
    cJSON_AddStringToObject(root, "firmware_version", esp_app_get_description()->version);
    cJSON_AddItemToObject(root, "measurement", measurement);
    cJSON_AddStringToObject(root, "storage_status", contract_storage_status(context->storage->status));
    cJSON_AddStringToObject(root, "time_status", time_trusted ? "trusted" : "untrusted");

    wifi_ap_record_t access_point = {0};
    if (esp_wifi_sta_get_ap_info(&access_point) == ESP_OK) {
        cJSON_AddNumberToObject(root, "wifi_rssi", access_point.rssi);
    } else {
        json_add_null(root, "wifi_rssi");
    }
    esp_netif_t *netif = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
    esp_netif_ip_info_t ip_info = {0};
    if (netif != NULL && esp_netif_get_ip_info(netif, &ip_info) == ESP_OK && ip_info.ip.addr != 0U) {
        char address[IP4ADDR_STRLEN_MAX];
        if (esp_ip4addr_ntoa(&ip_info.ip, address, sizeof(address)) != NULL) {
            cJSON_AddStringToObject(root, "ip_address", address);
        } else {
            json_add_null(root, "ip_address");
        }
    } else {
        json_add_null(root, "ip_address");
    }
    const uint64_t newest = context->storage->newest_sequence;
    const uint64_t acknowledged = context->sequence->acknowledged;
    json_add_u64(root, "backlog", newest > acknowledged ? newest - acknowledged : 0U);
    if (context->storage->oldest_sequence == 0U) {
        json_add_null(root, "oldest_sequence");
    } else {
        json_add_u64(root, "oldest_sequence", context->storage->oldest_sequence);
    }
    if (newest == 0U) {
        json_add_null(root, "newest_sequence");
    } else {
        json_add_u64(root, "newest_sequence", newest);
    }
    json_add_u64(root, "acknowledged_sequence", acknowledged);
    pm_diagnostics_snapshot_t diagnostics = {0};
    pm_diagnostics_capture(&diagnostics);
    json_add_u64(root, "free_internal_heap", diagnostics.free_internal_heap);
    json_add_u64(root, "largest_internal_block", diagnostics.largest_internal_block);
    json_add_u64(watermarks, "network_control", uxTaskGetStackHighWaterMark(NULL) * sizeof(StackType_t));
    cJSON_AddItemToObject(root, "task_stack_watermarks", watermarks);
    cJSON_AddStringToObject(root, "reboot_reason", reset_reason_name((esp_reset_reason_t)diagnostics.reboot_reason));

    if ((context->health_flags & PM_HEALTH_TLS_VALIDATION_FAILURE) != 0U) {
        append_health_flag(health, "tls_validation_failure");
    }
    if ((context->health_flags & PM_HEALTH_WIFI_REPEATED_FAILURE) != 0U) {
        append_health_flag(health, "wifi_repeated_failure");
    }
    if ((context->health_flags & PM_HEALTH_OTA_FAILED) != 0U) {
        append_health_flag(health, "ota_failed");
    }
    if ((context->health_flags & PM_HEALTH_OTA_ROLLED_BACK) != 0U) {
        append_health_flag(health, "ota_rolled_back");
    }
    if (pzem_status != PM_PZEM_OK) {
        append_health_flag(health, "pzem_unavailable");
    }
    if (context->storage->status == PM_STORAGE_MISSING) {
        append_health_flag(health, "microsd_missing");
    } else if (context->storage->status == PM_STORAGE_READ_ONLY) {
        append_health_flag(health, "microsd_read_only");
    } else if (context->storage->status == PM_STORAGE_FULL) {
        append_health_flag(health, "microsd_full");
    }
    if (context->storage->corrupt_records != 0U || context->storage->quarantined_segments != 0U ||
        context->storage->status == PM_STORAGE_CORRUPT) {
        append_health_flag(health, "microsd_corrupt_segment");
    }
    if (context->storage->bytes_total != 0U && context->storage->bytes_free < context->storage->bytes_total / 10U) {
        append_health_flag(health, "microsd_nearly_full");
    }
    if (!time_trusted) {
        append_health_flag(health, "time_untrusted");
    }
    if (newest > acknowledged) {
        append_health_flag(health, "backlog_present");
    }
    cJSON_AddItemToObject(root, "health_flags", health);

    for (size_t i = 0U; i < PM_COMMAND_LEDGER_SIZE; ++i) {
        const pm_command_t *command = &context->commands->entries[i];
        if (strlen(command->command_id) != PM_COMMAND_ID_MAX || !command_result_state(command->state)) {
            continue;
        }
        cJSON *result = cJSON_CreateObject();
        cJSON *evidence = cJSON_CreateObject();
        if (result == NULL || evidence == NULL) {
            cJSON_Delete(result);
            cJSON_Delete(evidence);
            cJSON_Delete(root);
            return ESP_ERR_NO_MEM;
        }
        char result_code[32];
        cJSON_AddStringToObject(result, "command_id", command->command_id);
        cJSON_AddStringToObject(result, "state", pm_command_state_name(command->state));
        cJSON_AddNumberToObject(result, "progress_percent", command->progress_percent);
        cJSON_AddStringToObject(result, "result_code", command_result_code(command, result_code));
        bool structured_evidence = false;
        if (command->evidence_json[0] != '\0') {
            cJSON *structured = cJSON_ParseWithLength(command->evidence_json, strlen(command->evidence_json));
            bool safe = cJSON_IsObject(structured);
            for (const cJSON *item = safe ? structured->child : NULL; item != NULL; item = item->next) {
                safe = item->string != NULL && strstr(item->string, "token") == NULL &&
                       strstr(item->string, "secret") == NULL &&
                       (cJSON_IsString(item) || cJSON_IsNumber(item) || cJSON_IsBool(item) || cJSON_IsNull(item));
                if (!safe) {
                    break;
                }
            }
            if (safe) {
                cJSON_Delete(evidence);
                evidence = structured;
                structured_evidence = true;
            } else {
                cJSON_Delete(structured);
                cJSON_AddStringToObject(evidence, "detail", "unsafe_structured_evidence_suppressed");
            }
        }
        if (!structured_evidence) {
            cJSON_AddNumberToObject(evidence, "attempt", command->attempt);
        }
        if (!structured_evidence && command->result_text[0] != '\0') {
            char redacted[PM_COMMAND_RESULT_MAX + 1U];
            pm_diagnostics_redact(command->result_text, redacted, sizeof(redacted));
            cJSON_AddStringToObject(evidence, "detail", redacted);
        }
        cJSON_AddItemToObject(result, "evidence", evidence);
        cJSON_AddItemToArray(results, result);
    }
    cJSON_AddItemToObject(root, "command_results", results);
    const esp_err_t rendered = render_json(root, body, body_size);
    cJSON_Delete(root);
    return rendered;
}

static bool add_interval_flags(cJSON *array, uint32_t flags)
{
    static const struct {
        uint32_t bit;
        const char *name;
    } mappings[] = {
        {PM_INTERVAL_FLAG_TIME_UNTRUSTED, "time_untrusted"},
        {PM_INTERVAL_FLAG_MISSING_SAMPLE, "missing_sample"},
        {PM_INTERVAL_FLAG_PZEM_RESET, "pzem_reset"},
        {PM_INTERVAL_FLAG_PZEM_ROLLOVER, "pzem_rollover"},
        {PM_INTERVAL_FLAG_IMPLAUSIBLE_JUMP, "implausible_jump"},
        {PM_INTERVAL_FLAG_CT_WARNING_80, "ct_warning_80"},
        {PM_INTERVAL_FLAG_CT_CRITICAL_90, "ct_critical_90"},
        {PM_INTERVAL_FLAG_SIMULATED, "simulated"},
    };
    for (size_t i = 0U; i < sizeof(mappings) / sizeof(mappings[0]); ++i) {
        if ((flags & mappings[i].bit) != 0U && !append_health_flag(array, mappings[i].name)) {
            return false;
        }
    }
    return true;
}

esp_err_t pm_network_serialize_reading_batch(const pm_storage_batch_t *batch, char *body, size_t body_size)
{
    if (batch == NULL || batch->count == 0U || batch->count > PM_STORAGE_BATCH_MAX || body == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    cJSON *root = cJSON_CreateObject();
    cJSON *records = cJSON_CreateArray();
    if (root == NULL || records == NULL) {
        cJSON_Delete(root);
        cJSON_Delete(records);
        return ESP_ERR_NO_MEM;
    }
    cJSON_AddStringToObject(root, "protocol_id", PM_PROTOCOL_ID);
    cJSON_AddItemToObject(root, "records", records);
    uint64_t previous_sequence = 0U;
    for (size_t i = 0U; i < batch->count; ++i) {
        const pm_journal_record_t *record = &batch->records[i];
        const pm_durable_interval_t *interval = &record->interval;
        if (record->sequence == 0U || record->sequence <= previous_sequence || interval->expected_samples == 0U ||
            interval->expected_samples > 3600U || interval->sample_count > 3600U ||
            interval->end_monotonic_us < interval->start_monotonic_us ||
            interval->selected_energy_source == PM_ENERGY_POWER_DIAGNOSTIC || interval->voltage_mv < 0 ||
            interval->current_ma < 0 || interval->active_power_mw < 0 || interval->frequency_mhz < 40000 ||
            interval->frequency_mhz > 70000 || interval->power_factor_milli < 0 ||
            interval->power_factor_milli > 1000) {
            cJSON_Delete(root);
            return ESP_ERR_INVALID_STATE;
        }
        previous_sequence = record->sequence;
        const bool time_trusted = (interval->flags & PM_INTERVAL_FLAG_TIME_UNTRUSTED) == 0U &&
                                  interval->start_utc_ms >= INT64_C(1704067200000) &&
                                  interval->end_utc_ms > interval->start_utc_ms;
        char start[32];
        char end[32];
        if (time_trusted && (!format_rfc3339_ms(interval->start_utc_ms, start) ||
                             !format_rfc3339_ms(interval->end_utc_ms, end))) {
            cJSON_Delete(root);
            return ESP_ERR_INVALID_STATE;
        }
        cJSON *item = cJSON_CreateObject();
        cJSON *flags = cJSON_CreateArray();
        if (item == NULL || flags == NULL) {
            cJSON_Delete(item);
            cJSON_Delete(flags);
            cJSON_Delete(root);
            return ESP_ERR_NO_MEM;
        }
        json_add_u64(item, "sequence", record->sequence);
        cJSON_AddNumberToObject(item, "reset_generation", record->reset_generation);
        if (time_trusted) {
            cJSON_AddStringToObject(item, "interval_start_utc", start);
            cJSON_AddStringToObject(item, "interval_end_utc", end);
        } else {
            json_add_null(item, "interval_start_utc");
            json_add_null(item, "interval_end_utc");
        }
        json_add_i64(item, "monotonic_start_us", interval->start_monotonic_us);
        json_add_i64(item, "monotonic_end_us", interval->end_monotonic_us);
        cJSON_AddNumberToObject(item, "sample_count", interval->sample_count);
        cJSON_AddNumberToObject(item, "expected_sample_count", interval->expected_samples);
        cJSON_AddNumberToObject(item, "voltage_mv", interval->voltage_mv);
        cJSON_AddNumberToObject(item, "current_ma", interval->current_ma);
        cJSON_AddNumberToObject(item, "active_power_mw", interval->active_power_mw);
        cJSON_AddNumberToObject(item, "frequency_mhz", interval->frequency_mhz);
        cJSON_AddNumberToObject(item, "power_factor_milli", interval->power_factor_milli);
        json_add_u64(item, "pzem_energy_wh", interval->pzem_energy_end_wh);
        const bool selected = interval->selected_energy_source == PM_ENERGY_PZEM_DELTA;
        if (selected) {
            json_add_u64(item, "interval_energy_mwh", interval->selected_energy_mwh);
            cJSON_AddStringToObject(item, "energy_selection", "pzem_delta");
        } else {
            json_add_null(item, "interval_energy_mwh");
            cJSON_AddStringToObject(item, "energy_selection",
                                    (interval->flags & PM_INTERVAL_FLAG_PZEM_RESET) != 0U ? "unavailable_reset" :
                                                                                          "unavailable_invalid");
        }
        cJSON_AddStringToObject(item, "pzem_status", "ok");
        cJSON_AddBoolToObject(item, "time_trusted", time_trusted);
        add_interval_flags(flags, interval->flags);
        cJSON_AddItemToObject(item, "flags", flags);
        uint8_t encoded[PM_JOURNAL_RECORD_SIZE];
        if (pm_journal_encode_record(record, encoded, sizeof(encoded)) != sizeof(encoded)) {
            cJSON_Delete(item);
            cJSON_Delete(root);
            return ESP_ERR_INVALID_CRC;
        }
        const uint32_t crc = (uint32_t)encoded[124] | ((uint32_t)encoded[125] << 8U) |
                             ((uint32_t)encoded[126] << 16U) | ((uint32_t)encoded[127] << 24U);
        json_add_u64(item, "record_crc32", crc);
        cJSON_AddItemToArray(records, item);
    }
    const esp_err_t rendered = render_json(root, body, body_size);
    cJSON_Delete(root);
    return rendered;
}

esp_err_t pm_network_serialize_permanent_loss(const pm_storage_health_t *storage, char *body, size_t body_size)
{
    if (storage == NULL || body == NULL || storage->unavailable_first == 0U ||
        storage->unavailable_last < storage->unavailable_first) {
        return ESP_ERR_INVALID_ARG;
    }
    const char *reason = storage->corrupt_records != 0U || storage->quarantined_segments != 0U ?
                             "segment_corrupt" : "storage_failure";
    char card_id[33];
    pm_hex_lower(storage->card_id, sizeof(storage->card_id), card_id, sizeof(card_id));
    char canonical[256];
    const int written = snprintf(canonical, sizeof(canonical),
                                 "%s\n%llu\n%llu\n%s\n%s\n%lu\n%lu", PM_PROTOCOL_ID,
                                 (unsigned long long)storage->unavailable_first,
                                 (unsigned long long)storage->unavailable_last, reason, card_id,
                                 (unsigned long)storage->corrupt_records,
                                 (unsigned long)storage->quarantined_segments);
    if (written < 0 || (size_t)written >= sizeof(canonical)) {
        return ESP_ERR_INVALID_SIZE;
    }
    uint8_t digest[PM_SHA256_SIZE];
    char digest_hex[PM_SHA256_HEX_SIZE + 1U];
    pm_sha256((const uint8_t *)canonical, (size_t)written, digest);
    pm_hex_lower(digest, sizeof(digest), digest_hex, sizeof(digest_hex));
    cJSON *root = cJSON_CreateObject();
    cJSON *ranges = cJSON_CreateArray();
    cJSON *range = cJSON_CreateObject();
    if (root == NULL || ranges == NULL || range == NULL) {
        cJSON_Delete(root);
        cJSON_Delete(ranges);
        cJSON_Delete(range);
        return ESP_ERR_NO_MEM;
    }
    cJSON_AddStringToObject(root, "protocol_id", PM_PROTOCOL_ID);
    json_add_u64(range, "first_sequence", storage->unavailable_first);
    json_add_u64(range, "last_sequence", storage->unavailable_last);
    cJSON_AddStringToObject(range, "reason_code", reason);
    cJSON_AddStringToObject(range, "evidence_sha256", digest_hex);
    cJSON_AddItemToArray(ranges, range);
    cJSON_AddItemToObject(root, "ranges", ranges);
    const esp_err_t rendered = render_json(root, body, body_size);
    cJSON_Delete(root);
    return rendered;
}

static esp_err_t signed_request(pm_network_context_t *context, const char *method, const char *path,
                                const char *body, char *response, size_t response_size, int *status)
{
    if (context == NULL || method == NULL || path == NULL || body == NULL || response == NULL || status == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    const size_t body_length = strlen(body);
    if (body_length > PM_NETWORK_BODY_MAX) {
        return ESP_ERR_INVALID_SIZE;
    }
    char url[PM_CONFIG_ORIGIN_MAX + 96U];
    if (snprintf(url, sizeof(url), "%s%s", context->config.server_origin, path) >= (int)sizeof(url)) {
        return ESP_ERR_INVALID_SIZE;
    }
    const int64_t utc_ms = (int64_t)time(NULL) * 1000;
    if (utc_ms < INT64_C(1704067200000)) {
        return ESP_ERR_INVALID_STATE;
    }
    uint8_t nonce[PM_NONCE_SIZE];
    esp_fill_random(nonce, sizeof(nonce));
    pm_auth_headers_t auth;
    esp_err_t error = pm_sign_request(context->device_to_server_key, context->device_id_text, method, path, NULL,
                                      utc_ms, nonce, (const uint8_t *)body, body_length, &auth);
    if (error != ESP_OK) {
        return error;
    }
    const esp_http_client_config_t config = {
        .url = url,
        .cert_pem = context->config.ca_pem,
        .timeout_ms = PM_REQUEST_TIMEOUT_MS,
        .buffer_size = 2048,
        .buffer_size_tx = 2048,
        .keep_alive_enable = true,
        .disable_auto_redirect = true,
    };
    esp_http_client_handle_t client = esp_http_client_init(&config);
    if (client == NULL) {
        return ESP_ERR_NO_MEM;
    }
    esp_http_client_set_method(client, strcmp(method, "POST") == 0 ? HTTP_METHOD_POST : HTTP_METHOD_GET);
    esp_http_client_set_header(client, "Content-Type", "application/json");
    esp_http_client_set_header(client, "X-PM-Protocol", auth.protocol);
    esp_http_client_set_header(client, "X-PM-Device-ID", auth.device_id);
    esp_http_client_set_header(client, "X-PM-Timestamp", auth.timestamp);
    esp_http_client_set_header(client, "X-PM-Nonce", auth.nonce);
    esp_http_client_set_header(client, "X-PM-Content-SHA256", auth.content_sha256);
    esp_http_client_set_header(client, "X-PM-Signature", auth.signature);
    error = esp_http_client_open(client, (int)body_length);
    if (error == ESP_OK && body_length != 0U && esp_http_client_write(client, body, (int)body_length) != (int)body_length) {
        error = ESP_ERR_HTTP_WRITE_DATA;
    }
    int64_t content_length = -1;
    pm_response_auth_headers_t response_auth = {0};
    if (error == ESP_OK) {
        content_length = esp_http_client_fetch_headers(client);
        *status = esp_http_client_get_status_code(client);
        if (content_length < 0) {
            error = ESP_ERR_HTTP_INCOMPLETE_DATA;
        } else if (content_length > (int64_t)response_size - 1) {
            error = ESP_ERR_INVALID_SIZE;
        }
    }
    static const struct {
        const char *header;
        size_t offset;
        size_t capacity;
    } response_headers[] = {
        {"X-PM-Protocol", offsetof(pm_response_auth_headers_t, protocol), sizeof(response_auth.protocol)},
        {"X-PM-Device-ID", offsetof(pm_response_auth_headers_t, device_id), sizeof(response_auth.device_id)},
        {"X-PM-Timestamp", offsetof(pm_response_auth_headers_t, timestamp), sizeof(response_auth.timestamp)},
        {"X-PM-Nonce", offsetof(pm_response_auth_headers_t, nonce), sizeof(response_auth.nonce)},
        {"X-PM-Content-SHA256", offsetof(pm_response_auth_headers_t, content_sha256),
         sizeof(response_auth.content_sha256)},
        {"X-PM-Signature", offsetof(pm_response_auth_headers_t, signature), sizeof(response_auth.signature)},
    };
    if (error == ESP_OK && *status >= 200 && *status < 300) {
        for (size_t i = 0U; i < sizeof(response_headers) / sizeof(response_headers[0]); ++i) {
            char *value = NULL;
            char *destination = (char *)&response_auth + response_headers[i].offset;
            if (esp_http_client_get_header(client, response_headers[i].header, &value) != ESP_OK || value == NULL ||
                strlen(value) >= response_headers[i].capacity) {
                error = ESP_ERR_INVALID_RESPONSE;
                break;
            }
            memcpy(destination, value, strlen(value) + 1U);
        }
    }
    size_t used = 0U;
    while (error == ESP_OK && used + 1U < response_size) {
        const int read = esp_http_client_read(client, &response[used], response_size - used - 1U);
        if (read < 0) {
            error = ESP_ERR_HTTP_INCOMPLETE_DATA;
            break;
        }
        if (read == 0) {
            break;
        }
        used += (size_t)read;
    }
    response[used] = '\0';
    if (error == ESP_OK && used + 1U == response_size && !esp_http_client_is_complete_data_received(client)) {
        error = ESP_ERR_INVALID_SIZE;
    }
    if (error == ESP_OK && (*status < 200 || *status >= 300)) {
        error = ESP_ERR_INVALID_RESPONSE;
    } else if (error == ESP_OK) {
        error = pm_verify_response(context->server_to_device_key, context->device_id_text, path, NULL, utc_ms,
                                   &response_auth, (const uint8_t *)response, used,
                                   &context->response_nonce_cache);
    }
    context->last_request_error = pm_network_classify_error(error, *status);
    pm_network_health_update(context, PM_HEALTH_TLS_VALIDATION_FAILURE,
                             context->last_request_error == PM_TLS_ERROR_HANDSHAKE ||
                                 context->last_request_error == PM_TLS_ERROR_CA ||
                                 context->last_request_error == PM_TLS_ERROR_HOSTNAME);
    esp_http_client_close(client);
    esp_http_client_cleanup(client);
    return error;
}

static int64_t days_from_civil(int year, unsigned int month, unsigned int day)
{
    year -= month <= 2U ? 1 : 0;
    const int era = (year >= 0 ? year : year - 399) / 400;
    const unsigned int year_of_era = (unsigned int)(year - era * 400);
    const unsigned int day_of_year = (153U * (month > 2U ? month - 3U : month + 9U) + 2U) / 5U + day - 1U;
    const unsigned int day_of_era = year_of_era * 365U + year_of_era / 4U - year_of_era / 100U + day_of_year;
    return (int64_t)era * 146097 + (int64_t)day_of_era - 719468;
}

static bool parse_rfc3339_ms(const char *value, int64_t *utc_ms)
{
    if (value == NULL || utc_ms == NULL || strlen(value) < 20U) {
        return false;
    }
    int year = 0;
    int month = 0;
    int day = 0;
    int hour = 0;
    int minute = 0;
    int second = 0;
    int consumed = 0;
    if (sscanf(value, "%4d-%2d-%2dT%2d:%2d:%2d%n", &year, &month, &day, &hour, &minute, &second,
               &consumed) != 6 || consumed != 19 || year < 1970 || year > 9999 || month < 1 || month > 12 ||
        hour < 0 || hour > 23 || minute < 0 || minute > 59 || second < 0 || second > 60) {
        return false;
    }
    static const uint8_t month_days[] = {31U, 28U, 31U, 30U, 31U, 30U, 31U, 31U, 30U, 31U, 30U, 31U};
    const bool leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    const unsigned int maximum_day = month == 2 ? month_days[1] + (leap ? 1U : 0U) : month_days[month - 1];
    if (day < 1 || (unsigned int)day > maximum_day) {
        return false;
    }
    const char *cursor = &value[19];
    int64_t fractional_ms = 0;
    if (*cursor == '.') {
        cursor++;
        unsigned int digits = 0U;
        while (*cursor >= '0' && *cursor <= '9') {
            if (digits < 3U) {
                fractional_ms = fractional_ms * 10 + (*cursor - '0');
            }
            digits++;
            cursor++;
        }
        if (digits == 0U) {
            return false;
        }
        while (digits < 3U) {
            fractional_ms *= 10;
            digits++;
        }
    }
    int offset_seconds = 0;
    if (*cursor == 'Z' && cursor[1] == '\0') {
        cursor++;
    } else if ((*cursor == '+' || *cursor == '-') && strlen(cursor) == 6U && cursor[3] == ':') {
        const int sign = *cursor == '+' ? 1 : -1;
        int offset_hour = 0;
        int offset_minute = 0;
        if (sscanf(cursor + 1, "%2d:%2d", &offset_hour, &offset_minute) != 2 || offset_hour > 23 ||
            offset_minute > 59) {
            return false;
        }
        offset_seconds = sign * (offset_hour * 3600 + offset_minute * 60);
        cursor += 6;
    } else {
        return false;
    }
    if (*cursor != '\0') {
        return false;
    }
    const int64_t seconds = days_from_civil(year, (unsigned int)month, (unsigned int)day) * 86400 +
                            hour * 3600 + minute * 60 + (second == 60 ? 59 : second) - offset_seconds;
    *utc_ms = seconds * 1000 + fractional_ms;
    return true;
}

static bool capability_supported(const char *capability)
{
    return capability == NULL || strcmp(capability, PM_PROTOCOL_ID) == 0 ||
           strcmp(capability, "headless-command-v1") == 0 || strcmp(capability, "esp-idf-ota-v1") == 0 ||
           strcmp(capability, "storage-journal-v1") == 0 || strcmp(capability, "ota_v1") == 0 ||
           strcmp(capability, "destructive_commands_v1") == 0;
}

static void notify_authenticated_result_acceptance(pm_network_context_t *context, const char *request_body)
{
    if (context->result_ack_callback == NULL || request_body == NULL) {
        return;
    }
    cJSON *root = cJSON_ParseWithLength(request_body, strlen(request_body));
    const cJSON *results = root == NULL ? NULL : cJSON_GetObjectItemCaseSensitive(root, "command_results");
    const cJSON *item = NULL;
    cJSON_ArrayForEach(item, results) {
        const cJSON *id = cJSON_GetObjectItemCaseSensitive(item, "command_id");
        if (cJSON_IsString(id) && strlen(id->valuestring) == PM_COMMAND_ID_MAX) {
            context->result_ack_callback(id->valuestring, context->result_ack_context);
        }
    }
    cJSON_Delete(root);
}

static void parse_commands(pm_network_context_t *context, const char *response)
{
    cJSON *root = cJSON_Parse(response);
    const cJSON *commands = root == NULL ? NULL : cJSON_GetObjectItemCaseSensitive(root, "commands");
    if (!cJSON_IsArray(commands)) {
        cJSON_Delete(root);
        return;
    }
    const cJSON *item = NULL;
    cJSON_ArrayForEach(item, commands) {
        pm_command_t command = {0};
        const cJSON *id = cJSON_GetObjectItemCaseSensitive(item, "command_id");
        const cJSON *idempotency = cJSON_GetObjectItemCaseSensitive(item, "idempotency_key");
        const cJSON *type = cJSON_GetObjectItemCaseSensitive(item, "command_type");
        const cJSON *not_before = cJSON_GetObjectItemCaseSensitive(item, "not_before");
        const cJSON *expires = cJSON_GetObjectItemCaseSensitive(item, "expires_at");
        const cJSON *attempt = cJSON_GetObjectItemCaseSensitive(item, "attempt");
        const cJSON *capability = cJSON_GetObjectItemCaseSensitive(item, "required_firmware_capability");
        const cJSON *payload = cJSON_GetObjectItemCaseSensitive(item, "payload");
        if (!cJSON_IsString(id) || strlen(id->valuestring) != PM_COMMAND_ID_MAX || !cJSON_IsString(idempotency) ||
            strlen(idempotency->valuestring) == 0U || strlen(idempotency->valuestring) > PM_IDEMPOTENCY_KEY_MAX ||
            !cJSON_IsString(type) || !cJSON_IsString(not_before) || !cJSON_IsString(expires) ||
            !cJSON_IsNumber(attempt) || attempt->valuedouble < 0.0 || attempt->valuedouble > 255.0 ||
            attempt->valuedouble != (double)(uint8_t)attempt->valuedouble ||
            !(cJSON_IsNull(capability) || cJSON_IsString(capability)) || !cJSON_IsObject(payload) ||
            !pm_command_type_from_name(type->valuestring, &command.type) ||
            !capability_supported(cJSON_IsString(capability) ? capability->valuestring : NULL) ||
            !parse_rfc3339_ms(not_before->valuestring, &command.not_before_utc_ms) ||
            !parse_rfc3339_ms(expires->valuestring, &command.expires_utc_ms) ||
            command.expires_utc_ms <= command.not_before_utc_ms) {
            continue;
        }
        (void)snprintf(command.command_id, sizeof(command.command_id), "%s", id->valuestring);
        (void)snprintf(command.idempotency_key, sizeof(command.idempotency_key), "%s", idempotency->valuestring);
        command.issued_utc_ms = (int64_t)time(NULL) * 1000;
        command.attempt = (uint8_t)attempt->valuedouble;
        char *serialized = cJSON_PrintUnformatted(payload);
        if (serialized == NULL || strlen(serialized) > PM_COMMAND_PAYLOAD_MAX) {
            cJSON_free(serialized);
            continue;
        }
        (void)snprintf(command.payload, sizeof(command.payload), "%s", serialized);
        cJSON_free(serialized);
        if (command.issued_utc_ms < command.not_before_utc_ms) {
            continue;
        }
        pm_command_t *stored = NULL;
        bool duplicate = false;
        if (pm_command_accept(context->commands, &command, command.issued_utc_ms, &stored, &duplicate) == ESP_OK &&
            !duplicate && context->command_callback != NULL) {
            context->command_callback(stored, context->command_context);
        }
    }
    cJSON_Delete(root);
}

static esp_err_t send_heartbeat(pm_network_context_t *context)
{
    pm_meter_sample_t live = {0};
    bool present = false;
    taskENTER_CRITICAL(&s_live_lock);
    live = s_live;
    present = s_live_present;
    taskEXIT_CRITICAL(&s_live_lock);
    char body[4096];
    esp_err_t error = pm_network_serialize_heartbeat(context, &live, present, body, sizeof(body));
    if (error != ESP_OK) {
        return error;
    }
    char response[PM_NETWORK_RESPONSE_MAX];
    int status = 0;
    error = signed_request(context, "POST", PM_HEARTBEAT_ENDPOINT, body, response, sizeof(response), &status);
    if (error == ESP_OK) {
        cJSON *root = cJSON_Parse(response);
        const cJSON *protocol = root == NULL ? NULL : cJSON_GetObjectItemCaseSensitive(root, "protocol_id");
        const cJSON *server_time = root == NULL ? NULL : cJSON_GetObjectItemCaseSensitive(root, "server_time");
        const cJSON *ack = root == NULL ? NULL : cJSON_GetObjectItemCaseSensitive(root, "highest_contiguous_sequence");
        const cJSON *gaps = root == NULL ? NULL : cJSON_GetObjectItemCaseSensitive(root, "gaps");
        const cJSON *commands = root == NULL ? NULL : cJSON_GetObjectItemCaseSensitive(root, "commands");
        int64_t server_utc_ms = 0;
        if (!cJSON_IsString(protocol) || strcmp(protocol->valuestring, PM_PROTOCOL_ID) != 0 ||
            !cJSON_IsString(server_time) || !parse_rfc3339_ms(server_time->valuestring, &server_utc_ms) ||
            !cJSON_IsNumber(ack) || ack->valuedouble < 0.0 || !cJSON_IsArray(gaps) || !cJSON_IsArray(commands)) {
            error = ESP_ERR_INVALID_RESPONSE;
        } else {
            const uint64_t acknowledgement = (uint64_t)ack->valuedouble;
            error = pm_sequence_acknowledge(context->sequence, acknowledgement);
            if (error == ESP_OK) {
                context->storage->acknowledged_sequence = acknowledgement;
                /* The authenticated 2xx response is the server's acceptance of
                 * every command result serialized in this exact request body. */
                notify_authenticated_result_acceptance(context, body);
                parse_commands(context, response);
            }
        }
        cJSON_Delete(root);
    }
    return error;
}

static esp_err_t send_backlog(pm_network_context_t *context)
{
    pm_storage_batch_t batch;
    esp_err_t error = pm_storage_read_batch(context->sequence->acknowledged, &batch, 3000U);
    if (error != ESP_OK || batch.count == 0U) {
        return error;
    }
    char body[PM_NETWORK_BODY_MAX + 1U];
    error = pm_network_serialize_reading_batch(&batch, body, sizeof(body));
    if (error != ESP_OK) {
        return error;
    }
    char response[PM_NETWORK_RESPONSE_MAX];
    int status = 0;
    error = signed_request(context, "POST", PM_READINGS_ENDPOINT, body, response, sizeof(response), &status);
    if (error != ESP_OK) {
        return error;
    }
    cJSON *root = cJSON_Parse(response);
    const cJSON *protocol = root == NULL ? NULL : cJSON_GetObjectItemCaseSensitive(root, "protocol_id");
    const cJSON *server_time = root == NULL ? NULL : cJSON_GetObjectItemCaseSensitive(root, "server_time");
    const cJSON *ack = root == NULL ? NULL : cJSON_GetObjectItemCaseSensitive(root, "highest_contiguous_sequence");
    const cJSON *gaps = root == NULL ? NULL : cJSON_GetObjectItemCaseSensitive(root, "gaps");
    int64_t server_utc_ms = 0;
    if (!cJSON_IsString(protocol) || strcmp(protocol->valuestring, PM_PROTOCOL_ID) != 0 ||
        !cJSON_IsString(server_time) || !parse_rfc3339_ms(server_time->valuestring, &server_utc_ms) ||
        !cJSON_IsNumber(ack) || ack->valuedouble < 0.0 || !cJSON_IsArray(gaps)) {
        cJSON_Delete(root);
        return ESP_ERR_INVALID_RESPONSE;
    }
    const uint64_t acknowledgement = (uint64_t)ack->valuedouble;
    cJSON_Delete(root);
    error = pm_sequence_acknowledge(context->sequence, acknowledgement);
    if (error == ESP_OK) {
        context->storage->acknowledged_sequence = acknowledgement;
    }
    return error;
}

static esp_err_t send_permanent_loss(pm_network_context_t *context)
{
    if (context->storage->unavailable_first == 0U ||
        context->storage->unavailable_last <= context->permanent_loss_reported_through) {
        return ESP_ERR_NOT_FOUND;
    }
    char body[1024];
    esp_err_t error = pm_network_serialize_permanent_loss(context->storage, body, sizeof(body));
    if (error != ESP_OK) {
        return error;
    }
    char response[PM_NETWORK_RESPONSE_MAX];
    int status = 0;
    error = signed_request(context, "POST", PM_PERMANENT_LOSS_ENDPOINT, body, response, sizeof(response), &status);
    if (error != ESP_OK) {
        return error;
    }
    cJSON *root = cJSON_Parse(response);
    const cJSON *protocol = root == NULL ? NULL : cJSON_GetObjectItemCaseSensitive(root, "protocol_id");
    const cJSON *server_time = root == NULL ? NULL : cJSON_GetObjectItemCaseSensitive(root, "server_time");
    const cJSON *accepted = root == NULL ? NULL : cJSON_GetObjectItemCaseSensitive(root, "accepted");
    const cJSON *ack = root == NULL ? NULL : cJSON_GetObjectItemCaseSensitive(root, "highest_contiguous_sequence");
    const cJSON *gaps = root == NULL ? NULL : cJSON_GetObjectItemCaseSensitive(root, "gaps");
    int64_t server_utc_ms = 0;
    if (!cJSON_IsString(protocol) || strcmp(protocol->valuestring, PM_PROTOCOL_ID) != 0 ||
        !cJSON_IsString(server_time) || !parse_rfc3339_ms(server_time->valuestring, &server_utc_ms) ||
        !cJSON_IsNumber(accepted) || accepted->valuedouble < 0.0 || !cJSON_IsNumber(ack) ||
        ack->valuedouble < 0.0 || !cJSON_IsArray(gaps)) {
        cJSON_Delete(root);
        return ESP_ERR_INVALID_RESPONSE;
    }
    const uint64_t acknowledgement = (uint64_t)ack->valuedouble;
    cJSON_Delete(root);
    error = pm_sequence_acknowledge(context->sequence, acknowledgement);
    if (error == ESP_OK) {
        context->storage->acknowledged_sequence = acknowledgement;
        context->permanent_loss_reported_through = context->storage->unavailable_last;
    }
    return error;
}

static void network_task(void *argument)
{
    pm_network_context_t *context = (pm_network_context_t *)argument;
    pm_network_scheduler_t scheduler;
    pm_network_scheduler_init(&scheduler, esp_timer_get_time(), CONFIG_PM_HEARTBEAT_SECONDS);
    uint32_t reconnect_attempt = 0U;
    bool connected = false;
    bool sntp_initialized = false;
    for (;;) {
        if (!connected) {
            const esp_err_t error = connect_wifi_bounded();
            connected = error == ESP_OK;
            if (!connected) {
                pm_network_health_update(context, PM_HEALTH_WIFI_REPEATED_FAILURE, reconnect_attempt >= 2U);
                const uint32_t delay = pm_network_reconnect_delay_ms(reconnect_attempt++, esp_random());
                vTaskDelay(pdMS_TO_TICKS(delay));
                continue;
            }
            reconnect_attempt = 0U;
            pm_network_health_update(context, PM_HEALTH_WIFI_REPEATED_FAILURE, false);
            if (!sntp_initialized) {
                esp_sntp_config_t time_config = ESP_NETIF_SNTP_DEFAULT_CONFIG("pool.ntp.org");
                if (esp_netif_sntp_init(&time_config) == ESP_OK) {
                    sntp_initialized = true;
                }
            }
        }
        const int64_t now = esp_timer_get_time();
        if ((xEventGroupGetBits(s_wifi_events) & PM_WIFI_CONNECTED_BIT) == 0U) {
            connected = false;
            continue;
        }
        if (pm_network_heartbeat_due(&scheduler, now)) {
            scheduler.request_in_progress = true;
            const bool success = send_heartbeat(context) == ESP_OK;
            pm_network_heartbeat_complete(&scheduler, esp_timer_get_time(), success);
        } else if (s_sync_requested || pm_network_backlog_allowed(&scheduler, now, INT64_C(5000000))) {
            scheduler.request_in_progress = true;
            if (send_permanent_loss(context) == ESP_ERR_NOT_FOUND) {
                (void)send_backlog(context);
            }
            s_sync_requested = false;
            scheduler.request_in_progress = false;
        }
        vTaskDelay(pdMS_TO_TICKS(100));
    }
}

esp_err_t pm_network_start(pm_network_context_t *context)
{
    if (context == NULL || context->sequence == NULL || context->storage == NULL || context->commands == NULL ||
        context->config.device_secret_len < 16U) {
        return ESP_ERR_INVALID_ARG;
    }
    if (strlen(context->device_id_text) != 36U) {
        return ESP_ERR_INVALID_ARG;
    }
    uint8_t boot_id[16];
    esp_fill_random(boot_id, sizeof(boot_id));
    boot_id[6] = (uint8_t)((boot_id[6] & 0x0FU) | 0x40U);
    boot_id[8] = (uint8_t)((boot_id[8] & 0x3FU) | 0x80U);
    (void)snprintf(context->boot_id, sizeof(context->boot_id),
                   "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
                   boot_id[0], boot_id[1], boot_id[2], boot_id[3], boot_id[4], boot_id[5], boot_id[6], boot_id[7],
                   boot_id[8], boot_id[9], boot_id[10], boot_id[11], boot_id[12], boot_id[13], boot_id[14], boot_id[15]);
    esp_err_t error = pm_hkdf_directional_keys(context->config.device_secret, context->config.device_secret_len,
                                               context->device_id_text,
                                               context->device_to_server_key, context->server_to_device_key);
    if (error != ESP_OK) {
        return error;
    }
    error = configure_wifi(&context->config);
    if (error != ESP_OK) {
        return error;
    }
    return xTaskCreate(network_task, "pm_network", PM_NETWORK_TASK_STACK, context, 7U, NULL) == pdPASS ? ESP_OK :
                                                                                                        ESP_ERR_NO_MEM;
}

static int hex_nibble(char value)
{
    if (value >= '0' && value <= '9') {
        return value - '0';
    }
    if (value >= 'a' && value <= 'f') {
        return value - 'a' + 10;
    }
    if (value >= 'A' && value <= 'F') {
        return value - 'A' + 10;
    }
    return -1;
}

static bool parse_uuid(const char *value, uint8_t output[16])
{
    if (value == NULL || output == NULL || strlen(value) != 36U || value[8] != '-' || value[13] != '-' ||
        value[18] != '-' || value[23] != '-') {
        return false;
    }
    size_t source = 0U;
    for (size_t destination = 0U; destination < 16U; ++destination) {
        if (source == 8U || source == 13U || source == 18U || source == 23U) {
            source++;
        }
        const int high = hex_nibble(value[source++]);
        const int low = hex_nibble(value[source++]);
        if (high < 0 || low < 0) {
            return false;
        }
        output[destination] = (uint8_t)((high << 4U) | low);
    }
    return true;
}

esp_err_t pm_network_provisioning_test(pm_provisioning_test_stage_t stage, pm_config_t *candidate,
                                       const char *enrollment_token, void *context)
{
    (void)context;
    if (candidate == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    if (stage == PM_PROVISIONING_TEST_WIFI) {
        esp_err_t error = configure_wifi(candidate);
        return error == ESP_OK ? connect_wifi_bounded() : error;
    }
    if (stage == PM_PROVISIONING_TEST_IPV4) {
        esp_netif_ip_info_t info = {0};
        esp_netif_t *netif = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
        return netif != NULL && esp_netif_get_ip_info(netif, &info) == ESP_OK && info.ip.addr != 0U ? ESP_OK :
                                                                                                     ESP_ERR_INVALID_STATE;
    }
    if (stage == PM_PROVISIONING_TEST_DNS) {
        /* A verified HTTPS request in the next stage proves DNS resolution too. */
        return ESP_OK;
    }
    char url[PM_CONFIG_ORIGIN_MAX + 32U];
    (void)snprintf(url, sizeof(url), "%s%s", candidate->server_origin, PM_ENROLL_ENDPOINT);
    const esp_http_client_config_t config = {
        .url = url,
        .cert_pem = candidate->ca_pem,
        .timeout_ms = PM_REQUEST_TIMEOUT_MS,
        .buffer_size = 1024,
        .disable_auto_redirect = true,
    };
    esp_http_client_handle_t client = esp_http_client_init(&config);
    if (client == NULL) {
        return ESP_ERR_NO_MEM;
    }
    esp_err_t error = ESP_OK;
    if (stage == PM_PROVISIONING_TEST_TLS) {
        esp_http_client_set_method(client, HTTP_METHOD_HEAD);
        error = esp_http_client_perform(client);
        const int status = esp_http_client_get_status_code(client);
        if (error == ESP_OK && (status < 200 || status >= 500)) {
            error = ESP_ERR_INVALID_RESPONSE;
        }
    } else if (stage == PM_PROVISIONING_TEST_ENROLLMENT) {
        if (enrollment_token == NULL || enrollment_token[0] == '\0') {
            error = ESP_ERR_INVALID_ARG;
        } else {
            char body[768];
            cJSON *enrollment = cJSON_CreateObject();
            if (enrollment == NULL) {
                error = ESP_ERR_NO_MEM;
            } else {
                cJSON_AddStringToObject(enrollment, "enrollment_token", enrollment_token);
                cJSON_AddStringToObject(enrollment, "protocol_id", PM_PROTOCOL_ID);
                cJSON_AddStringToObject(enrollment, "firmware_version", esp_app_get_description()->version);
                uint8_t base_mac[6];
                char hardware_fingerprint[32];
                if (esp_efuse_mac_get_default(base_mac) != ESP_OK) {
                    error = ESP_FAIL;
                } else {
                    (void)snprintf(hardware_fingerprint, sizeof(hardware_fingerprint),
                                   "esp32s3-%02x%02x%02x%02x%02x%02x", base_mac[0], base_mac[1], base_mac[2],
                                   base_mac[3], base_mac[4], base_mac[5]);
                    cJSON_AddStringToObject(enrollment, "hardware_fingerprint", hardware_fingerprint);
                }
            }
            if (error == ESP_OK && !cJSON_PrintPreallocated(enrollment, body, sizeof(body), false)) {
                error = ESP_ERR_INVALID_SIZE;
            }
            cJSON_Delete(enrollment);
            if (error == ESP_OK) {
                const int length = (int)strlen(body);
                esp_http_client_set_method(client, HTTP_METHOD_POST);
                esp_http_client_set_header(client, "Content-Type", "application/json");
                error = esp_http_client_open(client, length);
                if (error == ESP_OK && esp_http_client_write(client, body, length) != length) {
                    error = ESP_ERR_HTTP_WRITE_DATA;
                }
                char response[768];
                int read = -1;
                if (error == ESP_OK) {
                    const int64_t response_length = esp_http_client_fetch_headers(client);
                    if (response_length < 0 || response_length >= (int64_t)sizeof(response)) {
                        error = ESP_ERR_INVALID_SIZE;
                    } else {
                        read = esp_http_client_read_response(client, response, sizeof(response) - 1U);
                    }
                }
                if (error != ESP_OK || read <= 0 || esp_http_client_get_status_code(client) != 201) {
                    error = ESP_ERR_INVALID_RESPONSE;
                } else {
                    response[read] = '\0';
                    cJSON *root = cJSON_Parse(response);
                    const cJSON *protocol = root == NULL ? NULL : cJSON_GetObjectItemCaseSensitive(root, "protocol_id");
                    const cJSON *device_id = root == NULL ? NULL : cJSON_GetObjectItemCaseSensitive(root, "device_id");
                    const cJSON *secret = root == NULL ? NULL : cJSON_GetObjectItemCaseSensitive(root, "device_secret");
                    const cJSON *fingerprint_item = root == NULL ? NULL :
                        cJSON_GetObjectItemCaseSensitive(root, "credential_fingerprint");
                    size_t decoded = 0U;
                    uint8_t parsed_device_id[16];
                    if (!cJSON_IsString(protocol) || strcmp(protocol->valuestring, PM_PROTOCOL_ID) != 0 ||
                        !cJSON_IsString(device_id) || !parse_uuid(device_id->valuestring, parsed_device_id) ||
                        !cJSON_IsString(secret) || !cJSON_IsString(fingerprint_item) ||
                        mbedtls_base64_decode(candidate->device_secret, sizeof(candidate->device_secret), &decoded,
                                              (const uint8_t *)secret->valuestring, strlen(secret->valuestring)) != 0 ||
                        decoded != 32U) {
                        error = ESP_ERR_INVALID_RESPONSE;
                    } else {
                        memcpy(candidate->device_id, parsed_device_id, sizeof(candidate->device_id));
                        candidate->device_secret_len = (uint8_t)decoded;
                    }
                    cJSON_Delete(root);
                    memset(response, 0, sizeof(response));
                }
            }
            memset(body, 0, sizeof(body));
        }
    }
    esp_http_client_cleanup(client);
    return error;
}
