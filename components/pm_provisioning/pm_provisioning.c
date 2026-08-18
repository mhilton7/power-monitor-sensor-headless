#include "pm_provisioning.h"

#include <stdio.h>
#include <string.h>

#include "cJSON.h"
#include "driver/usb_serial_jtag.h"
#include "esp_app_desc.h"
#include "esp_heap_caps.h"
#include "esp_random.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "pm_protocol.h"

typedef struct {
    pm_provisioning_session_t *session;
    char line[PM_COM_LINE_MAX];
    char response[PM_COM_LINE_MAX];
} pm_usb_task_context_t;

static void secure_zero(void *value, size_t length)
{
    volatile uint8_t *bytes = (volatile uint8_t *)value;
    while (length-- > 0U) {
        *bytes++ = 0U;
    }
}

static void *allocate_task_context(size_t size)
{
    void *context = heap_caps_calloc(1U, size, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if (context == NULL) {
        context = heap_caps_calloc(1U, size, MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
    }
    return context;
}

static bool copy_json_string(const cJSON *object, const char *name, char *destination, size_t capacity,
                             bool required)
{
    const cJSON *value = cJSON_GetObjectItemCaseSensitive(object, name);
    if (value == NULL) {
        return !required;
    }
    if (!cJSON_IsString(value) || value->valuestring == NULL || strlen(value->valuestring) >= capacity) {
        return false;
    }
    (void)snprintf(destination, capacity, "%s", value->valuestring);
    return true;
}

static bool get_u32(const cJSON *object, const char *name, uint32_t *destination, bool required)
{
    const cJSON *value = cJSON_GetObjectItemCaseSensitive(object, name);
    if (value == NULL) {
        return !required;
    }
    if (!cJSON_IsNumber(value) || value->valuedouble < 0.0 || value->valuedouble > 4294967295.0) {
        return false;
    }
    *destination = (uint32_t)value->valuedouble;
    return true;
}

static void wipe_json_string(cJSON *object, const char *name)
{
    cJSON *value = cJSON_GetObjectItemCaseSensitive(object, name);
    if (cJSON_IsString(value) && value->valuestring != NULL) {
        secure_zero(value->valuestring, strlen(value->valuestring));
    }
}

static void secure_delete_request(cJSON *request)
{
    if (request != NULL) {
        cJSON *config = cJSON_GetObjectItemCaseSensitive(request, "config");
        if (cJSON_IsObject(config)) {
            wipe_json_string(config, "wifi_password");
            wipe_json_string(config, "enrollment_token");
            wipe_json_string(config, "ca_pem");
        }
        wipe_json_string(request, "confirmation_token");
    }
    cJSON_Delete(request);
}

static esp_err_t render_response(cJSON *root, char *response, size_t response_size)
{
    if (root == NULL || response == NULL || response_size == 0U) {
        cJSON_Delete(root);
        return ESP_ERR_INVALID_ARG;
    }
    const bool printed = cJSON_PrintPreallocated(root, response, (int)response_size, false);
    wipe_json_string(root, "confirmation_token");
    cJSON_Delete(root);
    if (!printed) {
        return ESP_ERR_INVALID_SIZE;
    }
    const size_t length = strlen(response);
    if (length + 2U > response_size) {
        return ESP_ERR_INVALID_SIZE;
    }
    response[length] = '\n';
    response[length + 1U] = '\0';
    return ESP_OK;
}

static cJSON *base_response(const cJSON *request, bool ok)
{
    cJSON *response = cJSON_CreateObject();
    if (response == NULL) {
        return NULL;
    }
    cJSON_AddStringToObject(response, "protocol", PM_COM_PROTOCOL);
    const cJSON *id = cJSON_GetObjectItemCaseSensitive(request, "id");
    cJSON_AddStringToObject(response, "id", cJSON_IsString(id) ? id->valuestring : "invalid");
    cJSON_AddBoolToObject(response, "ok", ok);
    return response;
}

void pm_provisioning_session_init(pm_provisioning_session_t *session, const pm_config_t *active,
                                  bool physically_authorized, pm_provisioning_test_fn test,
                                  pm_factory_reset_fn factory_reset, pm_safe_reboot_prepare_fn safe_reboot_prepare,
                                  void *callback_context)
{
    if (session == NULL) {
        return;
    }
    memset(session, 0, sizeof(*session));
    if (active != NULL) {
        session->active = *active;
    }
    session->physically_authorized = physically_authorized;
    session->test = test;
    session->factory_reset = factory_reset;
    session->safe_reboot_prepare = safe_reboot_prepare;
    session->callback_context = callback_context;
}

static void clear_candidate_state(pm_provisioning_session_t *session)
{
    if (session == NULL) {
        return;
    }
    pm_config_abort(&session->transaction);
    secure_zero(&session->candidate, sizeof(session->candidate));
    secure_zero(session->enrollment_token, sizeof(session->enrollment_token));
    session->candidate_present = false;
    session->tests_passed = false;
}

static bool parse_candidate(pm_provisioning_session_t *session, const cJSON *config)
{
    if (session == NULL) {
        return false;
    }
    clear_candidate_state(session);
    if (!cJSON_IsObject(config)) {
        return false;
    }
    if (session->active.generation == UINT32_MAX) {
        return false;
    }
    session->candidate = session->active;
    pm_config_t *candidate = &session->candidate;
    candidate->schema_version = PM_CONFIG_SCHEMA_VERSION;
    candidate->generation++;
    uint32_t ipv4_mode = 0U;
    uint32_t ct_rating = 0U;
    if (!copy_json_string(config, "friendly_name", candidate->friendly_name, sizeof(candidate->friendly_name), true) ||
        !copy_json_string(config, "wifi_ssid", candidate->wifi_ssid, sizeof(candidate->wifi_ssid), true) ||
        !copy_json_string(config, "wifi_password", candidate->wifi_password, sizeof(candidate->wifi_password), true) ||
        !copy_json_string(config, "server_origin", candidate->server_origin, sizeof(candidate->server_origin), true) ||
        !copy_json_string(config, "ca_pem", candidate->ca_pem, sizeof(candidate->ca_pem), true) ||
        !copy_json_string(config, "timezone", candidate->timezone, sizeof(candidate->timezone), true) ||
        !copy_json_string(config, "enrollment_token", session->enrollment_token, sizeof(session->enrollment_token), true) ||
        !get_u32(config, "ipv4_mode", &ipv4_mode, true) || !get_u32(config, "ct_rating_a", &ct_rating, true) ||
        ipv4_mode > PM_IPV4_STATIC || ct_rating == 0U || ct_rating > 100U) {
        goto invalid;
    }
    candidate->ipv4_mode = (pm_ipv4_mode_t)ipv4_mode;
    candidate->ct_rating_a = (uint16_t)ct_rating;
    const cJSON *variant = cJSON_GetObjectItemCaseSensitive(config, "pzem_variant");
    if (!cJSON_IsString(variant) || strcmp(variant->valuestring, "pzem-004t-v4-classic") != 0) {
        goto invalid;
    }
    candidate->meter_variant = PM_METER_PZEM004T_V4_CLASSIC;
    if (candidate->ipv4_mode == PM_IPV4_STATIC &&
        (!get_u32(config, "ipv4_address", &candidate->ipv4_address, true) ||
         !get_u32(config, "ipv4_gateway", &candidate->ipv4_gateway, true) ||
         !get_u32(config, "ipv4_netmask", &candidate->ipv4_netmask, true) ||
         !get_u32(config, "dns_primary", &candidate->dns_primary, true) ||
         !get_u32(config, "dns_secondary", &candidate->dns_secondary, false))) {
        goto invalid;
    }
    candidate->crc32 = pm_crc32_ieee(candidate, offsetof(pm_config_t, crc32));
    if (pm_config_validate(candidate, true) != ESP_OK) {
        goto invalid;
    }
    session->candidate_present = true;
    return true;

invalid:
    clear_candidate_state(session);
    return false;
}

static void fingerprint(const uint8_t *value, size_t length, char output[17])
{
    uint8_t digest[32];
    pm_sha256(value, length, digest);
    pm_hex_lower(digest, 8U, output, 17U);
}

esp_err_t pm_provisioning_handle_line(pm_provisioning_session_t *session, const char *line, char *response,
                                      size_t response_size)
{
    if (session == NULL || line == NULL || response == NULL || strlen(line) >= PM_COM_LINE_MAX) {
        return ESP_ERR_INVALID_ARG;
    }
    cJSON *request = cJSON_ParseWithLength(line, strlen(line));
    if (request == NULL) {
        (void)snprintf(response, response_size,
                       "{\"protocol\":\"%s\",\"id\":\"invalid\",\"ok\":false,\"error\":\"invalid_json\"}\n",
                       PM_COM_PROTOCOL);
        return ESP_ERR_INVALID_ARG;
    }
    const cJSON *protocol = cJSON_GetObjectItemCaseSensitive(request, "protocol");
    const cJSON *operation = cJSON_GetObjectItemCaseSensitive(request, "op");
    if (!cJSON_IsString(protocol) || strcmp(protocol->valuestring, PM_COM_PROTOCOL) != 0 || !cJSON_IsString(operation)) {
        cJSON *out = base_response(request, false);
        cJSON_AddStringToObject(out, "error", "unsupported_protocol_or_operation");
        secure_delete_request(request);
        return render_response(out, response, response_size);
    }

    cJSON *out = base_response(request, true);
    esp_err_t result = ESP_OK;
    bool request_reboot = false;
    if (strcmp(operation->valuestring, "hello") == 0 || strcmp(operation->valuestring, "status") == 0) {
        char id_fingerprint[17];
        fingerprint(session->active.device_id, sizeof(session->active.device_id), id_fingerprint);
        cJSON_AddStringToObject(out, "device_fingerprint", id_fingerprint);
        cJSON_AddStringToObject(out, "firmware", esp_app_get_description()->version);
        cJSON_AddBoolToObject(out, "provisioned", session->active.generation != 0U);
        cJSON_AddBoolToObject(out, "physical_recovery", session->physically_authorized);
        cJSON_AddNumberToObject(out, "sequence_floor", (double)session->active.sequence_floor);
    } else if (strcmp(operation->valuestring, "begin_config") == 0) {
        const cJSON *config = cJSON_GetObjectItemCaseSensitive(request, "config");
        if (!parse_candidate(session, config) || pm_config_begin(&session->candidate, &session->transaction) != ESP_OK) {
            clear_candidate_state(session);
            cJSON_ReplaceItemInObject(out, "ok", cJSON_CreateFalse());
            cJSON_AddStringToObject(out, "error", "candidate_invalid_or_write_failed");
            result = ESP_ERR_INVALID_ARG;
        } else {
            cJSON_AddStringToObject(out, "stage", "readback_verified");
        }
    } else if (strcmp(operation->valuestring, "test_config") == 0) {
        session->tests_passed = false;
        if (!session->candidate_present || session->test == NULL) {
            result = ESP_ERR_INVALID_STATE;
        } else {
            for (pm_provisioning_test_stage_t stage = PM_PROVISIONING_TEST_WIFI;
                 stage <= PM_PROVISIONING_TEST_ENROLLMENT && result == ESP_OK;
                 stage = (pm_provisioning_test_stage_t)(stage + 1)) {
                result = session->test(stage, &session->candidate, session->enrollment_token,
                                       session->callback_context);
            }
        }
        if (result == ESP_OK) {
            session->candidate.crc32 = pm_crc32_ieee(&session->candidate, offsetof(pm_config_t, crc32));
            /* Enrollment may have populated identity/secret. Rewrite and verify the
             * complete inactive slot before it can become active. */
            result = pm_config_begin(&session->candidate, &session->transaction);
            if (result == ESP_OK) {
                result = pm_config_mark_network_tested(&session->transaction);
            }
            session->tests_passed = result == ESP_OK;
        }
        if (result != ESP_OK) {
            clear_candidate_state(session);
            cJSON_ReplaceItemInObject(out, "ok", cJSON_CreateFalse());
            cJSON_AddStringToObject(out, "error", "configuration_test_failed");
            cJSON_AddNumberToObject(out, "code", result);
        } else {
            cJSON_AddStringToObject(out, "stage", "network_tls_enrollment_verified");
        }
    } else if (strcmp(operation->valuestring, "commit_config") == 0) {
        result = session->tests_passed ? pm_config_commit(&session->transaction) : ESP_ERR_INVALID_STATE;
        if (result == ESP_OK) {
            session->active = session->candidate;
            clear_candidate_state(session);
            cJSON_AddStringToObject(out, "stage", "committed");
        } else {
            clear_candidate_state(session);
            cJSON_ReplaceItemInObject(out, "ok", cJSON_CreateFalse());
            cJSON_AddStringToObject(out, "error", "commit_requires_successful_tests");
        }
    } else if (strcmp(operation->valuestring, "rollback_config") == 0) {
        clear_candidate_state(session);
        cJSON_AddStringToObject(out, "stage", "prior_config_retained");
    } else if (strcmp(operation->valuestring, "factory_reset_prepare") == 0) {
        if (!session->physically_authorized) {
            result = ESP_ERR_INVALID_STATE;
        } else {
            esp_fill_random(session->factory_token, sizeof(session->factory_token));
            session->factory_token_expires_us = esp_timer_get_time() + INT64_C(60000000);
            char token[33];
            pm_hex_lower(session->factory_token, sizeof(session->factory_token), token, sizeof(token));
            cJSON_AddStringToObject(out, "confirmation_token", token);
            cJSON_AddStringToObject(out, "warning", "factory reset revokes configuration; sequence identity is preserved unless separately authorized");
            secure_zero(token, sizeof(token));
        }
        if (result != ESP_OK) {
            cJSON_ReplaceItemInObject(out, "ok", cJSON_CreateFalse());
            cJSON_AddStringToObject(out, "error", "physical_authorization_required");
        }
    } else if (strcmp(operation->valuestring, "factory_reset_commit") == 0) {
        const cJSON *token = cJSON_GetObjectItemCaseSensitive(request, "confirmation_token");
        char expected[33];
        pm_hex_lower(session->factory_token, sizeof(session->factory_token), expected, sizeof(expected));
        if (!session->physically_authorized || !cJSON_IsString(token) || strlen(token->valuestring) != 32U ||
            esp_timer_get_time() > session->factory_token_expires_us ||
            !pm_constant_time_equal((const uint8_t *)expected, (const uint8_t *)token->valuestring, 32U) ||
            session->factory_reset == NULL) {
            result = ESP_ERR_INVALID_STATE;
        } else {
            result = session->factory_reset(session->callback_context);
        }
        if (result != ESP_OK) {
            cJSON_ReplaceItemInObject(out, "ok", cJSON_CreateFalse());
            cJSON_AddStringToObject(out, "error", "factory_reset_rejected");
        }
        secure_zero(expected, sizeof(expected));
        secure_zero(session->factory_token, sizeof(session->factory_token));
        session->factory_token_expires_us = 0;
    } else if (strcmp(operation->valuestring, "safe_reboot") == 0) {
        clear_candidate_state(session);
        if (session->safe_reboot_prepare == NULL) {
            result = ESP_ERR_INVALID_STATE;
            cJSON_ReplaceItemInObject(out, "ok", cJSON_CreateFalse());
            cJSON_AddStringToObject(out, "error", "safe_reboot_unavailable");
        } else {
            result = session->safe_reboot_prepare(session->callback_context);
            if (result == ESP_OK) {
                request_reboot = true;
                cJSON_AddStringToObject(out, "stage", "ready_for_safe_reboot");
            } else {
                cJSON_ReplaceItemInObject(out, "ok", cJSON_CreateFalse());
                cJSON_AddStringToObject(out, "error", "safe_reboot_preparation_failed");
                cJSON_AddNumberToObject(out, "code", result);
            }
        }
    } else {
        cJSON_ReplaceItemInObject(out, "ok", cJSON_CreateFalse());
        cJSON_AddStringToObject(out, "error", "unknown_operation");
        result = ESP_ERR_NOT_SUPPORTED;
    }
    secure_delete_request(request);
    const esp_err_t render = render_response(out, response, response_size);
    if (render == ESP_OK && request_reboot) {
        session->reboot_requested = true;
    }
    return render == ESP_OK ? result : render;
}

pm_com_frame_result_t pm_provisioning_framer_push(pm_com_framer_t *framer, uint8_t byte,
                                                   char *line, size_t line_capacity)
{
    if (framer == NULL || line == NULL || line_capacity < 2U) {
        return PM_COM_FRAME_NONE;
    }
    if (byte == '\n') {
        if (framer->discarding_oversized_line) {
            secure_zero(line, line_capacity);
            framer->used = 0U;
            framer->discarding_oversized_line = false;
            return PM_COM_FRAME_NONE;
        }
        line[framer->used] = '\0';
        framer->used = 0U;
        return PM_COM_FRAME_READY;
    }
    if (byte == '\r' || framer->discarding_oversized_line) {
        return PM_COM_FRAME_NONE;
    }
    if (framer->used + 1U < line_capacity) {
        line[framer->used++] = (char)byte;
        return PM_COM_FRAME_NONE;
    }
    secure_zero(line, line_capacity);
    framer->used = 0U;
    framer->discarding_oversized_line = true;
    return PM_COM_FRAME_OVERSIZED;
}

esp_err_t pm_provisioning_prepare_reboot_barrier(void)
{
    /* Stateless telemetry has no persistent writer or queue to drain. */
    return ESP_OK;
}

bool pm_provisioning_reboot_tx_complete(bool reboot_requested, size_t response_length,
                                        int written, esp_err_t drain_result)
{
    return reboot_requested && response_length > 0U && written == (int)response_length &&
           drain_result == ESP_OK;
}

static void usb_task(void *context)
{
    pm_usb_task_context_t *task = (pm_usb_task_context_t *)context;
    pm_com_framer_t framer = {0};
    for (;;) {
        uint8_t byte = 0U;
        const int read = usb_serial_jtag_read_bytes(&byte, 1U, pdMS_TO_TICKS(250));
        if (read <= 0) {
            continue;
        }
        const pm_com_frame_result_t frame =
            pm_provisioning_framer_push(&framer, byte, task->line, sizeof(task->line));
        if (frame == PM_COM_FRAME_READY) {
            task->response[0] = '\0';
            (void)pm_provisioning_handle_line(task->session, task->line, task->response, sizeof(task->response));
            const size_t response_length = strlen(task->response);
            const bool reboot_after_response = task->session->reboot_requested;
            task->session->reboot_requested = false;
            const int written = usb_serial_jtag_write_bytes(task->response, response_length, pdMS_TO_TICKS(1000));
            const esp_err_t drain_result = usb_serial_jtag_wait_tx_done(pdMS_TO_TICKS(1000));
            const bool reboot_now = pm_provisioning_reboot_tx_complete(
                reboot_after_response, response_length, written, drain_result);
            secure_zero(task->line, sizeof(task->line));
            secure_zero(task->response, sizeof(task->response));
            if (reboot_now) {
                vTaskDelay(pdMS_TO_TICKS(50));
                esp_restart();
            }
        } else if (frame == PM_COM_FRAME_OVERSIZED) {
            static const char error[] = "{\"protocol\":\"pm-com/1.0.0\",\"id\":\"invalid\",\"ok\":false,\"error\":\"line_too_large\"}\n";
            (void)usb_serial_jtag_write_bytes(error, sizeof(error) - 1U, pdMS_TO_TICKS(1000));
        }
    }
}

esp_err_t pm_provisioning_start_usb(pm_provisioning_session_t *session)
{
    if (session == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    pm_usb_task_context_t *task = (pm_usb_task_context_t *)allocate_task_context(sizeof(*task));
    if (task == NULL) {
        return ESP_ERR_NO_MEM;
    }
    task->session = session;
    const usb_serial_jtag_driver_config_t config = {
        .tx_buffer_size = 1024U,
        .rx_buffer_size = PM_COM_LINE_MAX,
    };
    esp_err_t error = usb_serial_jtag_driver_install((usb_serial_jtag_driver_config_t *)&config);
    if (error != ESP_OK && error != ESP_ERR_INVALID_STATE) {
        secure_zero(task, sizeof(*task));
        heap_caps_free(task);
        return error;
    }
    const bool driver_installed_here = error == ESP_OK;
    if (xTaskCreate(usb_task, "pm_usb_recovery", 16384U, task, 6U, NULL) != pdPASS) {
        if (driver_installed_here) {
            (void)usb_serial_jtag_driver_uninstall();
        }
        secure_zero(task, sizeof(*task));
        heap_caps_free(task);
        return ESP_ERR_NO_MEM;
    }
    return ESP_OK;
}
