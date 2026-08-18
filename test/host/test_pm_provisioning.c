#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "driver/usb_serial_jtag.h"
#include "esp_app_desc.h"
#include "freertos/task.h"
#include "pm_provisioning.h"
#include "pm_protocol.h"

#define CHECK(condition)                                                                                              \
    do {                                                                                                              \
        if (!(condition)) {                                                                                           \
            fprintf(stderr, "check failed at %s:%d: %s\n", __FILE__, __LINE__, #condition);                         \
            return 1;                                                                                                 \
        }                                                                                                             \
    } while (0)

static esp_err_t s_begin_error;
static esp_err_t s_commit_error;
static unsigned int s_begin_calls;
static unsigned int s_abort_calls;
static unsigned int s_install_calls;
static unsigned int s_uninstall_calls;
static BaseType_t s_task_create_result = pdPASS;
static pm_provisioning_test_stage_t s_failed_stage = (pm_provisioning_test_stage_t)-1;
static esp_err_t s_safe_reboot_result;
int s_test_heap_fail;

static const esp_app_desc_t s_app_desc = {.version = "test-version"};

const esp_app_desc_t *esp_app_get_description(void)
{
    return &s_app_desc;
}

int64_t esp_timer_get_time(void)
{
    return 1000;
}

void esp_fill_random(void *buffer, size_t length)
{
    memset(buffer, 0x5A, length);
}

void esp_restart(void)
{
    abort();
}

BaseType_t xTaskCreate(TaskFunction_t task, const char *name, uint32_t stack_depth,
                       void *context, UBaseType_t priority, TaskHandle_t *handle)
{
    (void)task;
    (void)name;
    (void)stack_depth;
    (void)context;
    (void)priority;
    (void)handle;
    return s_task_create_result;
}

void vTaskDelay(TickType_t ticks)
{
    (void)ticks;
}

esp_err_t usb_serial_jtag_driver_install(usb_serial_jtag_driver_config_t *config)
{
    (void)config;
    s_install_calls++;
    return ESP_OK;
}

esp_err_t usb_serial_jtag_driver_uninstall(void)
{
    s_uninstall_calls++;
    return ESP_OK;
}

int usb_serial_jtag_read_bytes(void *buffer, uint32_t length, TickType_t timeout)
{
    (void)buffer;
    (void)length;
    (void)timeout;
    return 0;
}

int usb_serial_jtag_write_bytes(const void *buffer, size_t length, TickType_t timeout)
{
    (void)buffer;
    (void)timeout;
    return (int)length;
}

esp_err_t usb_serial_jtag_wait_tx_done(TickType_t timeout)
{
    (void)timeout;
    return ESP_OK;
}

uint32_t pm_crc32_ieee(const void *data, size_t length)
{
    const uint8_t *bytes = (const uint8_t *)data;
    uint32_t value = 0U;
    for (size_t index = 0U; index < length; ++index) {
        value = value * 33U + bytes[index];
    }
    return value;
}

esp_err_t pm_config_validate(const pm_config_t *config, bool production_gate)
{
    (void)production_gate;
    return config == NULL ? ESP_ERR_INVALID_ARG : ESP_OK;
}

esp_err_t pm_config_begin(const pm_config_t *candidate, pm_config_transaction_t *transaction)
{
    s_begin_calls++;
    if (candidate == NULL || transaction == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    if (s_begin_error != ESP_OK) {
        return s_begin_error;
    }
    transaction->stage = PM_CONFIG_STAGE_READBACK_VERIFIED;
    transaction->candidate_generation = candidate->generation;
    transaction->transaction_id = 7U;
    transaction->candidate_slot = 'B';
    return ESP_OK;
}

esp_err_t pm_config_mark_network_tested(pm_config_transaction_t *transaction)
{
    if (transaction == NULL || transaction->stage != PM_CONFIG_STAGE_READBACK_VERIFIED) {
        return ESP_ERR_INVALID_STATE;
    }
    transaction->stage = PM_CONFIG_STAGE_NETWORK_TESTED;
    return ESP_OK;
}

esp_err_t pm_config_commit(pm_config_transaction_t *transaction)
{
    if (transaction == NULL || transaction->stage != PM_CONFIG_STAGE_NETWORK_TESTED) {
        return ESP_ERR_INVALID_STATE;
    }
    if (s_commit_error != ESP_OK) {
        return s_commit_error;
    }
    memset(transaction, 0, sizeof(*transaction));
    transaction->stage = PM_CONFIG_STAGE_COMMITTED;
    return ESP_OK;
}

void pm_config_abort(pm_config_transaction_t *transaction)
{
    s_abort_calls++;
    if (transaction != NULL) {
        memset(transaction, 0, sizeof(*transaction));
    }
}

void pm_sha256(const uint8_t *data, size_t length, uint8_t digest[PM_SHA256_SIZE])
{
    uint8_t value = 0U;
    for (size_t index = 0U; index < length; ++index) {
        value ^= data[index];
    }
    memset(digest, value, PM_SHA256_SIZE);
}

void pm_hex_lower(const uint8_t *data, size_t data_length, char *output, size_t output_size)
{
    static const char hex[] = "0123456789abcdef";
    if (output_size < data_length * 2U + 1U) {
        return;
    }
    for (size_t index = 0U; index < data_length; ++index) {
        output[index * 2U] = hex[data[index] >> 4U];
        output[index * 2U + 1U] = hex[data[index] & 0x0FU];
    }
    output[data_length * 2U] = '\0';
}

bool pm_constant_time_equal(const uint8_t *left, const uint8_t *right, size_t length)
{
    uint8_t difference = 0U;
    for (size_t index = 0U; index < length; ++index) {
        difference |= left[index] ^ right[index];
    }
    return difference == 0U;
}

static esp_err_t provisioning_test(pm_provisioning_test_stage_t stage, pm_config_t *candidate,
                                   const char *enrollment_token, void *context)
{
    (void)enrollment_token;
    (void)context;
    if (stage == PM_PROVISIONING_TEST_ENROLLMENT) {
        memset(candidate->device_secret, 0xA5, sizeof(candidate->device_secret));
        candidate->device_secret_len = sizeof(candidate->device_secret);
    }
    return stage == s_failed_stage ? ESP_FAIL : ESP_OK;
}

static esp_err_t safe_reboot_prepare(void *context)
{
    (void)context;
    return s_safe_reboot_result;
}

static pm_config_t active_config(uint32_t generation)
{
    pm_config_t config = {0};
    config.schema_version = PM_CONFIG_SCHEMA_VERSION;
    config.generation = generation;
    return config;
}

static const char *begin_line(void)
{
    return "{\"protocol\":\"pm-com/1.0.0\",\"id\":\"1\",\"op\":\"begin_config\",\"config\":{" \
           "\"friendly_name\":\"meter\",\"wifi_ssid\":\"ssid\",\"wifi_password\":\"secret\"," \
           "\"server_origin\":\"https://power-monitor.test\",\"ca_pem\":\"ca\"," \
           "\"timezone\":\"America/Los_Angeles\",\"enrollment_token\":\"token\"," \
           "\"ipv4_mode\":0,\"ct_rating_a\":100,\"pzem_variant\":\"pzem-004t-v4-classic\"}}";
}

static bool all_zero(const void *value, size_t length)
{
    const uint8_t *bytes = (const uint8_t *)value;
    for (size_t index = 0U; index < length; ++index) {
        if (bytes[index] != 0U) {
            return false;
        }
    }
    return true;
}

static void reset_fakes(void)
{
    s_begin_error = ESP_OK;
    s_commit_error = ESP_OK;
    s_begin_calls = 0U;
    s_abort_calls = 0U;
    s_install_calls = 0U;
    s_uninstall_calls = 0U;
    s_task_create_result = pdPASS;
    s_failed_stage = (pm_provisioning_test_stage_t)-1;
    s_safe_reboot_result = ESP_OK;
    s_test_heap_fail = 0;
}

static int test_begin_failure_and_generation_exhaustion_clear_prior_state(void)
{
    reset_fakes();
    pm_config_t active = active_config(4U);
    pm_provisioning_session_t session;
    pm_provisioning_session_init(&session, &active, true, provisioning_test, NULL, safe_reboot_prepare, NULL);
    memset(&session.candidate, 0xA5, sizeof(session.candidate));
    memset(session.enrollment_token, 0xA5, sizeof(session.enrollment_token));
    session.candidate_present = true;
    session.tests_passed = true;
    session.transaction.transaction_id = 99U;
    char response[1024] = {0};
    s_begin_error = ESP_FAIL;
    CHECK(pm_provisioning_handle_line(&session, begin_line(), response, sizeof(response)) == ESP_ERR_INVALID_ARG);
    CHECK(strstr(response, "candidate_invalid_or_write_failed") != NULL);
    CHECK(!session.candidate_present && !session.tests_passed);
    CHECK(all_zero(&session.candidate, sizeof(session.candidate)));
    CHECK(all_zero(session.enrollment_token, sizeof(session.enrollment_token)));
    CHECK(session.transaction.stage == PM_CONFIG_STAGE_NONE);

    active = active_config(UINT32_MAX);
    pm_provisioning_session_init(&session, &active, true, provisioning_test, NULL, safe_reboot_prepare, NULL);
    s_begin_calls = 0U;
    memset(response, 0, sizeof(response));
    CHECK(pm_provisioning_handle_line(&session, begin_line(), response, sizeof(response)) == ESP_ERR_INVALID_ARG);
    CHECK(s_begin_calls == 0U);
    CHECK(!session.candidate_present && !session.tests_passed);
    return 0;
}

static int test_failed_retest_clears_stale_success_and_partial_secret(void)
{
    reset_fakes();
    pm_config_t active = active_config(7U);
    pm_provisioning_session_t session;
    pm_provisioning_session_init(&session, &active, true, provisioning_test, NULL, safe_reboot_prepare, NULL);
    char response[1024] = {0};
    CHECK(pm_provisioning_handle_line(&session, begin_line(), response, sizeof(response)) == ESP_OK);
    CHECK(session.candidate_present);
    session.tests_passed = true;
    s_failed_stage = PM_PROVISIONING_TEST_ENROLLMENT;
    CHECK(pm_provisioning_handle_line(
              &session, "{\"protocol\":\"pm-com/1.0.0\",\"id\":\"2\",\"op\":\"test_config\"}",
              response, sizeof(response)) == ESP_FAIL);
    CHECK(strstr(response, "configuration_test_failed") != NULL);
    CHECK(!session.tests_passed && !session.candidate_present);
    CHECK(all_zero(&session.candidate, sizeof(session.candidate)));
    CHECK(all_zero(session.enrollment_token, sizeof(session.enrollment_token)));
    CHECK(session.transaction.stage == PM_CONFIG_STAGE_NONE);
    return 0;
}

static int test_safe_reboot_arms_only_after_successful_prepare_and_render(void)
{
    reset_fakes();
    pm_config_t active = active_config(2U);
    pm_provisioning_session_t session;
    pm_provisioning_session_init(&session, &active, true, provisioning_test, NULL, safe_reboot_prepare, NULL);
    char response[1024] = {0};
    const char *line = "{\"protocol\":\"pm-com/1.0.0\",\"id\":\"3\",\"op\":\"safe_reboot\"}";
    s_safe_reboot_result = ESP_FAIL;
    CHECK(pm_provisioning_handle_line(&session, line, response, sizeof(response)) == ESP_FAIL);
    CHECK(!session.reboot_requested);
    CHECK(strstr(response, "safe_reboot_preparation_failed") != NULL);

    s_safe_reboot_result = ESP_OK;
    CHECK(pm_provisioning_handle_line(&session, line, response, sizeof(response)) == ESP_OK);
    CHECK(session.reboot_requested);
    CHECK(strstr(response, "ready_for_safe_reboot") != NULL);

    session.reboot_requested = false;
    char tiny[8] = {0};
    CHECK(pm_provisioning_handle_line(&session, line, tiny, sizeof(tiny)) == ESP_ERR_INVALID_SIZE);
    CHECK(!session.reboot_requested);
    return 0;
}

static int test_oversized_frame_discards_suffix_until_newline(void)
{
    pm_com_framer_t framer = {0};
    char line[8] = {0};
    const char *oversized = "12345678suffix";
    unsigned int oversized_events = 0U;
    for (const char *cursor = oversized; *cursor != '\0'; ++cursor) {
        oversized_events += pm_provisioning_framer_push(&framer, (uint8_t)*cursor, line, sizeof(line)) ==
                            PM_COM_FRAME_OVERSIZED;
    }
    CHECK(oversized_events == 1U);
    CHECK(framer.discarding_oversized_line);
    CHECK(pm_provisioning_framer_push(&framer, '\n', line, sizeof(line)) == PM_COM_FRAME_NONE);
    CHECK(!framer.discarding_oversized_line);
    CHECK(all_zero(line, sizeof(line)));
    CHECK(pm_provisioning_framer_push(&framer, 'o', line, sizeof(line)) == PM_COM_FRAME_NONE);
    CHECK(pm_provisioning_framer_push(&framer, 'k', line, sizeof(line)) == PM_COM_FRAME_NONE);
    CHECK(pm_provisioning_framer_push(&framer, '\n', line, sizeof(line)) == PM_COM_FRAME_READY);
    CHECK(strcmp(line, "ok") == 0);
    return 0;
}

static int test_reboot_barrier_has_no_persistent_writer_to_drain(void)
{
    reset_fakes();
    CHECK(pm_provisioning_prepare_reboot_barrier() == ESP_OK);
    return 0;
}

static int test_reboot_requires_complete_write_and_tx_drain(void)
{
    CHECK(!pm_provisioning_reboot_tx_complete(false, 12U, 12, ESP_OK));
    CHECK(!pm_provisioning_reboot_tx_complete(true, 12U, 11, ESP_OK));
    CHECK(!pm_provisioning_reboot_tx_complete(true, 12U, 12, ESP_FAIL));
    CHECK(!pm_provisioning_reboot_tx_complete(true, 0U, 0, ESP_OK));
    CHECK(pm_provisioning_reboot_tx_complete(true, 12U, 12, ESP_OK));
    return 0;
}

static int test_usb_start_allocation_and_task_failure_cleanup(void)
{
    reset_fakes();
    pm_provisioning_session_t session = {0};
    s_test_heap_fail = 1;
    CHECK(pm_provisioning_start_usb(&session) == ESP_ERR_NO_MEM);
    CHECK(s_install_calls == 0U && s_uninstall_calls == 0U);
    s_test_heap_fail = 0;
    s_task_create_result = 0;
    CHECK(pm_provisioning_start_usb(&session) == ESP_ERR_NO_MEM);
    CHECK(s_install_calls == 1U && s_uninstall_calls == 1U);
    return 0;
}

int main(void)
{
    CHECK(test_begin_failure_and_generation_exhaustion_clear_prior_state() == 0);
    CHECK(test_failed_retest_clears_stale_success_and_partial_secret() == 0);
    CHECK(test_safe_reboot_arms_only_after_successful_prepare_and_render() == 0);
    CHECK(test_oversized_frame_discards_suffix_until_newline() == 0);
    CHECK(test_reboot_barrier_has_no_persistent_writer_to_drain() == 0);
    CHECK(test_reboot_requires_complete_write_and_tx_drain() == 0);
    CHECK(test_usb_start_allocation_and_task_failure_cleanup() == 0);
    puts("pm_provisioning state-machine tests passed");
    return 0;
}
