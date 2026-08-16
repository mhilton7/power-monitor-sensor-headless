#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "nvs.h"
#include "pm_config.h"
#include "pm_protocol.h"

#define CHECK(condition)                                                                                              \
    do {                                                                                                              \
        if (!(condition)) {                                                                                           \
            fprintf(stderr, "check failed at %s:%d: %s\n", __FILE__, __LINE__, #condition);                         \
            return 1;                                                                                                 \
        }                                                                                                             \
    } while (0)

typedef struct {
    bool present;
    pm_config_t config;
} config_slot_t;

static config_slot_t s_slot_a;
static config_slot_t s_slot_b;
static bool s_active_present;
static uint8_t s_active;
static esp_err_t s_get_active_error;
static bool s_open_fails;
static bool s_set_blob_fails;
static bool s_commit_fails;
static bool s_reenter_on_slot_read;
static esp_err_t s_reenter_result;
static pm_config_t s_reenter_candidate;
int s_test_heap_fail;

static config_slot_t *slot_for_key(const char *key)
{
    if (strcmp(key, "slot_a") == 0) {
        return &s_slot_a;
    }
    if (strcmp(key, "slot_b") == 0) {
        return &s_slot_b;
    }
    return NULL;
}

esp_err_t nvs_open(const char *namespace_name, nvs_open_mode_t open_mode, nvs_handle_t *out_handle)
{
    (void)open_mode;
    if (s_open_fails) {
        return ESP_FAIL;
    }
    if (namespace_name == NULL || strcmp(namespace_name, "pm_config") != 0 || out_handle == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    *out_handle = 1U;
    return ESP_OK;
}

void nvs_close(nvs_handle_t handle)
{
    (void)handle;
}

esp_err_t nvs_get_blob(nvs_handle_t handle, const char *key, void *out_value, size_t *length)
{
    config_slot_t *slot = slot_for_key(key);
    if (handle != 1U || slot == NULL || length == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    if (!slot->present) {
        return ESP_ERR_NVS_NOT_FOUND;
    }
    if (out_value == NULL || *length < sizeof(slot->config)) {
        *length = sizeof(slot->config);
        return ESP_ERR_INVALID_SIZE;
    }
    if (s_reenter_on_slot_read) {
        s_reenter_on_slot_read = false;
        pm_config_transaction_t zero_transaction = {0};
        pm_config_abort(&zero_transaction);
        pm_config_transaction_t competing_transaction = {0};
        s_reenter_result = pm_config_begin(&s_reenter_candidate, &competing_transaction);
        if (s_reenter_result == ESP_OK) {
            pm_config_abort(&competing_transaction);
        }
    }
    memcpy(out_value, &slot->config, sizeof(slot->config));
    *length = sizeof(slot->config);
    return ESP_OK;
}

esp_err_t nvs_set_blob(nvs_handle_t handle, const char *key, const void *value, size_t length)
{
    config_slot_t *slot = slot_for_key(key);
    if (handle != 1U || slot == NULL || value == NULL || length != sizeof(slot->config)) {
        return ESP_ERR_INVALID_ARG;
    }
    if (s_set_blob_fails) {
        return ESP_FAIL;
    }
    memcpy(&slot->config, value, sizeof(slot->config));
    slot->present = true;
    return ESP_OK;
}

esp_err_t nvs_get_u8(nvs_handle_t handle, const char *key, uint8_t *value)
{
    if (handle != 1U || strcmp(key, "active") != 0 || value == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    if (s_get_active_error != ESP_OK) {
        return s_get_active_error;
    }
    if (!s_active_present) {
        return ESP_ERR_NVS_NOT_FOUND;
    }
    *value = s_active;
    return ESP_OK;
}

esp_err_t nvs_set_u8(nvs_handle_t handle, const char *key, uint8_t value)
{
    if (handle != 1U || strcmp(key, "active") != 0) {
        return ESP_ERR_INVALID_ARG;
    }
    s_active = value;
    s_active_present = true;
    return ESP_OK;
}

esp_err_t nvs_erase_key(nvs_handle_t handle, const char *key)
{
    config_slot_t *slot = slot_for_key(key);
    if (handle != 1U || slot == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    if (!slot->present) {
        return ESP_ERR_NVS_NOT_FOUND;
    }
    memset(slot, 0, sizeof(*slot));
    return ESP_OK;
}

esp_err_t nvs_commit(nvs_handle_t handle)
{
    return handle == 1U ? (s_commit_fails ? ESP_FAIL : ESP_OK) : ESP_ERR_INVALID_ARG;
}

void pm_sha256(const uint8_t *data, size_t length, uint8_t digest[PM_SHA256_SIZE])
{
    uint32_t state = UINT32_C(2166136261);
    for (size_t index = 0U; index < length; ++index) {
        state = (state ^ data[index]) * UINT32_C(16777619);
    }
    for (size_t index = 0U; index < PM_SHA256_SIZE; ++index) {
        state = state * UINT32_C(1664525) + UINT32_C(1013904223);
        digest[index] = (uint8_t)(state >> 24U);
    }
}

bool pm_constant_time_equal(const uint8_t *left, const uint8_t *right, size_t length)
{
    uint8_t difference = 0U;
    for (size_t index = 0U; index < length; ++index) {
        difference |= left[index] ^ right[index];
    }
    return difference == 0U;
}

static pm_config_t valid_config(uint32_t generation, const char *name)
{
    pm_config_t config = {0};
    config.schema_version = PM_CONFIG_SCHEMA_VERSION;
    config.generation = generation;
    (void)snprintf(config.friendly_name, sizeof(config.friendly_name), "%s", name);
    (void)snprintf(config.wifi_ssid, sizeof(config.wifi_ssid), "test-ssid");
    (void)snprintf(config.server_origin, sizeof(config.server_origin), "https://power-monitor.test");
    (void)snprintf(config.ca_pem, sizeof(config.ca_pem), "test-ca");
    (void)snprintf(config.timezone, sizeof(config.timezone), "America/Los_Angeles");
    config.ct_rating_a = 100U;
    config.meter_variant = PM_METER_PZEM004T_V4_CLASSIC;
    config.crc32 = pm_crc32_ieee(&config, offsetof(pm_config_t, crc32));
    return config;
}

static void reset_nvs(void)
{
    memset(&s_slot_a, 0, sizeof(s_slot_a));
    memset(&s_slot_b, 0, sizeof(s_slot_b));
    s_active_present = true;
    s_active = (uint8_t)'A';
    s_get_active_error = ESP_OK;
    s_open_fails = false;
    s_set_blob_fails = false;
    s_commit_fails = false;
    s_reenter_on_slot_read = false;
    s_reenter_result = ESP_OK;
    s_test_heap_fail = 0;
}

static int test_transaction_excludes_competing_begin_and_zero_abort_does_not_unlock(void)
{
    reset_nvs();
    const pm_config_t first = valid_config(1U, "first");
    const pm_config_t second = valid_config(1U, "second");
    pm_config_transaction_t first_transaction = {0};
    pm_config_transaction_t second_transaction = {0};
    CHECK(pm_config_begin(&first, &first_transaction) == ESP_OK);
    CHECK(pm_config_begin(&second, &second_transaction) == ESP_ERR_INVALID_STATE);
    pm_config_abort(&second_transaction);
    CHECK(pm_config_begin(&second, &second_transaction) == ESP_ERR_INVALID_STATE);
    pm_config_abort(&first_transaction);
    CHECK(pm_config_begin(&second, &second_transaction) == ESP_OK);
    pm_config_abort(&second_transaction);
    return 0;
}

static int test_commit_rejects_same_generation_content_replacement(void)
{
    reset_nvs();
    const pm_config_t candidate = valid_config(2U, "selected");
    pm_config_transaction_t transaction = {0};
    CHECK(pm_config_begin(&candidate, &transaction) == ESP_OK);
    s_slot_b.config = valid_config(2U, "replaced");
    CHECK(pm_config_mark_network_tested(&transaction) == ESP_OK);
    CHECK(pm_config_commit(&transaction) == ESP_ERR_INVALID_STATE);
    CHECK(transaction.stage == PM_CONFIG_STAGE_NONE);
    CHECK(s_active == (uint8_t)'A');
    return 0;
}

static int test_allocation_and_nvs_failures_release_transaction_owner(void)
{
    reset_nvs();
    const pm_config_t candidate = valid_config(3U, "candidate");
    pm_config_transaction_t transaction = {0};
    s_test_heap_fail = 1;
    CHECK(pm_config_begin(&candidate, &transaction) == ESP_ERR_NO_MEM);
    s_test_heap_fail = 0;
    s_open_fails = true;
    CHECK(pm_config_begin(&candidate, &transaction) == ESP_FAIL);
    s_open_fails = false;
    s_set_blob_fails = true;
    CHECK(pm_config_begin(&candidate, &transaction) == ESP_FAIL);
    s_set_blob_fails = false;
    CHECK(pm_config_begin(&candidate, &transaction) == ESP_OK);
    pm_config_abort(&transaction);
    return 0;
}

static int test_zero_abort_cannot_unlock_unowned_mutation(void)
{
    reset_nvs();
    s_slot_b.present = true;
    s_slot_b.config = valid_config(4U, "staged");
    s_reenter_candidate = valid_config(5U, "competing");
    s_reenter_on_slot_read = true;
    CHECK(pm_config_activate_staged('B', 4U) == ESP_OK);
    CHECK(s_reenter_result == ESP_ERR_INVALID_STATE);
    CHECK(s_active == (uint8_t)'B');
    return 0;
}

static int test_invalid_or_unreadable_active_selector_fails_closed(void)
{
    reset_nvs();
    s_slot_a.present = true;
    s_slot_a.config = valid_config(3U, "active-a");
    s_slot_b.present = true;
    s_slot_b.config = valid_config(4U, "active-b");
    pm_config_t loaded;
    memset(&loaded, 0xA5, sizeof(loaded));
    s_active = (uint8_t)'X';
    CHECK(pm_config_load(&loaded) == ESP_ERR_INVALID_STATE);
    const pm_config_t empty = {0};
    CHECK(memcmp(&loaded, &empty, sizeof(loaded)) == 0);

    memset(&loaded, 0xA5, sizeof(loaded));
    s_active = (uint8_t)'B';
    s_get_active_error = ESP_FAIL;
    CHECK(pm_config_load(&loaded) == ESP_FAIL);
    CHECK(memcmp(&loaded, &empty, sizeof(loaded)) == 0);
    return 0;
}

static int test_begin_rejects_invalid_or_unreadable_active_selector(void)
{
    reset_nvs();
    const pm_config_t candidate = valid_config(5U, "candidate");
    pm_config_transaction_t transaction = {0};
    s_active = (uint8_t)'X';
    CHECK(pm_config_begin(&candidate, &transaction) == ESP_ERR_INVALID_STATE);
    CHECK(transaction.stage == PM_CONFIG_STAGE_NONE);
    s_active = (uint8_t)'A';
    s_get_active_error = ESP_FAIL;
    CHECK(pm_config_begin(&candidate, &transaction) == ESP_FAIL);
    CHECK(transaction.stage == PM_CONFIG_STAGE_NONE);
    s_get_active_error = ESP_OK;
    CHECK(pm_config_begin(&candidate, &transaction) == ESP_OK);
    pm_config_abort(&transaction);
    return 0;
}

static int test_load_never_boots_uncommitted_inactive_fallback(void)
{
    reset_nvs();
    s_slot_a.present = true;
    s_slot_a.config = valid_config(8U, "committed-corrupt");
    s_slot_a.config.crc32 ^= 1U;
    s_slot_b.present = true;
    s_slot_b.config = valid_config(9U, "uncommitted-candidate");
    pm_config_t loaded;
    memset(&loaded, 0xA5, sizeof(loaded));
    CHECK(pm_config_load(&loaded) == ESP_ERR_INVALID_CRC);
    const pm_config_t empty = {0};
    CHECK(memcmp(&loaded, &empty, sizeof(loaded)) == 0);
    return 0;
}

int main(void)
{
    CHECK(test_transaction_excludes_competing_begin_and_zero_abort_does_not_unlock() == 0);
    CHECK(test_commit_rejects_same_generation_content_replacement() == 0);
    CHECK(test_allocation_and_nvs_failures_release_transaction_owner() == 0);
    CHECK(test_zero_abort_cannot_unlock_unowned_mutation() == 0);
    CHECK(test_invalid_or_unreadable_active_selector_fails_closed() == 0);
    CHECK(test_begin_rejects_invalid_or_unreadable_active_selector() == 0);
    CHECK(test_load_never_boots_uncommitted_inactive_fallback() == 0);
    puts("pm_config transaction tests passed");
    return 0;
}
