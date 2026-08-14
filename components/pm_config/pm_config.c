#include "pm_config.h"

#include <stddef.h>
#include <string.h>

#include "esp_check.h"
#include "nvs.h"

#define PM_CONFIG_NAMESPACE "pm_config"
#define PM_CONFIG_SLOT_A "slot_a"
#define PM_CONFIG_SLOT_B "slot_b"
#define PM_CONFIG_ACTIVE "active"

uint32_t pm_crc32_ieee(const void *data, size_t length)
{
    const uint8_t *bytes = (const uint8_t *)data;
    uint32_t crc = UINT32_C(0xFFFFFFFF);
    for (size_t i = 0U; i < length; ++i) {
        crc ^= bytes[i];
        for (uint8_t bit = 0U; bit < 8U; ++bit) {
            const uint32_t mask = (uint32_t)-(int32_t)(crc & 1U);
            crc = (crc >> 1U) ^ (UINT32_C(0xEDB88320) & mask);
        }
    }
    return ~crc;
}

static uint32_t config_crc(const pm_config_t *config)
{
    return pm_crc32_ieee(config, offsetof(pm_config_t, crc32));
}

static bool nul_terminated(const char *value, size_t capacity)
{
    return memchr(value, '\0', capacity) != NULL;
}

esp_err_t pm_config_validate(const pm_config_t *config, bool production_gate)
{
    if (config == NULL || config->schema_version != PM_CONFIG_SCHEMA_VERSION ||
        config->crc32 != config_crc(config)) {
        return ESP_ERR_INVALID_CRC;
    }
    if (!nul_terminated(config->friendly_name, sizeof(config->friendly_name)) ||
        !nul_terminated(config->wifi_ssid, sizeof(config->wifi_ssid)) ||
        !nul_terminated(config->wifi_password, sizeof(config->wifi_password)) ||
        !nul_terminated(config->server_origin, sizeof(config->server_origin)) ||
        !nul_terminated(config->ca_pem, sizeof(config->ca_pem)) ||
        !nul_terminated(config->timezone, sizeof(config->timezone))) {
        return ESP_ERR_INVALID_SIZE;
    }
    if (config->friendly_name[0] == '\0' || config->wifi_ssid[0] == '\0' ||
        strncmp(config->server_origin, "https://", 8U) != 0 || config->ca_pem[0] == '\0' ||
        config->timezone[0] == '\0' || config->ct_rating_a == 0U || config->ct_rating_a > 100U ||
        config->device_secret_len > PM_CONFIG_SECRET_MAX ||
        config->acknowledged_sequence > config->sequence_floor) {
        return ESP_ERR_INVALID_ARG;
    }
    if (production_gate && config->meter_variant != PM_METER_PZEM004T_V4_CLASSIC) {
        return ESP_ERR_NOT_SUPPORTED;
    }
    if (config->ipv4_mode == PM_IPV4_STATIC &&
        (config->ipv4_address == 0U || config->ipv4_gateway == 0U || config->ipv4_netmask == 0U ||
         config->dns_primary == 0U)) {
        return ESP_ERR_INVALID_ARG;
    }
    return ESP_OK;
}

static esp_err_t read_slot(nvs_handle_t handle, const char *key, pm_config_t *config)
{
    size_t length = sizeof(*config);
    esp_err_t error = nvs_get_blob(handle, key, config, &length);
    if (error != ESP_OK) {
        return error;
    }
    return length == sizeof(*config) ? pm_config_validate(config, false) : ESP_ERR_INVALID_SIZE;
}

esp_err_t pm_config_load(pm_config_t *config)
{
    if (config == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    nvs_handle_t handle = 0;
    ESP_RETURN_ON_ERROR(nvs_open(PM_CONFIG_NAMESPACE, NVS_READONLY, &handle), "pm_config", "open");
    uint8_t active = (uint8_t)'A';
    esp_err_t error = nvs_get_u8(handle, PM_CONFIG_ACTIVE, &active);
    if (error == ESP_ERR_NVS_NOT_FOUND) {
        error = ESP_ERR_NOT_FOUND;
    } else if (error == ESP_OK) {
        error = read_slot(handle, active == (uint8_t)'B' ? PM_CONFIG_SLOT_B : PM_CONFIG_SLOT_A, config);
        if (error != ESP_OK) {
            error = read_slot(handle, active == (uint8_t)'B' ? PM_CONFIG_SLOT_A : PM_CONFIG_SLOT_B, config);
        }
    }
    nvs_close(handle);
    return error;
}

esp_err_t pm_config_begin(const pm_config_t *candidate, pm_config_transaction_t *transaction)
{
    if (candidate == NULL || transaction == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    pm_config_t staged = *candidate;
    staged.schema_version = PM_CONFIG_SCHEMA_VERSION;
    staged.crc32 = config_crc(&staged);
    ESP_RETURN_ON_ERROR(pm_config_validate(&staged, false), "pm_config", "candidate");

    nvs_handle_t handle = 0;
    ESP_RETURN_ON_ERROR(nvs_open(PM_CONFIG_NAMESPACE, NVS_READWRITE, &handle), "pm_config", "open");
    uint8_t active = (uint8_t)'A';
    (void)nvs_get_u8(handle, PM_CONFIG_ACTIVE, &active);
    const char inactive = active == (uint8_t)'A' ? 'B' : 'A';
    const char *key = inactive == 'B' ? PM_CONFIG_SLOT_B : PM_CONFIG_SLOT_A;
    esp_err_t error = nvs_set_blob(handle, key, &staged, sizeof(staged));
    if (error == ESP_OK) {
        error = nvs_commit(handle);
    }
    pm_config_t verified = {0};
    if (error == ESP_OK) {
        error = read_slot(handle, key, &verified);
    }
    nvs_close(handle);
    if (error != ESP_OK || memcmp(&verified, &staged, sizeof(staged)) != 0) {
        return error == ESP_OK ? ESP_FAIL : error;
    }
    *transaction = (pm_config_transaction_t){
        .stage = PM_CONFIG_STAGE_READBACK_VERIFIED,
        .candidate_generation = staged.generation,
        .candidate_slot = inactive,
    };
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
    if (transaction == NULL || transaction->stage != PM_CONFIG_STAGE_NETWORK_TESTED ||
        (transaction->candidate_slot != 'A' && transaction->candidate_slot != 'B')) {
        return ESP_ERR_INVALID_STATE;
    }
    nvs_handle_t handle = 0;
    ESP_RETURN_ON_ERROR(nvs_open(PM_CONFIG_NAMESPACE, NVS_READWRITE, &handle), "pm_config", "open");
    esp_err_t error = nvs_set_u8(handle, PM_CONFIG_ACTIVE, (uint8_t)transaction->candidate_slot);
    if (error == ESP_OK) {
        error = nvs_commit(handle);
    }
    nvs_close(handle);
    if (error == ESP_OK) {
        transaction->stage = PM_CONFIG_STAGE_COMMITTED;
    }
    return error;
}

void pm_config_abort(pm_config_transaction_t *transaction)
{
    if (transaction != NULL) {
        *transaction = (pm_config_transaction_t){0};
    }
}

bool pm_config_secret_field_name(const char *name)
{
    static const char *const secrets[] = {
        "wifi_password", "enrollment_token", "device_secret", "hmac_key", "private_key",
        "session_cookie", "administrator_credential",
    };
    if (name == NULL) {
        return false;
    }
    for (size_t i = 0U; i < sizeof(secrets) / sizeof(secrets[0]); ++i) {
        if (strcmp(name, secrets[i]) == 0) {
            return true;
        }
    }
    return false;
}

