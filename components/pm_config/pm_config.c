#include "pm_config.h"

#include <stddef.h>
#include <string.h>

#include "esp_check.h"
#include "esp_heap_caps.h"
#include "freertos/FreeRTOS.h"
#include "nvs.h"
#include "pm_protocol.h"

#define PM_CONFIG_NAMESPACE "pm_config"
#define PM_CONFIG_SLOT_A "slot_a"
#define PM_CONFIG_SLOT_B "slot_b"
#define PM_CONFIG_ACTIVE "active"

typedef struct {
    pm_config_t staged;
    pm_config_t verified;
} pm_config_begin_workspace_t;

static portMUX_TYPE s_mutation_lock = portMUX_INITIALIZER_UNLOCKED;
static uint32_t s_next_transaction_id = 1U;
static uint32_t s_active_transaction_id;
static bool s_mutation_in_progress;

static const char *slot_key(char slot);

static void secure_zero(void *value, size_t length)
{
    volatile uint8_t *bytes = (volatile uint8_t *)value;
    while (length-- > 0U) {
        *bytes++ = 0U;
    }
}

static void *allocate_config_workspace(size_t size)
{
    void *workspace = heap_caps_calloc(1U, size, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if (workspace == NULL) {
        workspace = heap_caps_calloc(1U, size, MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
    }
    return workspace;
}

static void free_config_workspace(void *workspace, size_t size)
{
    if (workspace != NULL) {
        secure_zero(workspace, size);
        heap_caps_free(workspace);
    }
}

static bool claim_new_transaction(uint32_t *transaction_id)
{
    bool claimed = false;
    taskENTER_CRITICAL(&s_mutation_lock);
    if (s_active_transaction_id == 0U && !s_mutation_in_progress) {
        uint32_t next = s_next_transaction_id++;
        if (next == 0U) {
            next = s_next_transaction_id++;
        }
        s_active_transaction_id = next;
        s_mutation_in_progress = true;
        *transaction_id = next;
        claimed = true;
    }
    taskEXIT_CRITICAL(&s_mutation_lock);
    return claimed;
}

static bool claim_transaction_mutation(uint32_t transaction_id)
{
    bool claimed = false;
    taskENTER_CRITICAL(&s_mutation_lock);
    if (transaction_id != 0U && s_active_transaction_id == transaction_id && !s_mutation_in_progress) {
        s_mutation_in_progress = true;
        claimed = true;
    }
    taskEXIT_CRITICAL(&s_mutation_lock);
    return claimed;
}

static bool claim_unowned_mutation(void)
{
    bool claimed = false;
    taskENTER_CRITICAL(&s_mutation_lock);
    if (s_active_transaction_id == 0U && !s_mutation_in_progress) {
        s_mutation_in_progress = true;
        claimed = true;
    }
    taskEXIT_CRITICAL(&s_mutation_lock);
    return claimed;
}

static void finish_mutation(void)
{
    taskENTER_CRITICAL(&s_mutation_lock);
    s_mutation_in_progress = false;
    taskEXIT_CRITICAL(&s_mutation_lock);
}

static void release_transaction(uint32_t transaction_id)
{
    taskENTER_CRITICAL(&s_mutation_lock);
    if (transaction_id != 0U && s_active_transaction_id == transaction_id) {
        s_active_transaction_id = 0U;
        s_mutation_in_progress = false;
    }
    taskEXIT_CRITICAL(&s_mutation_lock);
}

static bool transaction_is_active(uint32_t transaction_id)
{
    bool active = false;
    taskENTER_CRITICAL(&s_mutation_lock);
    active = transaction_id != 0U && s_active_transaction_id == transaction_id && !s_mutation_in_progress;
    taskEXIT_CRITICAL(&s_mutation_lock);
    return active;
}

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
        secure_zero(config, sizeof(*config));
        return error;
    }
    error = length == sizeof(*config) ? pm_config_validate(config, false) : ESP_ERR_INVALID_SIZE;
    if (error != ESP_OK) {
        secure_zero(config, sizeof(*config));
    }
    return error;
}

esp_err_t pm_config_load(pm_config_t *config)
{
    if (config == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    nvs_handle_t handle = 0;
    esp_err_t error = nvs_open(PM_CONFIG_NAMESPACE, NVS_READONLY, &handle);
    if (error != ESP_OK) {
        secure_zero(config, sizeof(*config));
        return error;
    }
    uint8_t active = (uint8_t)'A';
    error = nvs_get_u8(handle, PM_CONFIG_ACTIVE, &active);
    if (error == ESP_ERR_NVS_NOT_FOUND) {
        error = ESP_ERR_NOT_FOUND;
    } else if (error == ESP_OK) {
        if (active != (uint8_t)'A' && active != (uint8_t)'B') {
            error = ESP_ERR_INVALID_STATE;
        } else {
            /* The selector is the commit point. Never boot the inactive slot
             * as a fallback: it may contain a readback-verified candidate that
             * did not pass network/enrollment tests or commit. */
            error = read_slot(handle, active == (uint8_t)'B' ? PM_CONFIG_SLOT_B : PM_CONFIG_SLOT_A, config);
        }
    }
    nvs_close(handle);
    if (error != ESP_OK) {
        secure_zero(config, sizeof(*config));
    }
    return error;
}

esp_err_t pm_config_begin(const pm_config_t *candidate, pm_config_transaction_t *transaction)
{
    if (candidate == NULL || transaction == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    pm_config_begin_workspace_t *workspace =
        (pm_config_begin_workspace_t *)allocate_config_workspace(sizeof(*workspace));
    if (workspace == NULL) {
        return ESP_ERR_NO_MEM;
    }
    workspace->staged = *candidate;
    workspace->staged.schema_version = PM_CONFIG_SCHEMA_VERSION;
    workspace->staged.crc32 = config_crc(&workspace->staged);
    esp_err_t error = pm_config_validate(&workspace->staged, false);
    if (error != ESP_OK) {
        free_config_workspace(workspace, sizeof(*workspace));
        return error;
    }

    const bool restaging = transaction->stage == PM_CONFIG_STAGE_READBACK_VERIFIED &&
                           transaction->transaction_id != 0U &&
                           (transaction->candidate_slot == 'A' || transaction->candidate_slot == 'B');
    uint32_t transaction_id = restaging ? transaction->transaction_id : 0U;
    const bool claimed = restaging ? claim_transaction_mutation(transaction_id) :
                                     claim_new_transaction(&transaction_id);
    if (!claimed) {
        free_config_workspace(workspace, sizeof(*workspace));
        return ESP_ERR_INVALID_STATE;
    }

    nvs_handle_t handle = 0;
    error = nvs_open(PM_CONFIG_NAMESPACE, NVS_READWRITE, &handle);
    if (error != ESP_OK) {
        release_transaction(transaction_id);
        secure_zero(transaction, sizeof(*transaction));
        free_config_workspace(workspace, sizeof(*workspace));
        return error;
    }
    uint8_t active = (uint8_t)'A';
    const esp_err_t active_error = nvs_get_u8(handle, PM_CONFIG_ACTIVE, &active);
    if (active_error == ESP_ERR_NVS_NOT_FOUND) {
        active = (uint8_t)'A';
    } else if (active_error != ESP_OK) {
        error = active_error;
    } else if (active != (uint8_t)'A' && active != (uint8_t)'B') {
        error = ESP_ERR_INVALID_STATE;
    }
    const char inactive = restaging ? transaction->candidate_slot :
                          active == (uint8_t)'A' ? 'B' : 'A';
    if (restaging && active == (uint8_t)inactive) {
        error = ESP_ERR_INVALID_STATE;
    }
    const char *key = inactive == 'B' ? PM_CONFIG_SLOT_B : PM_CONFIG_SLOT_A;
    if (error == ESP_OK) {
        error = nvs_set_blob(handle, key, &workspace->staged, sizeof(workspace->staged));
    }
    if (error == ESP_OK) {
        error = nvs_commit(handle);
    }
    if (error == ESP_OK) {
        error = read_slot(handle, key, &workspace->verified);
    }
    nvs_close(handle);
    if (error == ESP_OK && memcmp(&workspace->verified, &workspace->staged, sizeof(workspace->staged)) != 0) {
        error = ESP_FAIL;
    }
    if (error == ESP_OK) {
        uint8_t candidate_sha256[PM_CONFIG_CONTENT_HASH_LEN];
        pm_sha256((const uint8_t *)&workspace->staged, sizeof(workspace->staged), candidate_sha256);
        *transaction = (pm_config_transaction_t){
            .stage = PM_CONFIG_STAGE_READBACK_VERIFIED,
            .candidate_generation = workspace->staged.generation,
            .transaction_id = transaction_id,
            .candidate_slot = inactive,
        };
        memcpy(transaction->candidate_sha256, candidate_sha256, sizeof(candidate_sha256));
        secure_zero(candidate_sha256, sizeof(candidate_sha256));
        finish_mutation();
    } else {
        release_transaction(transaction_id);
        secure_zero(transaction, sizeof(*transaction));
    }
    free_config_workspace(workspace, sizeof(*workspace));
    return error;
}

esp_err_t pm_config_mark_network_tested(pm_config_transaction_t *transaction)
{
    if (transaction == NULL || transaction->stage != PM_CONFIG_STAGE_READBACK_VERIFIED ||
        !transaction_is_active(transaction->transaction_id)) {
        return ESP_ERR_INVALID_STATE;
    }
    transaction->stage = PM_CONFIG_STAGE_NETWORK_TESTED;
    return ESP_OK;
}

esp_err_t pm_config_commit(pm_config_transaction_t *transaction)
{
    if (transaction == NULL || transaction->stage != PM_CONFIG_STAGE_NETWORK_TESTED ||
        transaction->transaction_id == 0U ||
        (transaction->candidate_slot != 'A' && transaction->candidate_slot != 'B')) {
        return ESP_ERR_INVALID_STATE;
    }
    pm_config_t *candidate = (pm_config_t *)allocate_config_workspace(sizeof(*candidate));
    if (candidate == NULL) {
        return ESP_ERR_NO_MEM;
    }
    const uint32_t transaction_id = transaction->transaction_id;
    if (!claim_transaction_mutation(transaction_id)) {
        free_config_workspace(candidate, sizeof(*candidate));
        return ESP_ERR_INVALID_STATE;
    }
    nvs_handle_t handle = 0;
    esp_err_t error = nvs_open(PM_CONFIG_NAMESPACE, NVS_READWRITE, &handle);
    const char *key = slot_key(transaction->candidate_slot);
    if (error == ESP_OK) {
        error = read_slot(handle, key, candidate);
    }
    uint8_t candidate_sha256[PM_CONFIG_CONTENT_HASH_LEN] = {0};
    if (error == ESP_OK) {
        pm_sha256((const uint8_t *)candidate, sizeof(*candidate), candidate_sha256);
        if (candidate->generation != transaction->candidate_generation ||
            !pm_constant_time_equal(candidate_sha256, transaction->candidate_sha256,
                                    sizeof(candidate_sha256))) {
            error = ESP_ERR_INVALID_STATE;
        }
    }
    if (error == ESP_OK) {
        error = nvs_set_u8(handle, PM_CONFIG_ACTIVE, (uint8_t)transaction->candidate_slot);
    }
    if (error == ESP_OK) {
        error = nvs_commit(handle);
    }
    if (handle != 0) {
        nvs_close(handle);
    }
    secure_zero(candidate_sha256, sizeof(candidate_sha256));
    free_config_workspace(candidate, sizeof(*candidate));
    release_transaction(transaction_id);
    secure_zero(transaction, sizeof(*transaction));
    if (error == ESP_OK) {
        transaction->stage = PM_CONFIG_STAGE_COMMITTED;
    }
    return error;
}

static const char *slot_key(char slot)
{
    return slot == 'A' ? PM_CONFIG_SLOT_A : slot == 'B' ? PM_CONFIG_SLOT_B : NULL;
}

esp_err_t pm_config_load_staged(char slot, uint32_t expected_generation, pm_config_t *config)
{
    const char *key = slot_key(slot);
    if (key == NULL || expected_generation == 0U || config == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    nvs_handle_t handle = 0;
    esp_err_t error = nvs_open(PM_CONFIG_NAMESPACE, NVS_READONLY, &handle);
    if (error != ESP_OK) {
        secure_zero(config, sizeof(*config));
        return error;
    }
    error = read_slot(handle, key, config);
    nvs_close(handle);
    if (error == ESP_OK && config->generation != expected_generation) {
        secure_zero(config, sizeof(*config));
        return ESP_ERR_INVALID_STATE;
    }
    return error;
}

esp_err_t pm_config_activate_staged(char slot, uint32_t expected_generation)
{
    const char *key = slot_key(slot);
    if (key == NULL || expected_generation == 0U) {
        return ESP_ERR_INVALID_ARG;
    }
    pm_config_t *candidate = (pm_config_t *)allocate_config_workspace(sizeof(*candidate));
    if (candidate == NULL) {
        return ESP_ERR_NO_MEM;
    }
    if (!claim_unowned_mutation()) {
        free_config_workspace(candidate, sizeof(*candidate));
        return ESP_ERR_INVALID_STATE;
    }
    nvs_handle_t handle = 0;
    esp_err_t error = nvs_open(PM_CONFIG_NAMESPACE, NVS_READWRITE, &handle);
    if (error != ESP_OK) {
        finish_mutation();
        free_config_workspace(candidate, sizeof(*candidate));
        return error;
    }
    error = read_slot(handle, key, candidate);
    if (error == ESP_OK && candidate->generation != expected_generation) {
        error = ESP_ERR_INVALID_STATE;
    }
    uint8_t active = 0U;
    if (error == ESP_OK) {
        error = nvs_get_u8(handle, PM_CONFIG_ACTIVE, &active);
    }
    if (error == ESP_OK && active != (uint8_t)slot) {
        error = nvs_set_u8(handle, PM_CONFIG_ACTIVE, (uint8_t)slot);
        if (error == ESP_OK) {
            error = nvs_commit(handle);
        }
    }
    nvs_close(handle);
    finish_mutation();
    free_config_workspace(candidate, sizeof(*candidate));
    return error;
}

esp_err_t pm_config_discard_staged(char slot, uint32_t expected_generation)
{
    const char *key = slot_key(slot);
    if (key == NULL || expected_generation == 0U) {
        return ESP_ERR_INVALID_ARG;
    }
    pm_config_t *candidate = (pm_config_t *)allocate_config_workspace(sizeof(*candidate));
    if (candidate == NULL) {
        return ESP_ERR_NO_MEM;
    }
    if (!claim_unowned_mutation()) {
        free_config_workspace(candidate, sizeof(*candidate));
        return ESP_ERR_INVALID_STATE;
    }
    nvs_handle_t handle = 0;
    esp_err_t error = nvs_open(PM_CONFIG_NAMESPACE, NVS_READWRITE, &handle);
    if (error != ESP_OK) {
        finish_mutation();
        free_config_workspace(candidate, sizeof(*candidate));
        return error;
    }
    uint8_t active = 0U;
    error = nvs_get_u8(handle, PM_CONFIG_ACTIVE, &active);
    if (error == ESP_OK && active == (uint8_t)slot) {
        error = ESP_ERR_INVALID_STATE;
    } else if (error == ESP_OK) {
        error = read_slot(handle, key, candidate);
        if (error == ESP_ERR_NVS_NOT_FOUND) {
            error = ESP_OK;
        } else if (error == ESP_OK && candidate->generation != expected_generation) {
            error = ESP_ERR_INVALID_STATE;
        } else if (error == ESP_OK) {
            error = nvs_erase_key(handle, key);
            if (error == ESP_OK) {
                error = nvs_commit(handle);
            }
        }
    }
    nvs_close(handle);
    finish_mutation();
    free_config_workspace(candidate, sizeof(*candidate));
    return error;
}

esp_err_t pm_config_discard_inactive_generation(uint32_t expected_generation)
{
    if (expected_generation == 0U) {
        return ESP_ERR_INVALID_ARG;
    }
    pm_config_t *candidate = (pm_config_t *)allocate_config_workspace(sizeof(*candidate));
    if (candidate == NULL) {
        return ESP_ERR_NO_MEM;
    }
    if (!claim_unowned_mutation()) {
        free_config_workspace(candidate, sizeof(*candidate));
        return ESP_ERR_INVALID_STATE;
    }
    nvs_handle_t handle = 0;
    esp_err_t error = nvs_open(PM_CONFIG_NAMESPACE, NVS_READWRITE, &handle);
    if (error != ESP_OK) {
        finish_mutation();
        free_config_workspace(candidate, sizeof(*candidate));
        return error;
    }
    uint8_t active = 0U;
    error = nvs_get_u8(handle, PM_CONFIG_ACTIVE, &active);
    if (error == ESP_OK && active != (uint8_t)'A' && active != (uint8_t)'B') {
        error = ESP_ERR_INVALID_STATE;
    }
    const char *key = active == (uint8_t)'A' ? PM_CONFIG_SLOT_B : PM_CONFIG_SLOT_A;
    if (error == ESP_OK) {
        error = read_slot(handle, key, candidate);
        if (error == ESP_ERR_NVS_NOT_FOUND ||
            (error == ESP_OK && candidate->generation != expected_generation)) {
            error = ESP_OK;
        } else if (error == ESP_OK) {
            error = nvs_erase_key(handle, key);
            if (error == ESP_OK) {
                error = nvs_commit(handle);
            }
        }
    }
    nvs_close(handle);
    finish_mutation();
    free_config_workspace(candidate, sizeof(*candidate));
    return error;
}

esp_err_t pm_config_erase_inactive(void)
{
    if (!claim_unowned_mutation()) {
        return ESP_ERR_INVALID_STATE;
    }
    nvs_handle_t handle = 0;
    esp_err_t error = nvs_open(PM_CONFIG_NAMESPACE, NVS_READWRITE, &handle);
    if (error != ESP_OK) {
        finish_mutation();
        return error;
    }
    uint8_t active = 0U;
    error = nvs_get_u8(handle, PM_CONFIG_ACTIVE, &active);
    if (error == ESP_OK && active != (uint8_t)'A' && active != (uint8_t)'B') {
        error = ESP_ERR_INVALID_STATE;
    }
    if (error == ESP_OK) {
        error = nvs_erase_key(handle, active == (uint8_t)'A' ? PM_CONFIG_SLOT_B : PM_CONFIG_SLOT_A);
        if (error == ESP_ERR_NVS_NOT_FOUND) {
            error = ESP_OK;
        }
    }
    if (error == ESP_OK) {
        error = nvs_commit(handle);
    }
    nvs_close(handle);
    finish_mutation();
    return error;
}

void pm_config_abort(pm_config_transaction_t *transaction)
{
    if (transaction != NULL) {
        release_transaction(transaction->transaction_id);
        secure_zero(transaction, sizeof(*transaction));
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
