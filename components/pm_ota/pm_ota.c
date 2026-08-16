#include "pm_ota.h"

#include <ctype.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cJSON.h"
#include "esp_app_desc.h"
#include "esp_heap_caps.h"
#include "esp_http_client.h"
#include "esp_ota_ops.h"
#include "esp_random.h"
#include "esp_timer.h"
#include "mbedtls/base64.h"
#include "nvs.h"
#include "psa/crypto.h"
#include "pm_board.h"
#include "pm_config.h"
#include "pm_protocol.h"

#define PM_OTA_BUFFER_SIZE 4096U

static void secure_zero_memory(void *value, size_t length)
{
    volatile uint8_t *bytes = (volatile uint8_t *)value;
    while (length-- > 0U) {
        *bytes++ = 0U;
    }
}

static uint8_t *allocate_download_buffer(void)
{
    uint8_t *buffer = (uint8_t *)heap_caps_malloc(
        PM_OTA_BUFFER_SIZE, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if (buffer == NULL) {
        buffer = (uint8_t *)heap_caps_malloc(
            PM_OTA_BUFFER_SIZE, MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
    }
    return buffer;
}

static bool uuid_valid(const char *value)
{
    if (value == NULL || strlen(value) != PM_OTA_UUID_MAX) {
        return false;
    }
    for (size_t i = 0U; i < PM_OTA_UUID_MAX; ++i) {
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

static bool string_copy(const cJSON *object, const char *name, char *output, size_t capacity)
{
    const cJSON *item = cJSON_GetObjectItemCaseSensitive(object, name);
    if (!cJSON_IsString(item) || item->valuestring == NULL || item->valuestring[0] == '\0' ||
        strlen(item->valuestring) >= capacity || strchr(item->valuestring, '\n') != NULL ||
        strchr(item->valuestring, '\r') != NULL) {
        return false;
    }
    (void)snprintf(output, capacity, "%s", item->valuestring);
    return true;
}

static bool u32_value(const cJSON *object, const char *name, uint32_t minimum, uint32_t *output)
{
    const cJSON *item = cJSON_GetObjectItemCaseSensitive(object, name);
    if (!cJSON_IsNumber(item) || item->valuedouble < (double)minimum ||
        item->valuedouble > (double)UINT32_MAX) {
        return false;
    }
    const uint32_t value = (uint32_t)item->valuedouble;
    if ((double)value != item->valuedouble) {
        return false;
    }
    *output = value;
    return true;
}

static bool hex_decode(const char *input, uint8_t *output, size_t length)
{
    if (input == NULL || output == NULL || strlen(input) != length * 2U) {
        return false;
    }
    for (size_t i = 0U; i < length; ++i) {
        const char high = input[i * 2U];
        const char low = input[i * 2U + 1U];
        const int high_value = high >= '0' && high <= '9' ? high - '0' :
                               high >= 'a' && high <= 'f' ? high - 'a' + 10 : -1;
        const int low_value = low >= '0' && low <= '9' ? low - '0' :
                              low >= 'a' && low <= 'f' ? low - 'a' + 10 : -1;
        if (high_value < 0 || low_value < 0) {
            return false;
        }
        output[i] = (uint8_t)((high_value << 4) | low_value);
    }
    return true;
}

esp_err_t pm_ota_manifest_parse_payload(const char *payload, const char *server_origin,
                                        const char *expected_device_id, pm_ota_manifest_t *manifest)
{
    if (payload == NULL || server_origin == NULL || expected_device_id == NULL || manifest == NULL ||
        !uuid_valid(expected_device_id) || strncmp(server_origin, "https://", 8U) != 0 ||
        strchr(server_origin, '?') != NULL || strchr(server_origin, '#') != NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    cJSON *root = cJSON_ParseWithLength(payload, strlen(payload));
    if (!cJSON_IsObject(root) || cJSON_GetArraySize(root) != 17) {
        cJSON_Delete(root);
        return ESP_ERR_INVALID_ARG;
    }
    pm_ota_manifest_t candidate = {0};
    char digest_hex[65] = {0};
    char nonce_hex[33] = {0};
    char signature_base64[45] = {0};
    bool valid = string_copy(root, "schema", candidate.schema, sizeof(candidate.schema)) &&
                 string_copy(root, "device_id", candidate.device_id, sizeof(candidate.device_id)) &&
                 string_copy(root, "deployment_id", candidate.deployment_id, sizeof(candidate.deployment_id)) &&
                 string_copy(root, "release_id", candidate.release_id, sizeof(candidate.release_id)) &&
                 string_copy(root, "semantic_version", candidate.version, sizeof(candidate.version)) &&
                 u32_value(root, "build_number", 1U, &candidate.build_number) &&
                 string_copy(root, "project_name", candidate.project_name, sizeof(candidate.project_name)) &&
                 string_copy(root, "target_chip", candidate.target_chip, sizeof(candidate.target_chip)) &&
                 string_copy(root, "board_profile", candidate.board_profile, sizeof(candidate.board_profile)) &&
                 u32_value(root, "minimum_boot_version", 1U, &candidate.minimum_boot_version) &&
                 u32_value(root, "minimum_config_version", 1U, &candidate.minimum_config_version) &&
                 string_copy(root, "minimum_protocol", candidate.minimum_protocol,
                             sizeof(candidate.minimum_protocol)) &&
                 u32_value(root, "image_size", 1U, &candidate.image_size) &&
                 string_copy(root, "sha256", digest_hex, sizeof(digest_hex)) &&
                 string_copy(root, "download_path", candidate.download_path, sizeof(candidate.download_path)) &&
                 string_copy(root, "manifest_nonce", nonce_hex, sizeof(nonce_hex)) &&
                 string_copy(root, "signature", signature_base64, sizeof(signature_base64));
    char expected_path[PM_OTA_DOWNLOAD_PATH_MAX + 1U];
    const int path_length = snprintf(expected_path, sizeof(expected_path),
                                     "/api/v1/device/firmware/%s", candidate.release_id);
    valid = valid && strcmp(candidate.schema, PM_OTA_SCHEMA) == 0 &&
            strcmp(candidate.device_id, expected_device_id) == 0 && uuid_valid(candidate.device_id) &&
            uuid_valid(candidate.deployment_id) && uuid_valid(candidate.release_id) &&
            path_length > 0 && (size_t)path_length < sizeof(expected_path) &&
            strcmp(candidate.download_path, expected_path) == 0 &&
            hex_decode(digest_hex, candidate.image_sha256, sizeof(candidate.image_sha256)) &&
            hex_decode(nonce_hex, candidate.manifest_nonce, sizeof(candidate.manifest_nonce));
    size_t signature_length = 0U;
    valid = valid && strlen(signature_base64) == PM_SIGNATURE_BASE64_SIZE &&
            mbedtls_base64_decode(candidate.signature, sizeof(candidate.signature), &signature_length,
                                  (const uint8_t *)signature_base64, strlen(signature_base64)) == 0 &&
            signature_length == sizeof(candidate.signature);
    size_t origin_length = strlen(server_origin);
    while (origin_length > 8U && server_origin[origin_length - 1U] == '/') {
        origin_length--;
    }
    const int url_length = valid ? snprintf(candidate.download_url, sizeof(candidate.download_url), "%.*s%s",
                                            (int)origin_length, server_origin, candidate.download_path) : -1;
    valid = valid && url_length > 0 && (size_t)url_length < sizeof(candidate.download_url);
    cJSON_Delete(root);
    if (!valid) {
        memset(&candidate, 0, sizeof(candidate));
        return ESP_ERR_INVALID_ARG;
    }
    *manifest = candidate;
    return ESP_OK;
}

static uint32_t checkpoint_crc(const pm_ota_checkpoint_t *checkpoint)
{
    return pm_crc32_ieee(checkpoint, offsetof(pm_ota_checkpoint_t, crc32));
}

static bool checkpoint_valid(const pm_ota_checkpoint_t *checkpoint)
{
    return checkpoint->stage <= PM_OTA_FAILED && checkpoint->bytes_written <= checkpoint->image_size &&
           checkpoint->crc32 == checkpoint_crc(checkpoint);
}

static esp_err_t read_checkpoint(nvs_handle_t handle, const char *key,
                                 pm_ota_checkpoint_t *checkpoint)
{
    size_t length = sizeof(*checkpoint);
    const esp_err_t error = nvs_get_blob(handle, key, checkpoint, &length);
    if (error != ESP_OK) {
        return error;
    }
    return length == sizeof(*checkpoint) && checkpoint_valid(checkpoint) ? ESP_OK :
           ESP_ERR_INVALID_CRC;
}

static esp_err_t persist_checkpoint(pm_ota_checkpoint_t *checkpoint)
{
    if (checkpoint == NULL || checkpoint->generation == UINT32_MAX) {
        return ESP_ERR_INVALID_STATE;
    }
    pm_ota_checkpoint_t candidate = *checkpoint;
    candidate.generation++;
    candidate.crc32 = checkpoint_crc(&candidate);
    nvs_handle_t handle = 0;
    esp_err_t error = nvs_open("pm_ota", NVS_READWRITE, &handle);
    if (error == ESP_OK) {
        error = nvs_set_blob(handle, (candidate.generation & 1U) != 0U ? "slot_a" : "slot_b",
                             &candidate, sizeof(candidate));
    }
    if (error == ESP_OK) {
        error = nvs_commit(handle);
    }
    pm_ota_checkpoint_t verified = {0};
    if (error == ESP_OK) {
        error = read_checkpoint(handle, (candidate.generation & 1U) != 0U ? "slot_a" : "slot_b",
                                &verified);
    }
    if (error == ESP_OK && memcmp(&verified, &candidate, sizeof(candidate)) != 0) {
        error = ESP_ERR_INVALID_STATE;
    }
    if (handle != 0) {
        nvs_close(handle);
    }
    if (error == ESP_OK) {
        *checkpoint = candidate;
    }
    return error;
}

esp_err_t pm_ota_load_checkpoint(pm_ota_checkpoint_t *checkpoint)
{
    if (checkpoint == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    nvs_handle_t handle = 0;
    esp_err_t error = nvs_open("pm_ota", NVS_READWRITE, &handle);
    if (error != ESP_OK) {
        return error;
    }
    pm_ota_checkpoint_t a = {0};
    pm_ota_checkpoint_t b = {0};
    const esp_err_t error_a = read_checkpoint(handle, "slot_a", &a);
    const esp_err_t error_b = read_checkpoint(handle, "slot_b", &b);
    const bool valid_a = error_a == ESP_OK;
    const bool valid_b = error_b == ESP_OK;
    nvs_close(handle);
    if (!valid_a && !valid_b) {
        if (error_a != ESP_ERR_NVS_NOT_FOUND || error_b != ESP_ERR_NVS_NOT_FOUND) {
            return error_a != ESP_ERR_NVS_NOT_FOUND ? error_a : error_b;
        }
        *checkpoint = (pm_ota_checkpoint_t){.stage = PM_OTA_IDLE};
        return persist_checkpoint(checkpoint);
    }
    if ((!valid_a && error_a != ESP_ERR_NVS_NOT_FOUND) ||
        (!valid_b && error_b != ESP_ERR_NVS_NOT_FOUND)) {
        return !valid_a && error_a != ESP_ERR_NVS_NOT_FOUND ? error_a : error_b;
    }
    if (valid_a && valid_b && a.generation == b.generation && memcmp(&a, &b, sizeof(a)) != 0) {
        return ESP_ERR_INVALID_STATE;
    }
    *checkpoint = valid_a && (!valid_b || a.generation >= b.generation) ? a : b;
    return ESP_OK;
}

esp_err_t pm_ota_manifest_canonical(const pm_ota_manifest_t *manifest, char *output, size_t output_size)
{
    if (manifest == NULL || output == NULL || manifest->schema[0] == '\0' || manifest->device_id[0] == '\0' ||
        manifest->deployment_id[0] == '\0' || manifest->release_id[0] == '\0' || manifest->version[0] == '\0' ||
        manifest->project_name[0] == '\0' || manifest->target_chip[0] == '\0' ||
        manifest->board_profile[0] == '\0' || manifest->download_path[0] == '\0' || manifest->image_size == 0U) {
        return ESP_ERR_INVALID_ARG;
    }
    char digest[65];
    char nonce[33];
    pm_hex_lower(manifest->image_sha256, sizeof(manifest->image_sha256), digest, sizeof(digest));
    pm_hex_lower(manifest->manifest_nonce, sizeof(manifest->manifest_nonce), nonce, sizeof(nonce));
    const int written = snprintf(output, output_size,
                                 "PM-OTA-MANIFEST-V1\n%s\n%s\n%s\n%s\n%s\n%lu\n%s\n%s\n%s\n%lu\n%lu\n%s\n%lu\n%s\n%s\n%s",
                                 manifest->schema, manifest->device_id, manifest->deployment_id,
                                 manifest->release_id, manifest->version, (unsigned long)manifest->build_number,
                                 manifest->project_name, manifest->target_chip, manifest->board_profile,
                                 (unsigned long)manifest->minimum_boot_version,
                                 (unsigned long)manifest->minimum_config_version, manifest->minimum_protocol,
                                 (unsigned long)manifest->image_size, digest, manifest->download_path, nonce);
    return written >= 0 && (size_t)written < output_size ? ESP_OK : ESP_ERR_INVALID_SIZE;
}

esp_err_t pm_ota_verify_manifest(const pm_ota_manifest_t *manifest, const uint8_t server_to_device_key[32])
{
    if (manifest == NULL || server_to_device_key == NULL || strcmp(manifest->schema, PM_OTA_SCHEMA) != 0 ||
        !uuid_valid(manifest->device_id) || !uuid_valid(manifest->deployment_id) || !uuid_valid(manifest->release_id) ||
        strcmp(manifest->project_name, "power-monitor-sensor-headless") != 0 ||
        strcmp(manifest->target_chip, "esp32s3") != 0 || strcmp(manifest->board_profile, PM_BOARD_PROFILE) != 0 ||
        strcmp(manifest->minimum_protocol, PM_PROTOCOL_ID) != 0 || manifest->minimum_boot_version == 0U ||
        manifest->minimum_boot_version > PM_BOOT_ABI_VERSION || manifest->minimum_config_version == 0U ||
        manifest->minimum_config_version > PM_CONFIG_SCHEMA_VERSION ||
        strncmp(manifest->download_url, "https://", 8U) != 0) {
        return ESP_ERR_NOT_SUPPORTED;
    }
    char canonical[1024];
    esp_err_t error = pm_ota_manifest_canonical(manifest, canonical, sizeof(canonical));
    if (error != ESP_OK) {
        return error;
    }
    uint8_t expected[32];
    if (pm_hmac_sha256(server_to_device_key, 32U, (const uint8_t *)canonical,
                       strlen(canonical), expected) != ESP_OK) {
        return ESP_FAIL;
    }
    return pm_constant_time_equal(expected, manifest->signature, sizeof(expected)) ? ESP_OK : ESP_ERR_INVALID_CRC;
}

static void report(pm_ota_progress_fn callback, void *context, uint8_t percent, pm_ota_stage_t stage)
{
    if (callback != NULL) {
        callback(percent, stage, context);
    }
}

static esp_err_t copy_http_header(esp_http_client_handle_t client, const char *name,
                                  char *destination, size_t capacity)
{
    char *value = NULL;
    if (esp_http_client_get_header(client, name, &value) != ESP_OK || value == NULL ||
        value[0] == '\0' || strlen(value) >= capacity) {
        return ESP_ERR_INVALID_RESPONSE;
    }
    memcpy(destination, value, strlen(value) + 1U);
    return ESP_OK;
}

esp_err_t pm_ota_install(const pm_ota_manifest_t *manifest, const char *ca_pem,
                         const uint8_t device_to_server_key[32], const uint8_t server_to_device_key[32],
                         int64_t request_utc_ms, pm_ota_progress_fn progress, void *context)
{
    uint8_t *buffer = NULL;
    esp_err_t error = pm_ota_verify_manifest(manifest, server_to_device_key);
    if (error != ESP_OK || ca_pem == NULL || ca_pem[0] == '\0' || device_to_server_key == NULL ||
        request_utc_ms < INT64_C(1704067200000)) {
        return error == ESP_OK ? ESP_ERR_INVALID_ARG : error;
    }
    uint8_t request_nonce[PM_NONCE_SIZE];
    esp_fill_random(request_nonce, sizeof(request_nonce));
    pm_auth_headers_t request_auth;
    error = pm_sign_request(device_to_server_key, manifest->device_id, "GET", manifest->download_path, NULL,
                            request_utc_ms, request_nonce, NULL, 0U, &request_auth);
    if (error != ESP_OK) {
        return error;
    }
    pm_ota_checkpoint_t checkpoint = {
        .stage = PM_OTA_MANIFEST_VERIFIED,
        .image_size = manifest->image_size,
    };
    memcpy(checkpoint.image_sha256, manifest->image_sha256, sizeof(checkpoint.image_sha256));
    error = persist_checkpoint(&checkpoint);
    if (error != ESP_OK) {
        return error;
    }
    report(progress, context, 0U, checkpoint.stage);

    const esp_partition_t *partition = esp_ota_get_next_update_partition(NULL);
    if (partition == NULL || manifest->image_size > partition->size) {
        return ESP_ERR_INVALID_SIZE;
    }
    esp_ota_handle_t ota = 0;
    /* Resume bytes are never trusted after interruption. esp_ota_begin erases
     * the target range and every retry restarts from byte zero. */
    error = esp_ota_begin(partition, manifest->image_size, &ota);
    if (error != ESP_OK) {
        return error;
    }
    const esp_http_client_config_t http_config = {
        .url = manifest->download_url,
        .cert_pem = ca_pem,
        .timeout_ms = 15000,
        .buffer_size = PM_OTA_BUFFER_SIZE,
        .buffer_size_tx = 1024,
        .keep_alive_enable = true,
        .disable_auto_redirect = true,
    };
    esp_http_client_handle_t client = esp_http_client_init(&http_config);
    if (client == NULL) {
        (void)esp_ota_abort(ota);
        return ESP_ERR_NO_MEM;
    }
    error = esp_http_client_set_method(client, HTTP_METHOD_GET);
    if (error == ESP_OK) {
        error = esp_http_client_set_header(client, "Accept", "application/octet-stream");
    }
    if (error == ESP_OK) {
        error = esp_http_client_set_header(client, "X-PM-Protocol", request_auth.protocol);
    }
    if (error == ESP_OK) {
        error = esp_http_client_set_header(client, "X-PM-Device-ID", request_auth.device_id);
    }
    if (error == ESP_OK) {
        error = esp_http_client_set_header(client, "X-PM-Timestamp", request_auth.timestamp);
    }
    if (error == ESP_OK) {
        error = esp_http_client_set_header(client, "X-PM-Nonce", request_auth.nonce);
    }
    if (error == ESP_OK) {
        error = esp_http_client_set_header(client, "X-PM-Content-SHA256", request_auth.content_sha256);
    }
    if (error == ESP_OK) {
        error = esp_http_client_set_header(client, "X-PM-Signature", request_auth.signature);
    }
    if (error != ESP_OK) {
        goto cleanup;
    }
    const int64_t request_started_us = esp_timer_get_time();
    error = esp_http_client_open(client, 0);
    const int64_t content_length = error == ESP_OK ? esp_http_client_fetch_headers(client) : -1;
    if (error != ESP_OK || content_length != (int64_t)manifest->image_size ||
        esp_http_client_get_status_code(client) != 200) {
        error = error == ESP_OK ? ESP_ERR_INVALID_RESPONSE : error;
        goto cleanup;
    }
    pm_response_auth_headers_t response_auth = {0};
    error = copy_http_header(client, "X-PM-Protocol", response_auth.protocol, sizeof(response_auth.protocol));
    if (error == ESP_OK) {
        error = copy_http_header(client, "X-PM-Device-ID", response_auth.device_id,
                                 sizeof(response_auth.device_id));
    }
    if (error == ESP_OK) {
        error = copy_http_header(client, "X-PM-Timestamp", response_auth.timestamp,
                                 sizeof(response_auth.timestamp));
    }
    if (error == ESP_OK) {
        error = copy_http_header(client, "X-PM-Nonce", response_auth.nonce, sizeof(response_auth.nonce));
    }
    if (error == ESP_OK) {
        error = copy_http_header(client, "X-PM-Content-SHA256", response_auth.content_sha256,
                                 sizeof(response_auth.content_sha256));
    }
    if (error == ESP_OK) {
        error = copy_http_header(client, "X-PM-Signature", response_auth.signature,
                                 sizeof(response_auth.signature));
    }
    char etag[68] = {0};
    char expected_etag[68] = {0};
    char manifest_digest_hex[65];
    pm_hex_lower(manifest->image_sha256, sizeof(manifest->image_sha256),
                 manifest_digest_hex, sizeof(manifest_digest_hex));
    (void)snprintf(expected_etag, sizeof(expected_etag), "\"%s\"", manifest_digest_hex);
    if (error == ESP_OK) {
        error = copy_http_header(client, "ETag", etag, sizeof(etag));
    }
    if (error != ESP_OK || strcmp(etag, expected_etag) != 0) {
        error = ESP_ERR_INVALID_RESPONSE;
        goto cleanup;
    }
    buffer = allocate_download_buffer();
    if (buffer == NULL) {
        error = ESP_ERR_NO_MEM;
        goto cleanup;
    }
    psa_hash_operation_t sha = PSA_HASH_OPERATION_INIT;
    if (psa_hash_setup(&sha, PSA_ALG_SHA_256) != PSA_SUCCESS) {
        error = ESP_FAIL;
        goto cleanup_sha;
    }
    checkpoint.stage = PM_OTA_DOWNLOADING;
    error = persist_checkpoint(&checkpoint);
    if (error != ESP_OK) {
        goto cleanup_sha;
    }
    while (checkpoint.bytes_written < manifest->image_size) {
        const int received = esp_http_client_read(client, (char *)buffer, PM_OTA_BUFFER_SIZE);
        if (received <= 0 || checkpoint.bytes_written + (uint32_t)received > manifest->image_size) {
            error = received == 0 ? ESP_ERR_INVALID_SIZE : ESP_ERR_HTTP_INCOMPLETE_DATA;
            goto cleanup_sha;
        }
        if (psa_hash_update(&sha, buffer, (size_t)received) != PSA_SUCCESS ||
            esp_ota_write(ota, buffer, (size_t)received) != ESP_OK) {
            error = ESP_FAIL;
            goto cleanup_sha;
        }
        checkpoint.bytes_written += (uint32_t)received;
        const uint8_t percent = (uint8_t)((uint64_t)checkpoint.bytes_written * 90U / manifest->image_size);
        report(progress, context, percent, PM_OTA_DOWNLOADING);
        if ((checkpoint.bytes_written & UINT32_C(0xFFFF)) < (uint32_t)received) {
            error = persist_checkpoint(&checkpoint);
            if (error != ESP_OK) {
                goto cleanup_sha;
            }
        }
    }
    uint8_t digest[32];
    size_t digest_length = 0U;
    if (psa_hash_finish(&sha, digest, sizeof(digest), &digest_length) != PSA_SUCCESS ||
        digest_length != sizeof(digest) ||
        !pm_constant_time_equal(digest, manifest->image_sha256, sizeof(digest))) {
        error = ESP_ERR_INVALID_CRC;
        goto cleanup_sha;
    }
    (void)psa_hash_abort(&sha);
    if (!esp_http_client_is_complete_data_received(client)) {
        error = ESP_ERR_HTTP_INCOMPLETE_DATA;
        goto cleanup;
    }
    char downloaded_digest_hex[PM_SHA256_HEX_SIZE + 1U];
    pm_hex_lower(digest, sizeof(digest), downloaded_digest_hex, sizeof(downloaded_digest_hex));
    pm_nonce_cache_t response_nonce_cache = {0};
    const int64_t response_now_utc_ms = request_utc_ms +
        (esp_timer_get_time() - request_started_us) / INT64_C(1000);
    error = pm_verify_response_digest(server_to_device_key, manifest->device_id,
                                      manifest->download_path, NULL, response_now_utc_ms,
                                      &response_auth, downloaded_digest_hex, &response_nonce_cache);
    if (error != ESP_OK) {
        goto cleanup;
    }
    error = esp_ota_end(ota);
    ota = 0;
    if (error != ESP_OK) {
        goto cleanup;
    }
    esp_app_desc_t app = {0};
    error = esp_ota_get_partition_description(partition, &app);
    if (error != ESP_OK || strcmp(app.project_name, manifest->project_name) != 0 ||
        strcmp(app.version, manifest->version) != 0) {
        error = ESP_ERR_NOT_SUPPORTED;
        goto cleanup;
    }
    checkpoint.stage = PM_OTA_IMAGE_VERIFIED;
    error = persist_checkpoint(&checkpoint);
    if (error != ESP_OK) {
        goto cleanup;
    }
    report(progress, context, 95U, checkpoint.stage);
    error = esp_ota_set_boot_partition(partition);
    if (error == ESP_OK) {
        checkpoint.stage = PM_OTA_BOOT_SELECTED;
        error = persist_checkpoint(&checkpoint);
        if (error == ESP_OK) {
            report(progress, context, 100U, checkpoint.stage);
        } else {
            const esp_partition_t *running = esp_ota_get_running_partition();
            if (running != NULL) {
                (void)esp_ota_set_boot_partition(running);
            }
        }
    }
    goto cleanup;

cleanup_sha:
    (void)psa_hash_abort(&sha);
cleanup:
    if (buffer != NULL) {
        secure_zero_memory(buffer, PM_OTA_BUFFER_SIZE);
        heap_caps_free(buffer);
    }
    esp_http_client_close(client);
    esp_http_client_cleanup(client);
    if (ota != 0) {
        (void)esp_ota_abort(ota);
    }
    if (error != ESP_OK) {
        checkpoint.stage = PM_OTA_FAILED;
        checkpoint.last_error = error;
        const esp_err_t checkpoint_error = persist_checkpoint(&checkpoint);
        if (checkpoint_error != ESP_OK) {
            error = checkpoint_error;
        }
        report(progress, context, 0U, checkpoint.stage);
    }
    return error;
}

esp_err_t pm_ota_post_boot_validate(bool config_readable, bool scheduler_running, bool watchdog_running,
                                    bool storage_initialized_or_degraded, bool network_retry_capable)
{
    const esp_partition_t *running = esp_ota_get_running_partition();
    esp_ota_img_states_t state = ESP_OTA_IMG_UNDEFINED;
    esp_err_t error = esp_ota_get_state_partition(running, &state);
    if (error == ESP_ERR_NOT_FOUND || state != ESP_OTA_IMG_PENDING_VERIFY) {
        return ESP_OK;
    }
    if (config_readable && scheduler_running && watchdog_running && storage_initialized_or_degraded &&
        network_retry_capable) {
        pm_ota_checkpoint_t checkpoint = {0};
        error = pm_ota_load_checkpoint(&checkpoint);
        if (error != ESP_OK) {
            return error;
        }
        checkpoint.stage = PM_OTA_VALID;
        checkpoint.last_error = ESP_OK;
        error = persist_checkpoint(&checkpoint);
        if (error != ESP_OK) {
            return error;
        }
        error = esp_ota_mark_app_valid_cancel_rollback();
    } else {
        pm_ota_checkpoint_t checkpoint = {0};
        error = pm_ota_load_checkpoint(&checkpoint);
        if (error != ESP_OK) {
            return error;
        }
        checkpoint.stage = PM_OTA_ROLLED_BACK;
        checkpoint.last_error = ESP_ERR_INVALID_STATE;
        error = persist_checkpoint(&checkpoint);
        if (error != ESP_OK) {
            return error;
        }
        error = esp_ota_mark_app_invalid_rollback_and_reboot();
    }
    return error;
}

esp_err_t pm_ota_cancel_pending_boot(esp_err_t reason)
{
    const esp_partition_t *running = esp_ota_get_running_partition();
    if (running == NULL) {
        return ESP_ERR_NOT_FOUND;
    }
    esp_err_t error = esp_ota_set_boot_partition(running);
    if (error != ESP_OK) {
        return error;
    }
    pm_ota_checkpoint_t checkpoint = {0};
    error = pm_ota_load_checkpoint(&checkpoint);
    if (error == ESP_OK) {
        checkpoint.stage = PM_OTA_FAILED;
        checkpoint.last_error = reason == ESP_OK ? ESP_ERR_INVALID_STATE : reason;
        error = persist_checkpoint(&checkpoint);
    }
    return error;
}
