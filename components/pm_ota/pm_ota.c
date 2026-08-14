#include "pm_ota.h"

#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include "esp_app_desc.h"
#include "esp_http_client.h"
#include "esp_ota_ops.h"
#include "nvs.h"
#include "psa/crypto.h"
#include "pm_board.h"
#include "pm_config.h"
#include "pm_protocol.h"

#define PM_OTA_BUFFER_SIZE 4096U

static uint32_t checkpoint_crc(const pm_ota_checkpoint_t *checkpoint)
{
    return pm_crc32_ieee(checkpoint, offsetof(pm_ota_checkpoint_t, crc32));
}

static bool checkpoint_valid(const pm_ota_checkpoint_t *checkpoint)
{
    return checkpoint->stage <= PM_OTA_FAILED && checkpoint->bytes_written <= checkpoint->image_size &&
           checkpoint->crc32 == checkpoint_crc(checkpoint);
}

static esp_err_t persist_checkpoint(pm_ota_checkpoint_t *checkpoint)
{
    checkpoint->generation++;
    checkpoint->crc32 = checkpoint_crc(checkpoint);
    nvs_handle_t handle = 0;
    esp_err_t error = nvs_open("pm_ota", NVS_READWRITE, &handle);
    if (error == ESP_OK) {
        error = nvs_set_blob(handle, (checkpoint->generation & 1U) != 0U ? "slot_a" : "slot_b", checkpoint,
                             sizeof(*checkpoint));
    }
    if (error == ESP_OK) {
        error = nvs_commit(handle);
    }
    if (handle != 0) {
        nvs_close(handle);
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
    size_t length = sizeof(a);
    const bool valid_a = nvs_get_blob(handle, "slot_a", &a, &length) == ESP_OK && length == sizeof(a) &&
                         checkpoint_valid(&a);
    length = sizeof(b);
    const bool valid_b = nvs_get_blob(handle, "slot_b", &b, &length) == ESP_OK && length == sizeof(b) &&
                         checkpoint_valid(&b);
    nvs_close(handle);
    if (!valid_a && !valid_b) {
        *checkpoint = (pm_ota_checkpoint_t){.stage = PM_OTA_IDLE};
        return persist_checkpoint(checkpoint);
    }
    *checkpoint = valid_a && (!valid_b || a.generation >= b.generation) ? a : b;
    return ESP_OK;
}

esp_err_t pm_ota_manifest_canonical(const pm_ota_manifest_t *manifest, char *output, size_t output_size)
{
    if (manifest == NULL || output == NULL || manifest->version[0] == '\0' || manifest->project_name[0] == '\0' ||
        manifest->target_chip[0] == '\0' || manifest->board_profile[0] == '\0' || manifest->download_url[0] == '\0' ||
        manifest->image_size == 0U) {
        return ESP_ERR_INVALID_ARG;
    }
    char digest[65];
    char nonce[33];
    pm_hex_lower(manifest->image_sha256, sizeof(manifest->image_sha256), digest, sizeof(digest));
    pm_hex_lower(manifest->manifest_nonce, sizeof(manifest->manifest_nonce), nonce, sizeof(nonce));
    const int written = snprintf(output, output_size,
                                 "PM-OTA-MANIFEST-V1\n%s\n%lu\n%s\n%s\n%s\n%lu\n%lu\n%s\n%lu\n%s\n%s\n%s",
                                 manifest->version, (unsigned long)manifest->build_number, manifest->project_name,
                                 manifest->target_chip, manifest->board_profile,
                                 (unsigned long)manifest->minimum_boot_version,
                                 (unsigned long)manifest->minimum_config_version, manifest->minimum_protocol,
                                 (unsigned long)manifest->image_size, digest, manifest->download_url, nonce);
    return written >= 0 && (size_t)written < output_size ? ESP_OK : ESP_ERR_INVALID_SIZE;
}

esp_err_t pm_ota_verify_manifest(const pm_ota_manifest_t *manifest, const uint8_t server_to_device_key[32])
{
    if (manifest == NULL || server_to_device_key == NULL || strcmp(manifest->project_name, "power-monitor-sensor-headless") != 0 ||
        strcmp(manifest->target_chip, "esp32s3") != 0 || strcmp(manifest->board_profile, PM_BOARD_PROFILE) != 0 ||
        strcmp(manifest->minimum_protocol, PM_PROTOCOL_ID) != 0 || manifest->minimum_config_version > PM_CONFIG_SCHEMA_VERSION ||
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

esp_err_t pm_ota_install(const pm_ota_manifest_t *manifest, const char *ca_pem,
                         const uint8_t server_to_device_key[32], pm_ota_progress_fn progress, void *context)
{
    esp_err_t error = pm_ota_verify_manifest(manifest, server_to_device_key);
    if (error != ESP_OK || ca_pem == NULL || ca_pem[0] == '\0') {
        return error == ESP_OK ? ESP_ERR_INVALID_ARG : error;
    }
    pm_ota_checkpoint_t checkpoint = {
        .stage = PM_OTA_MANIFEST_VERIFIED,
        .image_size = manifest->image_size,
    };
    memcpy(checkpoint.image_sha256, manifest->image_sha256, sizeof(checkpoint.image_sha256));
    (void)persist_checkpoint(&checkpoint);
    report(progress, context, 0U, checkpoint.stage);

    const esp_partition_t *partition = esp_ota_get_next_update_partition(NULL);
    if (partition == NULL || manifest->image_size > partition->size) {
        return ESP_ERR_INVALID_SIZE;
    }
    esp_ota_handle_t ota = 0;
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
    error = esp_http_client_open(client, 0);
    if (error != ESP_OK || esp_http_client_fetch_headers(client) != (int64_t)manifest->image_size ||
        esp_http_client_get_status_code(client) != 200) {
        error = error == ESP_OK ? ESP_ERR_INVALID_RESPONSE : error;
        goto cleanup;
    }
    psa_hash_operation_t sha = PSA_HASH_OPERATION_INIT;
    if (psa_hash_setup(&sha, PSA_ALG_SHA_256) != PSA_SUCCESS) {
        error = ESP_FAIL;
        goto cleanup_sha;
    }
    checkpoint.stage = PM_OTA_DOWNLOADING;
    (void)persist_checkpoint(&checkpoint);
    uint8_t buffer[PM_OTA_BUFFER_SIZE];
    while (checkpoint.bytes_written < manifest->image_size) {
        const int received = esp_http_client_read(client, (char *)buffer, sizeof(buffer));
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
            (void)persist_checkpoint(&checkpoint);
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
    (void)persist_checkpoint(&checkpoint);
    report(progress, context, 95U, checkpoint.stage);
    error = esp_ota_set_boot_partition(partition);
    if (error == ESP_OK) {
        checkpoint.stage = PM_OTA_BOOT_SELECTED;
        (void)persist_checkpoint(&checkpoint);
        report(progress, context, 100U, checkpoint.stage);
    }
    goto cleanup;

cleanup_sha:
    (void)psa_hash_abort(&sha);
cleanup:
    esp_http_client_close(client);
    esp_http_client_cleanup(client);
    if (ota != 0) {
        (void)esp_ota_abort(ota);
    }
    if (error != ESP_OK) {
        checkpoint.stage = PM_OTA_FAILED;
        checkpoint.last_error = error;
        (void)persist_checkpoint(&checkpoint);
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
        error = esp_ota_mark_app_valid_cancel_rollback();
        if (error == ESP_OK) {
            pm_ota_checkpoint_t checkpoint;
            if (pm_ota_load_checkpoint(&checkpoint) == ESP_OK) {
                checkpoint.stage = PM_OTA_VALID;
                checkpoint.last_error = ESP_OK;
                (void)persist_checkpoint(&checkpoint);
            }
        }
    } else {
        pm_ota_checkpoint_t checkpoint;
        if (pm_ota_load_checkpoint(&checkpoint) == ESP_OK) {
            checkpoint.stage = PM_OTA_ROLLED_BACK;
            checkpoint.last_error = ESP_ERR_INVALID_STATE;
            (void)persist_checkpoint(&checkpoint);
        }
        error = esp_ota_mark_app_invalid_rollback_and_reboot();
    }
    return error;
}
