#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

#define PM_OTA_VERSION_MAX 31U
#define PM_OTA_PROJECT_MAX 47U
#define PM_OTA_TARGET_MAX 15U
#define PM_OTA_BOARD_MAX 63U
#define PM_OTA_URL_MAX 255U
#define PM_OTA_PROTOCOL_MAX 31U
#define PM_OTA_UUID_MAX 36U
#define PM_OTA_DOWNLOAD_PATH_MAX 95U
#define PM_OTA_SCHEMA "pm-ota-manifest/1.0.0"
#define PM_BOOT_ABI_VERSION 1U

typedef struct {
    char schema[sizeof(PM_OTA_SCHEMA)];
    char device_id[PM_OTA_UUID_MAX + 1U];
    char deployment_id[PM_OTA_UUID_MAX + 1U];
    char release_id[PM_OTA_UUID_MAX + 1U];
    char version[PM_OTA_VERSION_MAX + 1U];
    uint32_t build_number;
    char project_name[PM_OTA_PROJECT_MAX + 1U];
    char target_chip[PM_OTA_TARGET_MAX + 1U];
    char board_profile[PM_OTA_BOARD_MAX + 1U];
    uint32_t minimum_boot_version;
    uint32_t minimum_config_version;
    char minimum_protocol[PM_OTA_PROTOCOL_MAX + 1U];
    uint32_t image_size;
    uint8_t image_sha256[32];
    char download_path[PM_OTA_DOWNLOAD_PATH_MAX + 1U];
    char download_url[PM_OTA_URL_MAX + 1U];
    uint8_t manifest_nonce[16];
    uint8_t signature[32];
} pm_ota_manifest_t;

typedef enum {
    PM_OTA_IDLE = 0,
    PM_OTA_MANIFEST_VERIFIED,
    PM_OTA_DOWNLOADING,
    PM_OTA_IMAGE_VERIFIED,
    PM_OTA_BOOT_SELECTED,
    PM_OTA_PENDING_VERIFY,
    PM_OTA_VALID,
    PM_OTA_ROLLED_BACK,
    PM_OTA_FAILED,
} pm_ota_stage_t;

typedef struct {
    pm_ota_stage_t stage;
    uint32_t bytes_written;
    uint32_t image_size;
    uint8_t image_sha256[32];
    uint32_t generation;
    int32_t last_error;
    uint32_t crc32;
} pm_ota_checkpoint_t;

typedef void (*pm_ota_progress_fn)(uint8_t percent, pm_ota_stage_t stage, void *context);

esp_err_t pm_ota_manifest_canonical(const pm_ota_manifest_t *manifest, char *output, size_t output_size);
esp_err_t pm_ota_manifest_parse_payload(const char *payload, const char *server_origin,
                                        const char *expected_device_id, pm_ota_manifest_t *manifest);
esp_err_t pm_ota_verify_manifest(const pm_ota_manifest_t *manifest, const uint8_t server_to_device_key[32]);
esp_err_t pm_ota_install(const pm_ota_manifest_t *manifest, const char *ca_pem,
                         const uint8_t device_to_server_key[32], const uint8_t server_to_device_key[32],
                         int64_t request_utc_ms, pm_ota_progress_fn progress, void *context);
esp_err_t pm_ota_load_checkpoint(pm_ota_checkpoint_t *checkpoint);
esp_err_t pm_ota_cancel_pending_boot(esp_err_t reason);
esp_err_t pm_ota_post_boot_validate(bool config_readable, bool scheduler_running, bool watchdog_running,
                                    bool telemetry_runtime_ready, bool network_retry_capable);

#ifdef __cplusplus
}
#endif
