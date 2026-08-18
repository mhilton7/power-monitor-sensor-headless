#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

#define PM_CONFIG_SCHEMA_VERSION 1U
#define PM_CONFIG_NAME_MAX 48U
#define PM_CONFIG_SSID_MAX 32U
#define PM_CONFIG_PASSWORD_MAX 63U
#define PM_CONFIG_ORIGIN_MAX 192U
#define PM_CONFIG_CA_MAX 4096U
#define PM_CONFIG_TIMEZONE_MAX 64U
#define PM_CONFIG_SECRET_MAX 32U
#define PM_CONFIG_DEVICE_ID_LEN 16U
#define PM_CONFIG_CONTENT_HASH_LEN 32U

typedef enum {
    PM_IPV4_DHCP = 0,
    PM_IPV4_STATIC = 1,
} pm_ipv4_mode_t;

typedef enum {
    PM_METER_UNSPECIFIED = 0,
    PM_METER_PZEM004T_V4_CLASSIC = 1,
} pm_meter_variant_t;

typedef struct {
    uint32_t schema_version;
    uint32_t generation;
    uint8_t device_id[PM_CONFIG_DEVICE_ID_LEN];
    char friendly_name[PM_CONFIG_NAME_MAX + 1U];
    char wifi_ssid[PM_CONFIG_SSID_MAX + 1U];
    char wifi_password[PM_CONFIG_PASSWORD_MAX + 1U];
    pm_ipv4_mode_t ipv4_mode;
    uint32_t ipv4_address;
    uint32_t ipv4_gateway;
    uint32_t ipv4_netmask;
    uint32_t dns_primary;
    uint32_t dns_secondary;
    char server_origin[PM_CONFIG_ORIGIN_MAX + 1U];
    char ca_pem[PM_CONFIG_CA_MAX + 1U];
    char timezone[PM_CONFIG_TIMEZONE_MAX + 1U];
    uint16_t ct_rating_a;
    pm_meter_variant_t meter_variant;
    uint8_t device_secret[PM_CONFIG_SECRET_MAX];
    uint8_t device_secret_len;
    /* Legacy schema-v1 ABI words. Retained only so existing configuration
     * blobs keep their size/CRC; the stateless runtime never updates or uses
     * them for telemetry acceptance. */
    uint64_t sequence_floor;
    uint64_t acknowledged_sequence;
    uint32_t reset_generation;
    uint32_t crc32;
} pm_config_t;

typedef enum {
    PM_CONFIG_STAGE_NONE = 0,
    PM_CONFIG_STAGE_VALIDATED,
    PM_CONFIG_STAGE_WRITTEN_INACTIVE,
    PM_CONFIG_STAGE_READBACK_VERIFIED,
    PM_CONFIG_STAGE_NETWORK_TESTED,
    PM_CONFIG_STAGE_COMMITTED,
} pm_config_stage_t;

typedef struct {
    pm_config_stage_t stage;
    uint32_t candidate_generation;
    uint32_t transaction_id;
    char candidate_slot;
    uint8_t candidate_sha256[PM_CONFIG_CONTENT_HASH_LEN];
} pm_config_transaction_t;

uint32_t pm_crc32_ieee(const void *data, size_t length);
esp_err_t pm_config_validate(const pm_config_t *config, bool production_gate);
esp_err_t pm_config_load(pm_config_t *config);
esp_err_t pm_config_begin(const pm_config_t *candidate, pm_config_transaction_t *transaction);
esp_err_t pm_config_mark_network_tested(pm_config_transaction_t *transaction);
esp_err_t pm_config_commit(pm_config_transaction_t *transaction);
esp_err_t pm_config_load_staged(char slot, uint32_t expected_generation, pm_config_t *config);
esp_err_t pm_config_activate_staged(char slot, uint32_t expected_generation);
esp_err_t pm_config_discard_staged(char slot, uint32_t expected_generation);
esp_err_t pm_config_discard_inactive_generation(uint32_t expected_generation);
esp_err_t pm_config_erase_inactive(void);
void pm_config_abort(pm_config_transaction_t *transaction);
bool pm_config_secret_field_name(const char *name);

#ifdef __cplusplus
}
#endif
