#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

#define PM_PROTOCOL_ID "pm-protocol/1.0.0"
#define PM_HMAC_SCHEME "PM-HMAC-SHA256-V1"
#define PM_SHA256_SIZE 32U
#define PM_NONCE_SIZE 16U
#define PM_NONCE_HEX_SIZE 32U
#define PM_SHA256_HEX_SIZE 64U
#define PM_SIGNATURE_BASE64_SIZE 44U
#define PM_RESPONSE_NONCE_MAX 128U
#define PM_CANONICAL_MAX 1024U
#define PM_CANONICAL_QUERY_MAX 384U
#define PM_NONCE_CACHE_SIZE 32U

typedef struct {
    char protocol[sizeof(PM_PROTOCOL_ID)];
    char device_id[37];
    char timestamp[24];
    char nonce[PM_NONCE_HEX_SIZE + 1U];
    char content_sha256[PM_SHA256_HEX_SIZE + 1U];
    char signature[PM_SIGNATURE_BASE64_SIZE + 1U];
} pm_auth_headers_t;

typedef struct {
    uint8_t values[PM_NONCE_CACHE_SIZE][PM_SHA256_SIZE];
    size_t count;
    size_t next;
} pm_nonce_cache_t;

typedef struct {
    char protocol[sizeof(PM_PROTOCOL_ID)];
    char device_id[37];
    char timestamp[24];
    char nonce[PM_RESPONSE_NONCE_MAX + 1U];
    char content_sha256[PM_SHA256_HEX_SIZE + 1U];
    char signature[PM_SIGNATURE_BASE64_SIZE + 1U];
} pm_response_auth_headers_t;

typedef enum {
    PM_TIME_UNTRUSTED = 0,
    PM_TIME_PERSISTED_CHECKPOINT,
    PM_TIME_SNTP,
    PM_TIME_SERVER_CORROBORATED,
} pm_time_source_t;

typedef struct {
    pm_time_source_t source;
    int64_t utc_checkpoint_ms;
    int64_t monotonic_checkpoint_us;
    int64_t last_returned_utc_ms;
    int64_t maximum_backward_step_ms;
    bool trusted;
} pm_time_state_t;

void pm_sha256(const uint8_t *data, size_t length, uint8_t digest[PM_SHA256_SIZE]);
esp_err_t pm_hmac_sha256(const uint8_t *key, size_t key_length, const uint8_t *data, size_t data_length,
                         uint8_t digest[PM_SHA256_SIZE]);
void pm_hex_lower(const uint8_t *data, size_t length, char *output, size_t output_size);
bool pm_constant_time_equal(const uint8_t *left, const uint8_t *right, size_t length);
esp_err_t pm_canonical_query(const char *query, char *output, size_t output_size);
esp_err_t pm_build_canonical(const char *method, const char *path, const char *query, const char *timestamp,
                             const char *nonce, const char *content_sha256, char *output, size_t output_size);
esp_err_t pm_hkdf_directional_keys(const uint8_t *device_secret, size_t secret_length, const char *device_id,
                                   uint8_t device_to_server[PM_SHA256_SIZE],
                                   uint8_t server_to_device[PM_SHA256_SIZE]);
esp_err_t pm_sign_request(const uint8_t key[PM_SHA256_SIZE], const char *device_id, const char *method,
                          const char *path, const char *query, int64_t utc_ms, const uint8_t nonce[PM_NONCE_SIZE],
                          const uint8_t *body, size_t body_length, pm_auth_headers_t *headers);
bool pm_nonce_accept(pm_nonce_cache_t *cache, const uint8_t nonce[PM_NONCE_SIZE]);
esp_err_t pm_verify_response(const uint8_t key[PM_SHA256_SIZE], const char *expected_device_id,
                             const char *path, const char *query, int64_t now_utc_ms,
                             const pm_response_auth_headers_t *headers, const uint8_t *body,
                             size_t body_length, pm_nonce_cache_t *replay_cache);

void pm_time_init(pm_time_state_t *state, int64_t monotonic_us);
esp_err_t pm_time_load_checkpoint(pm_time_state_t *state, int64_t monotonic_us);
esp_err_t pm_time_observe(pm_time_state_t *state, pm_time_source_t source, int64_t utc_ms, int64_t monotonic_us);
bool pm_time_now(pm_time_state_t *state, int64_t monotonic_us, int64_t *utc_ms);

#ifdef __cplusplus
}
#endif
