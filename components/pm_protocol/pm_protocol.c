#include "pm_protocol.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mbedtls/base64.h"
#include "psa/crypto.h"

void pm_sha256(const uint8_t *data, size_t length, uint8_t digest[PM_SHA256_SIZE])
{
    if (digest != NULL) {
        static const uint8_t empty = 0U;
        size_t digest_length = 0U;
        if (psa_hash_compute(PSA_ALG_SHA_256, data == NULL ? &empty : data, length, digest,
                             PM_SHA256_SIZE, &digest_length) != PSA_SUCCESS ||
            digest_length != PM_SHA256_SIZE) {
            memset(digest, 0, PM_SHA256_SIZE);
        }
    }
}

esp_err_t pm_hmac_sha256(const uint8_t *key, size_t key_length, const uint8_t *data, size_t data_length,
                         uint8_t digest[PM_SHA256_SIZE])
{
    if (key == NULL || digest == NULL || (data == NULL && data_length != 0U)) {
        return ESP_ERR_INVALID_ARG;
    }
    uint8_t key_block[64] = {0};
    if (key_length > sizeof(key_block)) {
        pm_sha256(key, key_length, key_block);
    } else {
        memcpy(key_block, key, key_length);
    }
    uint8_t inner_pad[64];
    uint8_t outer_pad[64];
    for (size_t i = 0U; i < sizeof(key_block); ++i) {
        inner_pad[i] = key_block[i] ^ 0x36U;
        outer_pad[i] = key_block[i] ^ 0x5CU;
    }
    uint8_t inner_digest[PM_SHA256_SIZE];
    size_t written = 0U;
    psa_hash_operation_t operation = PSA_HASH_OPERATION_INIT;
    psa_status_t status = psa_hash_setup(&operation, PSA_ALG_SHA_256);
    if (status == PSA_SUCCESS) {
        status = psa_hash_update(&operation, inner_pad, sizeof(inner_pad));
    }
    if (status == PSA_SUCCESS && data_length != 0U) {
        status = psa_hash_update(&operation, data, data_length);
    }
    if (status == PSA_SUCCESS) {
        status = psa_hash_finish(&operation, inner_digest, sizeof(inner_digest), &written);
    }
    (void)psa_hash_abort(&operation);
    operation = (psa_hash_operation_t)PSA_HASH_OPERATION_INIT;
    if (status == PSA_SUCCESS && written == sizeof(inner_digest)) {
        status = psa_hash_setup(&operation, PSA_ALG_SHA_256);
    }
    if (status == PSA_SUCCESS) {
        status = psa_hash_update(&operation, outer_pad, sizeof(outer_pad));
    }
    if (status == PSA_SUCCESS) {
        status = psa_hash_update(&operation, inner_digest, sizeof(inner_digest));
    }
    if (status == PSA_SUCCESS) {
        status = psa_hash_finish(&operation, digest, PM_SHA256_SIZE, &written);
    }
    (void)psa_hash_abort(&operation);
    memset(key_block, 0, sizeof(key_block));
    memset(inner_pad, 0, sizeof(inner_pad));
    memset(outer_pad, 0, sizeof(outer_pad));
    memset(inner_digest, 0, sizeof(inner_digest));
    if (status != PSA_SUCCESS || written != PM_SHA256_SIZE) {
        memset(digest, 0, PM_SHA256_SIZE);
        return ESP_FAIL;
    }
    return ESP_OK;
}

void pm_hex_lower(const uint8_t *data, size_t length, char *output, size_t output_size)
{
    static const char alphabet[] = "0123456789abcdef";
    if (data == NULL || output == NULL || output_size < length * 2U + 1U) {
        return;
    }
    for (size_t i = 0U; i < length; ++i) {
        output[i * 2U] = alphabet[data[i] >> 4U];
        output[i * 2U + 1U] = alphabet[data[i] & 0x0FU];
    }
    output[length * 2U] = '\0';
}

bool pm_constant_time_equal(const uint8_t *left, const uint8_t *right, size_t length)
{
    if (left == NULL || right == NULL) {
        return false;
    }
    uint8_t difference = 0U;
    for (size_t i = 0U; i < length; ++i) {
        difference |= left[i] ^ right[i];
    }
    return difference == 0U;
}

static bool valid_encoded_component(const char *value)
{
    for (size_t i = 0U; value[i] != '\0'; ++i) {
        const unsigned char c = (unsigned char)value[i];
        if (c == '%' && (!isxdigit((unsigned char)value[i + 1U]) || !isxdigit((unsigned char)value[i + 2U]))) {
            return false;
        }
        if (c <= 0x20U || c == 0x7FU || c == '#' || c == '+') {
            return false;
        }
    }
    return true;
}

static int compare_strings(const void *left, const void *right)
{
    return strcmp(*(const char *const *)left, *(const char *const *)right);
}

esp_err_t pm_canonical_query(const char *query, char *output, size_t output_size)
{
    if (output == NULL || output_size == 0U) {
        return ESP_ERR_INVALID_ARG;
    }
    output[0] = '\0';
    if (query == NULL || query[0] == '\0') {
        return ESP_OK;
    }
    const size_t length = strlen(query);
    if (length >= PM_CANONICAL_QUERY_MAX || length + 1U > output_size) {
        return ESP_ERR_INVALID_SIZE;
    }
    char scratch[PM_CANONICAL_QUERY_MAX];
    memcpy(scratch, query, length + 1U);
    char *parts[32];
    size_t count = 0U;
    char *cursor = scratch;
    while (cursor != NULL && count < sizeof(parts) / sizeof(parts[0])) {
        parts[count++] = cursor;
        char *separator = strchr(cursor, '&');
        if (separator == NULL) {
            cursor = NULL;
        } else {
            *separator = '\0';
            cursor = separator + 1U;
        }
    }
    if (cursor != NULL) {
        return ESP_ERR_INVALID_SIZE;
    }
    for (size_t i = 0U; i < count; ++i) {
        if (parts[i][0] == '\0' || !valid_encoded_component(parts[i])) {
            return ESP_ERR_INVALID_ARG;
        }
        for (size_t j = 0U; parts[i][j] != '\0'; ++j) {
            if (parts[i][j] == '%') {
                parts[i][j + 1U] = (char)toupper((unsigned char)parts[i][j + 1U]);
                parts[i][j + 2U] = (char)toupper((unsigned char)parts[i][j + 2U]);
                j += 2U;
            }
        }
    }
    qsort(parts, count, sizeof(parts[0]), compare_strings);
    size_t used = 0U;
    for (size_t i = 0U; i < count; ++i) {
        const size_t part_length = strlen(parts[i]);
        if (used + part_length + (i == 0U ? 0U : 1U) + 1U > output_size) {
            return ESP_ERR_INVALID_SIZE;
        }
        if (i != 0U) {
            output[used++] = '&';
        }
        memcpy(&output[used], parts[i], part_length);
        used += part_length;
    }
    output[used] = '\0';
    return ESP_OK;
}

esp_err_t pm_build_canonical(const char *method, const char *path, const char *query, const char *timestamp,
                             const char *nonce, const char *content_sha256, char *output, size_t output_size)
{
    if (method == NULL || path == NULL || path[0] != '/' || timestamp == NULL || nonce == NULL ||
        content_sha256 == NULL || output == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    char uppercase_method[16];
    const size_t method_length = strlen(method);
    if (method_length == 0U || method_length >= sizeof(uppercase_method)) {
        return ESP_ERR_INVALID_SIZE;
    }
    for (size_t i = 0U; i <= method_length; ++i) {
        uppercase_method[i] = (char)toupper((unsigned char)method[i]);
    }
    char canonical_query[PM_CANONICAL_QUERY_MAX];
    esp_err_t error = pm_canonical_query(query, canonical_query, sizeof(canonical_query));
    if (error != ESP_OK) {
        return error;
    }
    char target[512];
    const int target_length = snprintf(target, sizeof(target), "%s%s%s", path,
                                       canonical_query[0] == '\0' ? "" : "?", canonical_query);
    if (target_length < 0 || (size_t)target_length >= sizeof(target)) {
        return ESP_ERR_INVALID_SIZE;
    }
    const int written = snprintf(output, output_size, "%s\n%s\n%s\n%s\n%s\n%s",
                                 PM_HMAC_SCHEME, uppercase_method, target, timestamp, nonce, content_sha256);
    return written >= 0 && (size_t)written < output_size ? ESP_OK : ESP_ERR_INVALID_SIZE;
}

esp_err_t pm_hkdf_directional_keys(const uint8_t *device_secret, size_t secret_length, const char *device_id,
                                   uint8_t device_to_server[PM_SHA256_SIZE],
                                   uint8_t server_to_device[PM_SHA256_SIZE])
{
    if (device_secret == NULL || secret_length < 16U || device_id == NULL || strlen(device_id) != 36U ||
        device_to_server == NULL || server_to_device == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    static const uint8_t outbound_info[] = "PowerMeter V2\0device-to-server";
    static const uint8_t inbound_info[] = "PowerMeter V2\0server-to-device";
    uint8_t salt[sizeof(PM_PROTOCOL_ID) + 36U];
    const size_t protocol_length = strlen(PM_PROTOCOL_ID);
    memcpy(salt, PM_PROTOCOL_ID, protocol_length);
    salt[protocol_length] = 0U;
    memcpy(&salt[protocol_length + 1U], device_id, 36U);
    uint8_t pseudorandom_key[PM_SHA256_SIZE];
    uint8_t expand_input[sizeof(outbound_info) + 1U];
    if (pm_hmac_sha256(salt, protocol_length + 1U + 36U, device_secret, secret_length,
                       pseudorandom_key) != ESP_OK) {
        return ESP_FAIL;
    }
    /* Both outputs are one SHA-256 block. HKDF-Expand is HMAC(PRK, info || 0x01). */
    memcpy(expand_input, outbound_info, sizeof(outbound_info) - 1U);
    expand_input[sizeof(outbound_info) - 1U] = 1U;
    if (pm_hmac_sha256(pseudorandom_key, sizeof(pseudorandom_key), expand_input,
                       sizeof(outbound_info), device_to_server) != ESP_OK) {
        memset(pseudorandom_key, 0, sizeof(pseudorandom_key));
        return ESP_FAIL;
    }
    memcpy(expand_input, inbound_info, sizeof(inbound_info) - 1U);
    expand_input[sizeof(inbound_info) - 1U] = 1U;
    const esp_err_t result = pm_hmac_sha256(pseudorandom_key, sizeof(pseudorandom_key), expand_input,
                                            sizeof(inbound_info), server_to_device);
    memset(pseudorandom_key, 0, sizeof(pseudorandom_key));
    memset(expand_input, 0, sizeof(expand_input));
    memset(salt, 0, sizeof(salt));
    if (result != ESP_OK) {
        memset(device_to_server, 0, PM_SHA256_SIZE);
        memset(server_to_device, 0, PM_SHA256_SIZE);
        return ESP_FAIL;
    }
    return ESP_OK;
}

esp_err_t pm_sign_request(const uint8_t key[PM_SHA256_SIZE], const char *device_id, const char *method,
                          const char *path, const char *query, int64_t utc_ms, const uint8_t nonce[PM_NONCE_SIZE],
                          const uint8_t *body, size_t body_length, pm_auth_headers_t *headers)
{
    if (key == NULL || device_id == NULL || method == NULL || path == NULL || nonce == NULL || headers == NULL ||
        (body == NULL && body_length != 0U)) {
        return ESP_ERR_INVALID_ARG;
    }
    memset(headers, 0, sizeof(*headers));
    uint8_t body_hash[PM_SHA256_SIZE];
    pm_sha256(body, body_length, body_hash);
    (void)snprintf(headers->protocol, sizeof(headers->protocol), "%s", PM_PROTOCOL_ID);
    (void)snprintf(headers->device_id, sizeof(headers->device_id), "%s", device_id);
    (void)snprintf(headers->timestamp, sizeof(headers->timestamp), "%lld", (long long)(utc_ms / 1000));
    pm_hex_lower(nonce, PM_NONCE_SIZE, headers->nonce, sizeof(headers->nonce));
    pm_hex_lower(body_hash, sizeof(body_hash), headers->content_sha256, sizeof(headers->content_sha256));
    char canonical[PM_CANONICAL_MAX];
    esp_err_t error = pm_build_canonical(method, path, query, headers->timestamp, headers->nonce,
                                         headers->content_sha256, canonical, sizeof(canonical));
    if (error != ESP_OK) {
        return error;
    }
    uint8_t hmac[PM_SHA256_SIZE];
    if (pm_hmac_sha256(key, PM_SHA256_SIZE, (const uint8_t *)canonical, strlen(canonical), hmac) != ESP_OK) {
        return ESP_FAIL;
    }
    size_t encoded_length = 0U;
    if (mbedtls_base64_encode((uint8_t *)headers->signature, sizeof(headers->signature), &encoded_length,
                              hmac, sizeof(hmac)) != 0 || encoded_length != PM_SIGNATURE_BASE64_SIZE) {
        memset(hmac, 0, sizeof(hmac));
        return ESP_FAIL;
    }
    headers->signature[encoded_length] = '\0';
    memset(hmac, 0, sizeof(hmac));
    return ESP_OK;
}

bool pm_nonce_accept(pm_nonce_cache_t *cache, const uint8_t nonce[PM_NONCE_SIZE])
{
    if (cache == NULL || nonce == NULL) {
        return false;
    }
    uint8_t digest[PM_SHA256_SIZE];
    pm_sha256(nonce, PM_NONCE_SIZE, digest);
    for (size_t i = 0U; i < cache->count; ++i) {
        if (pm_constant_time_equal(cache->values[i], digest, PM_SHA256_SIZE)) {
            return false;
        }
    }
    memcpy(cache->values[cache->next], digest, PM_SHA256_SIZE);
    cache->next = (cache->next + 1U) % PM_NONCE_CACHE_SIZE;
    if (cache->count < PM_NONCE_CACHE_SIZE) {
        cache->count++;
    }
    return true;
}

static bool lowercase_hex_sha256(const char *value)
{
    if (value == NULL || strlen(value) != PM_SHA256_HEX_SIZE) {
        return false;
    }
    for (size_t i = 0U; i < PM_SHA256_HEX_SIZE; ++i) {
        if (!isdigit((unsigned char)value[i]) && (value[i] < 'a' || value[i] > 'f')) {
            return false;
        }
    }
    return true;
}

esp_err_t pm_verify_response(const uint8_t key[PM_SHA256_SIZE], const char *expected_device_id,
                             const char *path, const char *query, int64_t now_utc_ms,
                             const pm_response_auth_headers_t *headers, const uint8_t *body,
                             size_t body_length, pm_nonce_cache_t *replay_cache)
{
    if (key == NULL || expected_device_id == NULL || path == NULL || headers == NULL ||
        (body == NULL && body_length != 0U) || replay_cache == NULL ||
        strcmp(headers->protocol, PM_PROTOCOL_ID) != 0 ||
        strcmp(headers->device_id, expected_device_id) != 0 ||
        !lowercase_hex_sha256(headers->content_sha256)) {
        return ESP_ERR_INVALID_ARG;
    }
    char *timestamp_end = NULL;
    const long long timestamp_seconds = strtoll(headers->timestamp, &timestamp_end, 10);
    if (timestamp_end == headers->timestamp || timestamp_end == NULL || *timestamp_end != '\0' ||
        timestamp_seconds < 0LL || now_utc_ms < 0 ||
        llabs(timestamp_seconds - (long long)(now_utc_ms / 1000)) > 300LL) {
        return ESP_ERR_INVALID_RESPONSE;
    }
    const size_t nonce_length = strlen(headers->nonce);
    if (nonce_length < 16U || nonce_length > PM_RESPONSE_NONCE_MAX ||
        strlen(headers->signature) != PM_SIGNATURE_BASE64_SIZE) {
        return ESP_ERR_INVALID_RESPONSE;
    }
    uint8_t body_digest[PM_SHA256_SIZE];
    char body_hex[PM_SHA256_HEX_SIZE + 1U];
    pm_sha256(body, body_length, body_digest);
    pm_hex_lower(body_digest, sizeof(body_digest), body_hex, sizeof(body_hex));
    if (!pm_constant_time_equal((const uint8_t *)body_hex,
                                (const uint8_t *)headers->content_sha256, PM_SHA256_HEX_SIZE)) {
        return ESP_ERR_INVALID_CRC;
    }
    char canonical[PM_CANONICAL_MAX];
    esp_err_t error = pm_build_canonical("RESPONSE", path, query, headers->timestamp, headers->nonce,
                                         headers->content_sha256, canonical, sizeof(canonical));
    if (error != ESP_OK) {
        return error;
    }
    uint8_t expected[PM_SHA256_SIZE];
    uint8_t presented[PM_SHA256_SIZE];
    size_t decoded_length = 0U;
    if (pm_hmac_sha256(key, PM_SHA256_SIZE, (const uint8_t *)canonical, strlen(canonical), expected) != ESP_OK ||
        mbedtls_base64_decode(presented, sizeof(presented), &decoded_length,
                              (const uint8_t *)headers->signature, strlen(headers->signature)) != 0 ||
        decoded_length != sizeof(presented) ||
        !pm_constant_time_equal(expected, presented, sizeof(expected))) {
        memset(expected, 0, sizeof(expected));
        memset(presented, 0, sizeof(presented));
        return ESP_ERR_INVALID_MAC;
    }
    uint8_t nonce_digest[PM_SHA256_SIZE];
    pm_sha256((const uint8_t *)headers->nonce, nonce_length, nonce_digest);
    for (size_t i = 0U; i < replay_cache->count; ++i) {
        if (pm_constant_time_equal(replay_cache->values[i], nonce_digest, sizeof(nonce_digest))) {
            memset(expected, 0, sizeof(expected));
            memset(presented, 0, sizeof(presented));
            return ESP_ERR_INVALID_STATE;
        }
    }
    memcpy(replay_cache->values[replay_cache->next], nonce_digest, sizeof(nonce_digest));
    replay_cache->next = (replay_cache->next + 1U) % PM_NONCE_CACHE_SIZE;
    if (replay_cache->count < PM_NONCE_CACHE_SIZE) {
        replay_cache->count++;
    }
    memset(expected, 0, sizeof(expected));
    memset(presented, 0, sizeof(presented));
    memset(nonce_digest, 0, sizeof(nonce_digest));
    return ESP_OK;
}
