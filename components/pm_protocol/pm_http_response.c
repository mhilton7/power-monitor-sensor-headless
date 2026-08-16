#include "pm_http_response.h"

#include <stddef.h>
#include <string.h>

enum {
    PM_HTTP_SEEN_PROTOCOL = 1U << 0,
    PM_HTTP_SEEN_DEVICE_ID = 1U << 1,
    PM_HTTP_SEEN_TIMESTAMP = 1U << 2,
    PM_HTTP_SEEN_NONCE = 1U << 3,
    PM_HTTP_SEEN_CONTENT_SHA256 = 1U << 4,
    PM_HTTP_SEEN_SIGNATURE = 1U << 5,
    PM_HTTP_SEEN_ETAG = 1U << 6,
};

#define PM_HTTP_REQUIRED_AUTH_MASK                                                     \
    (PM_HTTP_SEEN_PROTOCOL | PM_HTTP_SEEN_DEVICE_ID | PM_HTTP_SEEN_TIMESTAMP |        \
     PM_HTTP_SEEN_NONCE | PM_HTTP_SEEN_CONTENT_SHA256 | PM_HTTP_SEEN_SIGNATURE)

static char ascii_lower(char value)
{
    return value >= 'A' && value <= 'Z' ? (char)(value + ('a' - 'A')) : value;
}

static bool header_name_equal(const char *actual, const char *expected)
{
    if (actual == NULL || expected == NULL) {
        return false;
    }
    size_t index = 0U;
    while (expected[index] != '\0') {
        if (actual[index] == '\0' || ascii_lower(actual[index]) != ascii_lower(expected[index])) {
            return false;
        }
        index++;
    }
    return actual[index] == '\0';
}

static size_t bounded_value_length(const char *value, size_t capacity)
{
    if (value == NULL) {
        return capacity;
    }
    for (size_t length = 0U; length < capacity; ++length) {
        if (value[length] == '\0') {
            return length;
        }
    }
    return capacity;
}

void pm_http_response_capture_init(pm_http_response_capture_t *capture)
{
    if (capture != NULL) {
        memset(capture, 0, sizeof(*capture));
    }
}

esp_err_t pm_http_response_capture_header(pm_http_response_capture_t *capture,
                                          const char *name, const char *value)
{
    if (capture == NULL || name == NULL || value == NULL) {
        if (capture != NULL) {
            capture->invalid = true;
        }
        return ESP_ERR_INVALID_ARG;
    }
    if (capture->invalid) {
        return ESP_ERR_INVALID_RESPONSE;
    }

    char *destination = NULL;
    size_t capacity = 0U;
    uint8_t field = 0U;
    if (header_name_equal(name, "X-PM-Protocol")) {
        destination = capture->auth.protocol;
        capacity = sizeof(capture->auth.protocol);
        field = PM_HTTP_SEEN_PROTOCOL;
    } else if (header_name_equal(name, "X-PM-Device-ID")) {
        destination = capture->auth.device_id;
        capacity = sizeof(capture->auth.device_id);
        field = PM_HTTP_SEEN_DEVICE_ID;
    } else if (header_name_equal(name, "X-PM-Timestamp")) {
        destination = capture->auth.timestamp;
        capacity = sizeof(capture->auth.timestamp);
        field = PM_HTTP_SEEN_TIMESTAMP;
    } else if (header_name_equal(name, "X-PM-Nonce")) {
        destination = capture->auth.nonce;
        capacity = sizeof(capture->auth.nonce);
        field = PM_HTTP_SEEN_NONCE;
    } else if (header_name_equal(name, "X-PM-Content-SHA256")) {
        destination = capture->auth.content_sha256;
        capacity = sizeof(capture->auth.content_sha256);
        field = PM_HTTP_SEEN_CONTENT_SHA256;
    } else if (header_name_equal(name, "X-PM-Signature")) {
        destination = capture->auth.signature;
        capacity = sizeof(capture->auth.signature);
        field = PM_HTTP_SEEN_SIGNATURE;
    } else if (header_name_equal(name, "ETag")) {
        destination = capture->etag;
        capacity = sizeof(capture->etag);
        field = PM_HTTP_SEEN_ETAG;
    } else {
        return ESP_OK;
    }

    const size_t length = bounded_value_length(value, capacity);
    if ((capture->seen_mask & field) != 0U || length == 0U || length >= capacity) {
        capture->invalid = true;
        if (destination != NULL && capacity != 0U) {
            memset(destination, 0, capacity);
        }
        return ESP_ERR_INVALID_RESPONSE;
    }
    memcpy(destination, value, length + 1U);
    capture->seen_mask |= field;
    return ESP_OK;
}

esp_err_t pm_http_response_capture_validate(const pm_http_response_capture_t *capture,
                                            bool require_etag)
{
    if (capture == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    const uint8_t required = require_etag ?
        (uint8_t)(PM_HTTP_REQUIRED_AUTH_MASK | PM_HTTP_SEEN_ETAG) :
        (uint8_t)PM_HTTP_REQUIRED_AUTH_MASK;
    return !capture->invalid && (capture->seen_mask & required) == required ?
        ESP_OK : ESP_ERR_INVALID_RESPONSE;
}
