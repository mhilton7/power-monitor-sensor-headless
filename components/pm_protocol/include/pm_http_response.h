#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "esp_err.h"
#include "pm_protocol.h"

#ifdef __cplusplus
extern "C" {
#endif

#define PM_HTTP_RESPONSE_ETAG_CAPACITY 68U

typedef struct {
    pm_response_auth_headers_t auth;
    char etag[PM_HTTP_RESPONSE_ETAG_CAPACITY];
    uint8_t seen_mask;
    bool invalid;
} pm_http_response_capture_t;

void pm_http_response_capture_init(pm_http_response_capture_t *capture);
esp_err_t pm_http_response_capture_header(pm_http_response_capture_t *capture,
                                          const char *name, const char *value);
esp_err_t pm_http_response_capture_validate(const pm_http_response_capture_t *capture,
                                            bool require_etag);

#ifdef __cplusplus
}
#endif
