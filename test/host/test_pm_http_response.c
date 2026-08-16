#include <stdio.h>
#include <string.h>

#include "pm_http_response.h"

static unsigned int assertions;
static unsigned int failures;

#define CHECK(condition)                                                                  \
    do {                                                                                  \
        assertions++;                                                                     \
        if (!(condition)) {                                                               \
            failures++;                                                                   \
            fprintf(stderr, "check failed at %s:%d: %s\n", __FILE__, __LINE__, #condition); \
        }                                                                                 \
    } while (0)

static void add_auth_headers(pm_http_response_capture_t *capture)
{
    CHECK(pm_http_response_capture_header(capture, "x-pm-protocol", "pm-protocol/1.0.0") == ESP_OK);
    CHECK(pm_http_response_capture_header(capture, "X-PM-Device-ID",
                                          "123e4567-e89b-42d3-a456-426614174000") == ESP_OK);
    CHECK(pm_http_response_capture_header(capture, "X-PM-Timestamp", "1786842000") == ESP_OK);
    CHECK(pm_http_response_capture_header(capture, "X-PM-Nonce",
                                          "00112233445566778899aabbccddeeff") == ESP_OK);
    CHECK(pm_http_response_capture_header(
              capture, "X-PM-Content-SHA256",
              "aa73e2c4562e7c8b3fc8b4972629a2c21a254762815aec50ba1b9de3f9d1c7ab") == ESP_OK);
    CHECK(pm_http_response_capture_header(
              capture, "X-PM-Signature", "J6gMy6ogVd6+/t0n+gaT10ODKPwus/+nOeuT4xoMbTc=") == ESP_OK);
}

static void test_complete_allowlist(void)
{
    pm_http_response_capture_t capture;
    pm_http_response_capture_init(&capture);
    CHECK(pm_http_response_capture_header(&capture, "Content-Type", "application/json") == ESP_OK);
    add_auth_headers(&capture);
    CHECK(pm_http_response_capture_validate(&capture, false) == ESP_OK);
    CHECK(pm_http_response_capture_validate(&capture, true) == ESP_ERR_INVALID_RESPONSE);
    CHECK(pm_http_response_capture_header(
              &capture, "etag", "\"aa73e2c4562e7c8b3fc8b4972629a2c21a254762815aec50ba1b9de3f9d1c7ab\"") == ESP_OK);
    CHECK(pm_http_response_capture_validate(&capture, true) == ESP_OK);
    CHECK(strcmp(capture.auth.protocol, "pm-protocol/1.0.0") == 0);
    CHECK(strcmp(capture.etag,
                 "\"aa73e2c4562e7c8b3fc8b4972629a2c21a254762815aec50ba1b9de3f9d1c7ab\"") == 0);
}

static void test_missing_duplicate_and_empty_fail_closed(void)
{
    pm_http_response_capture_t missing;
    pm_http_response_capture_init(&missing);
    CHECK(pm_http_response_capture_header(&missing, "X-PM-Protocol", "pm-protocol/1.0.0") == ESP_OK);
    CHECK(pm_http_response_capture_validate(&missing, false) == ESP_ERR_INVALID_RESPONSE);

    pm_http_response_capture_t duplicate;
    pm_http_response_capture_init(&duplicate);
    CHECK(pm_http_response_capture_header(&duplicate, "X-PM-Nonce", "one") == ESP_OK);
    CHECK(pm_http_response_capture_header(&duplicate, "x-pm-nonce", "two") == ESP_ERR_INVALID_RESPONSE);
    CHECK(duplicate.invalid);
    CHECK(pm_http_response_capture_header(&duplicate, "Server", "ignored") == ESP_ERR_INVALID_RESPONSE);
    CHECK(pm_http_response_capture_validate(&duplicate, false) == ESP_ERR_INVALID_RESPONSE);

    pm_http_response_capture_t empty;
    pm_http_response_capture_init(&empty);
    CHECK(pm_http_response_capture_header(&empty, "X-PM-Signature", "") == ESP_ERR_INVALID_RESPONSE);
    CHECK(empty.invalid);
}

static void test_every_allowlisted_header_is_bounded(void)
{
    static const char *const names[] = {
        "X-PM-Protocol", "X-PM-Device-ID", "X-PM-Timestamp", "X-PM-Nonce",
        "X-PM-Content-SHA256", "X-PM-Signature", "ETag",
    };
    char oversized[256];
    memset(oversized, 'a', sizeof(oversized));
    oversized[sizeof(oversized) - 1U] = '\0';
    for (size_t index = 0U; index < sizeof(names) / sizeof(names[0]); ++index) {
        pm_http_response_capture_t capture;
        pm_http_response_capture_init(&capture);
        CHECK(pm_http_response_capture_header(&capture, names[index], oversized) == ESP_ERR_INVALID_RESPONSE);
        CHECK(capture.invalid);
        CHECK(pm_http_response_capture_validate(&capture, false) == ESP_ERR_INVALID_RESPONSE);
    }

    pm_http_response_capture_t unknown;
    pm_http_response_capture_init(&unknown);
    CHECK(pm_http_response_capture_header(&unknown, "X-Untrusted-Arbitrary", oversized) == ESP_OK);
    CHECK(!unknown.invalid);
    CHECK(unknown.seen_mask == 0U);
}

static void test_invalid_arguments(void)
{
    pm_http_response_capture_t capture;
    pm_http_response_capture_init(&capture);
    CHECK(pm_http_response_capture_header(NULL, "X-PM-Nonce", "value") == ESP_ERR_INVALID_ARG);
    CHECK(pm_http_response_capture_header(&capture, NULL, "value") == ESP_ERR_INVALID_ARG);
    CHECK(capture.invalid);
    CHECK(pm_http_response_capture_validate(NULL, false) == ESP_ERR_INVALID_ARG);
}

int main(void)
{
    test_complete_allowlist();
    test_missing_duplicate_and_empty_fail_closed();
    test_every_allowlisted_header_is_bounded();
    test_invalid_arguments();
    printf("{\"suite\":\"pm-http-response\",\"assertions\":%u,\"failures\":%u}\n",
           assertions, failures);
    return failures == 0U ? 0 : 1;
}
