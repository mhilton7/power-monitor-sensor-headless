#include <math.h>
#include <stdint.h>
#include <stdio.h>

#include "pm_command_envelope.h"
#include "pm_ota_version.h"

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

static void test_strict_monotonic_versions(void)
{
    CHECK(pm_ota_version_require_upgrade("0.1.0-rc.7", "0.1.0-rc.8") == ESP_OK);
    CHECK(pm_ota_version_require_upgrade("0.1.0-rc.8", "0.1.0") == ESP_OK);
    CHECK(pm_ota_version_require_upgrade("0.1.0", "0.1.1-rc.1") == ESP_OK);
    CHECK(pm_ota_version_require_upgrade("0.1.9", "0.2.0-rc.1") == ESP_OK);
    CHECK(pm_ota_version_require_upgrade("9.9.9", "10.0.0-rc.1") == ESP_OK);

    CHECK(pm_ota_version_require_upgrade("0.1.0-rc.8", "0.1.0-rc.7") == ESP_ERR_NOT_SUPPORTED);
    CHECK(pm_ota_version_require_upgrade("0.1.0-rc.8", "0.1.0-rc.8") == ESP_ERR_NOT_SUPPORTED);
    CHECK(pm_ota_version_require_upgrade("0.1.0", "0.1.0-rc.9") == ESP_ERR_NOT_SUPPORTED);
    CHECK(pm_ota_version_require_upgrade("1.0.0", "0.99.99") == ESP_ERR_NOT_SUPPORTED);
}

static void test_malformed_versions_fail_closed(void)
{
    static const char *const invalid[] = {
        "", "v0.1.0", "0.1", "0.1.0.1", "00.1.0", "0.01.0", "0.1.00",
        "0.1.0-rc", "0.1.0-rc.", "0.1.0-rc.0", "0.1.0-rc.01", "0.1.0-alpha.1",
        "0.1.0+build.1", "4294967296.0.0", "0.4294967296.0", "0.0.4294967296",
    };
    for (size_t index = 0U; index < sizeof(invalid) / sizeof(invalid[0]); ++index) {
        CHECK(pm_ota_version_require_upgrade(invalid[index], "1.0.0") == ESP_ERR_INVALID_ARG);
        CHECK(pm_ota_version_require_upgrade("0.1.0", invalid[index]) == ESP_ERR_INVALID_ARG);
    }
    CHECK(pm_ota_version_require_upgrade(NULL, "1.0.0") == ESP_ERR_INVALID_ARG);
    CHECK(pm_ota_version_require_upgrade("0.1.0", NULL) == ESP_ERR_INVALID_ARG);
}

static void test_stale_delivery_attempt_saturates(void)
{
    uint8_t attempt = 0U;
    CHECK(pm_command_attempt_from_json_number(0.0, &attempt) && attempt == 0U);
    CHECK(pm_command_attempt_from_json_number(1.0, &attempt) && attempt == 1U);
    CHECK(pm_command_attempt_from_json_number(255.0, &attempt) && attempt == UINT8_MAX);
    CHECK(pm_command_attempt_from_json_number(256.0, &attempt) && attempt == UINT8_MAX);
    CHECK(pm_command_attempt_from_json_number(1000000.0, &attempt) && attempt == UINT8_MAX);
    CHECK(pm_command_attempt_from_json_number(4294967295.0, &attempt) && attempt == UINT8_MAX);
    CHECK(!pm_command_attempt_from_json_number(-1.0, &attempt));
    CHECK(!pm_command_attempt_from_json_number(1.5, &attempt));
    CHECK(!pm_command_attempt_from_json_number(4294967296.0, &attempt));
    CHECK(!pm_command_attempt_from_json_number(NAN, &attempt));
    CHECK(!pm_command_attempt_from_json_number(1.0, NULL));
}

int main(void)
{
    test_strict_monotonic_versions();
    test_malformed_versions_fail_closed();
    test_stale_delivery_attempt_saturates();
    printf("{\"suite\":\"pm-ota-policy\",\"assertions\":%u,\"failures\":%u}\n",
           assertions, failures);
    return failures == 0U ? 0 : 1;
}
