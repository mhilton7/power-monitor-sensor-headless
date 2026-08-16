#include "pm_ota_version.h"

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

typedef struct {
    uint32_t major;
    uint32_t minor;
    uint32_t patch;
    uint32_t release_candidate;
    bool is_release_candidate;
} pm_ota_version_t;

static bool parse_number(const char **cursor, uint32_t *output)
{
    const char *value = cursor == NULL ? NULL : *cursor;
    if (value == NULL || output == NULL || *value < '0' || *value > '9') {
        return false;
    }
    if (*value == '0' && value[1] >= '0' && value[1] <= '9') {
        return false;
    }
    uint32_t parsed = 0U;
    do {
        const uint32_t digit = (uint32_t)(*value - '0');
        if (parsed > (UINT32_MAX - digit) / 10U) {
            return false;
        }
        parsed = parsed * 10U + digit;
        value++;
    } while (*value >= '0' && *value <= '9');
    *cursor = value;
    *output = parsed;
    return true;
}

static bool parse_version(const char *text, pm_ota_version_t *version)
{
    if (text == NULL || version == NULL || *text == '\0') {
        return false;
    }
    pm_ota_version_t candidate = {0};
    const char *cursor = text;
    if (!parse_number(&cursor, &candidate.major) || *cursor++ != '.' ||
        !parse_number(&cursor, &candidate.minor) || *cursor++ != '.' ||
        !parse_number(&cursor, &candidate.patch)) {
        return false;
    }
    if (*cursor == '\0') {
        *version = candidate;
        return true;
    }
    if (strncmp(cursor, "-rc.", 4U) != 0) {
        return false;
    }
    cursor += 4U;
    candidate.is_release_candidate = true;
    if (!parse_number(&cursor, &candidate.release_candidate) ||
        candidate.release_candidate == 0U || *cursor != '\0') {
        return false;
    }
    *version = candidate;
    return true;
}

static int compare_versions(const pm_ota_version_t *left, const pm_ota_version_t *right)
{
    const uint32_t left_values[] = {left->major, left->minor, left->patch};
    const uint32_t right_values[] = {right->major, right->minor, right->patch};
    for (size_t index = 0U; index < sizeof(left_values) / sizeof(left_values[0]); ++index) {
        if (left_values[index] != right_values[index]) {
            return left_values[index] > right_values[index] ? 1 : -1;
        }
    }
    if (left->is_release_candidate != right->is_release_candidate) {
        return left->is_release_candidate ? -1 : 1;
    }
    if (!left->is_release_candidate || left->release_candidate == right->release_candidate) {
        return 0;
    }
    return left->release_candidate > right->release_candidate ? 1 : -1;
}

esp_err_t pm_ota_version_require_upgrade(const char *current_version,
                                         const char *candidate_version)
{
    pm_ota_version_t current = {0};
    pm_ota_version_t candidate = {0};
    if (!parse_version(current_version, &current) || !parse_version(candidate_version, &candidate)) {
        return ESP_ERR_INVALID_ARG;
    }
    return compare_versions(&candidate, &current) > 0 ? ESP_OK : ESP_ERR_NOT_SUPPORTED;
}
