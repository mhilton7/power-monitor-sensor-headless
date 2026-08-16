#pragma once

#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

esp_err_t pm_ota_version_require_upgrade(const char *current_version,
                                         const char *candidate_version);

#ifdef __cplusplus
}
#endif
