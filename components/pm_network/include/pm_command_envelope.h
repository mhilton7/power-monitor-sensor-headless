#pragma once

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

bool pm_command_attempt_from_json_number(double value, uint8_t *attempt);

#ifdef __cplusplus
}
#endif
