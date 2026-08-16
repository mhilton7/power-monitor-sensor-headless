#include "pm_command_envelope.h"

#include <stddef.h>
#include <stdint.h>

bool pm_command_attempt_from_json_number(double value, uint8_t *attempt)
{
    if (attempt == NULL || !(value >= 0.0 && value <= (double)UINT32_MAX)) {
        return false;
    }
    const uint32_t wire_value = (uint32_t)value;
    if ((double)wire_value != value) {
        return false;
    }
    *attempt = wire_value > UINT8_MAX ? UINT8_MAX : (uint8_t)wire_value;
    return true;
}
