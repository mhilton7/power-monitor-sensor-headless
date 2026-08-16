#pragma once

#define ESP_RETURN_ON_ERROR(expression, tag, message) \
    do {                                                \
        (void)(tag);                                    \
        (void)(message);                                \
        const esp_err_t result_ = (expression);         \
        if (result_ != ESP_OK) {                        \
            return result_;                             \
        }                                               \
    } while (0)
