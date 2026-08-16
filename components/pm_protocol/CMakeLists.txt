idf_component_register(
    SRCS "pm_protocol.c" "pm_time.c"
    INCLUDE_DIRS "include"
    REQUIRES mbedtls nvs_flash esp_timer
)
target_compile_options(${COMPONENT_LIB} PRIVATE -Wall -Wextra -Werror -Wframe-larger-than=3072)

