idf_component_register(
    SRCS "pm_ota.c" "pm_ota_version.c"
    INCLUDE_DIRS "include"
    REQUIRES app_update esp_http_client esp_https_ota mbedtls nvs_flash heap espressif__cjson pm_protocol pm_config
)
target_compile_options(${COMPONENT_LIB} PRIVATE -Wall -Wextra -Werror -Wframe-larger-than=3072)
