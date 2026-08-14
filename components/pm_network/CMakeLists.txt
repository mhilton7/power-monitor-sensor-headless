idf_component_register(
    SRCS "pm_network.c"
    INCLUDE_DIRS "include"
    REQUIRES esp_wifi esp_event esp_netif esp_http_client esp_hw_support esp_app_format lwip espressif__cjson mbedtls pm_config pm_meter pm_storage pm_protocol pm_commands pm_provisioning pm_diagnostics
)
target_compile_options(${COMPONENT_LIB} PRIVATE -Wall -Wextra -Werror)
