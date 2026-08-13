idf_component_register(
    SRCS "app_main.c"
    INCLUDE_DIRS "."
    REQUIRES
        pm_config
        pm_measurement
        pm_meter
        pm_storage
        pm_protocol
        pm_network
        pm_commands
        pm_ota
        pm_provisioning
        pm_diagnostics
        esp_event
        esp_netif
        esp_wifi
        nvs_flash
)

target_compile_options(${COMPONENT_LIB} PRIVATE -Wall -Wextra -Werror)

