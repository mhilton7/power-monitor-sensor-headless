idf_component_register(
    SRCS "pm_meter.c" "pm_meter_pzem_v4_classic.c"
    INCLUDE_DIRS "include"
    REQUIRES esp_driver_uart esp_timer pm_config
)
target_compile_options(${COMPONENT_LIB} PRIVATE -Wall -Wextra -Werror)
