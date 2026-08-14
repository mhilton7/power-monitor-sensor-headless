idf_component_register(
    SRCS "pm_config.c" "pm_state.c"
    INCLUDE_DIRS "include"
    REQUIRES nvs_flash esp_timer
)
target_compile_options(${COMPONENT_LIB} PRIVATE -Wall -Wextra -Werror)

