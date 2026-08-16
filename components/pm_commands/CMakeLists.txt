idf_component_register(
    SRCS "pm_commands.c"
    INCLUDE_DIRS "include"
    REQUIRES nvs_flash esp_timer esp_system esp_hw_support freertos pm_config pm_storage pm_protocol
)
target_compile_options(${COMPONENT_LIB} PRIVATE -Wall -Wextra -Werror -Wframe-larger-than=3072)
