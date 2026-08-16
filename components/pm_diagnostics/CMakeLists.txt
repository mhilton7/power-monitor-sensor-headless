idf_component_register(
    SRCS "pm_diagnostics.c"
    INCLUDE_DIRS "include"
    REQUIRES heap freertos esp_system pm_config
)
target_compile_options(${COMPONENT_LIB} PRIVATE -Wall -Wextra -Werror -Wframe-larger-than=3072)

