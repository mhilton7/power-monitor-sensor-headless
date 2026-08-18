idf_component_register(
    SRCS "pm_telemetry.c"
    INCLUDE_DIRS "include"
    REQUIRES pm_meter
)
target_compile_options(${COMPONENT_LIB} PRIVATE -Wall -Wextra -Werror -Wframe-larger-than=3072)
