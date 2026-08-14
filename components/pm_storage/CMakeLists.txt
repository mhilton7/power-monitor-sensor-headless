idf_component_register(
    SRCS "pm_storage.c" "pm_journal.c" "pm_sequence.c"
    INCLUDE_DIRS "include"
    REQUIRES pm_config pm_measurement fatfs sdmmc driver nvs_flash esp_hw_support
)
target_compile_options(${COMPONENT_LIB} PRIVATE -Wall -Wextra -Werror)
