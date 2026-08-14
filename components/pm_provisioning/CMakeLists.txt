idf_component_register(
    SRCS "pm_provisioning.c"
    INCLUDE_DIRS "include"
    REQUIRES espressif__cjson esp_driver_usb_serial_jtag esp_system esp_hw_support pm_config pm_protocol
)
target_compile_options(${COMPONENT_LIB} PRIVATE -Wall -Wextra -Werror)
