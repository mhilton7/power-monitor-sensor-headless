#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "esp_err.h"
#include "pm_config.h"

#ifdef __cplusplus
extern "C" {
#endif

#define PM_COM_PROTOCOL "pm-com/1.0.0"
#define PM_COM_LINE_MAX 8192U
#define PM_ENROLLMENT_TOKEN_MAX 192U

typedef enum {
    PM_PROVISIONING_TEST_WIFI = 0,
    PM_PROVISIONING_TEST_IPV4,
    PM_PROVISIONING_TEST_DNS,
    PM_PROVISIONING_TEST_TLS,
    PM_PROVISIONING_TEST_ENROLLMENT,
} pm_provisioning_test_stage_t;

typedef esp_err_t (*pm_provisioning_test_fn)(pm_provisioning_test_stage_t stage, pm_config_t *candidate,
                                             const char *enrollment_token, void *context);
typedef esp_err_t (*pm_factory_reset_fn)(void *context);
typedef esp_err_t (*pm_safe_reboot_prepare_fn)(void *context);
typedef esp_err_t (*pm_safe_reboot_flush_fn)(void *context, uint32_t timeout_ms);

typedef struct {
    size_t used;
    bool discarding_oversized_line;
} pm_com_framer_t;

typedef enum {
    PM_COM_FRAME_NONE = 0,
    PM_COM_FRAME_READY,
    PM_COM_FRAME_OVERSIZED,
} pm_com_frame_result_t;

typedef struct {
    pm_config_t active;
    pm_config_t candidate;
    pm_config_transaction_t transaction;
    char enrollment_token[PM_ENROLLMENT_TOKEN_MAX + 1U];
    uint8_t factory_token[16];
    int64_t factory_token_expires_us;
    bool candidate_present;
    bool tests_passed;
    bool reboot_requested;
    bool physically_authorized;
    pm_provisioning_test_fn test;
    pm_factory_reset_fn factory_reset;
    pm_safe_reboot_prepare_fn safe_reboot_prepare;
    void *callback_context;
} pm_provisioning_session_t;

void pm_provisioning_session_init(pm_provisioning_session_t *session, const pm_config_t *active,
                                  bool physically_authorized, pm_provisioning_test_fn test,
                                  pm_factory_reset_fn factory_reset, pm_safe_reboot_prepare_fn safe_reboot_prepare,
                                  void *callback_context);
esp_err_t pm_provisioning_handle_line(pm_provisioning_session_t *session, const char *line, char *response,
                                      size_t response_size);
pm_com_frame_result_t pm_provisioning_framer_push(pm_com_framer_t *framer, uint8_t byte,
                                                   char *line, size_t line_capacity);
esp_err_t pm_provisioning_prepare_reboot_barrier(bool storage_worker_available,
                                                  pm_safe_reboot_flush_fn flush, void *context,
                                                  uint32_t timeout_ms);
bool pm_provisioning_reboot_tx_complete(bool reboot_requested, size_t response_length,
                                        int written, esp_err_t drain_result);
esp_err_t pm_provisioning_start_usb(pm_provisioning_session_t *session);

#ifdef __cplusplus
}
#endif

