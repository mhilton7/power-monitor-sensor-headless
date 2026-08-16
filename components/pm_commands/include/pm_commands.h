#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

#define PM_COMMAND_ID_MAX 36U
#define PM_IDEMPOTENCY_KEY_MAX 100U
#define PM_COMMAND_PAYLOAD_MAX 1536U
#define PM_COMMAND_RESULT_MAX 160U
#define PM_COMMAND_EVIDENCE_MAX 384U
#define PM_COMMAND_LEDGER_SIZE 8U

typedef enum {
    PM_COMMAND_REBOOT = 0,
    PM_COMMAND_MAINTENANCE_SLEEP,
    PM_COMMAND_SYNC_NOW,
    PM_COMMAND_DIAGNOSTICS_SNAPSHOT,
    PM_COMMAND_NETWORK_SELF_TEST,
    PM_COMMAND_METER_SELF_TEST,
    PM_COMMAND_STORAGE_SELF_TEST,
    PM_COMMAND_FORMAT_STORAGE_PREPARE,
    PM_COMMAND_FORMAT_STORAGE_COMMIT,
    PM_COMMAND_APPLY_CONFIGURATION,
    PM_COMMAND_ROTATE_DEVICE_CREDENTIALS,
    PM_COMMAND_OTA_INSTALL,
    PM_COMMAND_DATA_RESET_PREPARE,
    PM_COMMAND_DATA_RESET_COMMIT,
    PM_COMMAND_DATA_RESET_CANCEL,
    PM_COMMAND_TYPE_COUNT,
} pm_command_type_t;

typedef enum {
    PM_COMMAND_QUEUED = 0,
    PM_COMMAND_DELIVERED,
    PM_COMMAND_ACCEPTED,
    PM_COMMAND_RUNNING,
    PM_COMMAND_SUCCEEDED,
    PM_COMMAND_FAILED,
    PM_COMMAND_EXPIRED,
    PM_COMMAND_CANCELLED,
    PM_COMMAND_SUPERSEDED,
    PM_COMMAND_AWAITING_REBOOT,
    PM_COMMAND_AWAITING_HEARTBEAT,
    PM_COMMAND_ROLLED_BACK,
} pm_command_state_t;

typedef struct {
    char command_id[PM_COMMAND_ID_MAX + 1U];
    char idempotency_key[PM_IDEMPOTENCY_KEY_MAX + 1U];
    pm_command_type_t type;
    pm_command_state_t state;
    int64_t issued_utc_ms;
    int64_t not_before_utc_ms;
    int64_t expires_utc_ms;
    uint8_t progress_percent;
    uint8_t attempt;
    bool result_ack_required;
    bool payload_redacted;
    uint8_t payload_sha256[32];
    char payload[PM_COMMAND_PAYLOAD_MAX + 1U];
    char result_text[PM_COMMAND_RESULT_MAX + 1U];
    char evidence_json[PM_COMMAND_EVIDENCE_MAX + 1U];
    int32_t result_code;
    uint32_t crc32;
} pm_command_t;

typedef struct {
    pm_command_t entries[PM_COMMAND_LEDGER_SIZE];
    uint32_t generation;
    uint8_t next;
    uint32_t crc32;
} pm_command_ledger_t;

typedef enum {
    PM_COMMAND_BOOT_IGNORE = 0,
    PM_COMMAND_BOOT_REQUEUE,
    PM_COMMAND_BOOT_FAIL_INTERRUPTED,
    PM_COMMAND_BOOT_COMPLETE_REBOOT,
    PM_COMMAND_BOOT_COMPLETE_WAKE,
    PM_COMMAND_BOOT_RECONCILE_OTA,
} pm_command_boot_action_t;

esp_err_t pm_commands_load(pm_command_ledger_t *ledger);
esp_err_t pm_commands_lock(void);
void pm_commands_unlock(void);
esp_err_t pm_command_accept(pm_command_ledger_t *ledger, const pm_command_t *incoming, int64_t now_utc_ms,
                            pm_command_t **stored, bool *duplicate);
esp_err_t pm_command_transition(pm_command_ledger_t *ledger, pm_command_t *command, pm_command_state_t state,
                                uint8_t progress_percent, int32_t result_code);
esp_err_t pm_command_acknowledge_result(pm_command_ledger_t *ledger, const char *command_id);
esp_err_t pm_command_zeroize_payload(pm_command_ledger_t *ledger, pm_command_t *command);
pm_command_boot_action_t pm_command_boot_action(const pm_command_t *command);
esp_err_t pm_command_reconcile_boot(pm_command_ledger_t *ledger, pm_command_t *command,
                                    pm_command_state_t state, int32_t result_code,
                                    const char *result_text);
const char *pm_command_type_name(pm_command_type_t type);
const char *pm_command_state_name(pm_command_state_t state);
bool pm_command_type_from_name(const char *name, pm_command_type_t *type);

#ifdef __cplusplus
}
#endif
