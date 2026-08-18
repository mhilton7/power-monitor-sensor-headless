#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "nvs.h"
#include "pm_commands.h"
#include "pm_config.h"
#include "pm_protocol.h"

#define CHECK(condition)                                                                                              \
    do {                                                                                                              \
        if (!(condition)) {                                                                                           \
            fprintf(stderr, "check failed at %s:%d: %s\n", __FILE__, __LINE__, #condition);                         \
            return 1;                                                                                                 \
        }                                                                                                             \
    } while (0)

typedef struct {
    bool present;
    uint8_t bytes[sizeof(pm_command_ledger_t)];
    size_t size;
} nvs_slot_t;

static nvs_slot_t s_slot_a;
static nvs_slot_t s_slot_b;
static bool s_open_fails;
static bool s_commit_fails;
static unsigned int s_commit_count;
static unsigned int s_get_count;
static unsigned int s_fail_get_call;
static unsigned int s_override_get_call;
static pm_command_ledger_t s_get_override;
static const char *s_get_keys[8];
unsigned int s_test_mutex_depth;
unsigned int s_test_mutex_max_depth;

static nvs_slot_t *slot_for_key(const char *key)
{
    if (strcmp(key, "slot_a") == 0) {
        return &s_slot_a;
    }
    if (strcmp(key, "slot_b") == 0) {
        return &s_slot_b;
    }
    return NULL;
}

esp_err_t nvs_open(const char *namespace_name, nvs_open_mode_t open_mode, nvs_handle_t *out_handle)
{
    if (s_open_fails) {
        return ESP_FAIL;
    }
    if (namespace_name == NULL || strcmp(namespace_name, "pm_commands") != 0 ||
        open_mode != NVS_READWRITE || out_handle == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    *out_handle = 1U;
    return ESP_OK;
}

void nvs_close(nvs_handle_t handle)
{
    (void)handle;
}

esp_err_t nvs_get_blob(nvs_handle_t handle, const char *key, void *out_value, size_t *length)
{
    s_get_count++;
    if (s_get_count <= 8U) {
        s_get_keys[s_get_count - 1U] = key;
    }
    if (s_fail_get_call == s_get_count) {
        return ESP_FAIL;
    }
    nvs_slot_t *slot = slot_for_key(key);
    if (handle != 1U || slot == NULL || length == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    if (!slot->present) {
        return ESP_ERR_NVS_NOT_FOUND;
    }
    if (out_value == NULL || *length < slot->size) {
        *length = slot->size;
        return ESP_ERR_INVALID_SIZE;
    }
    if (s_override_get_call == s_get_count) {
        memcpy(out_value, &s_get_override, sizeof(s_get_override));
    } else {
        memcpy(out_value, slot->bytes, slot->size);
    }
    *length = slot->size;
    return ESP_OK;
}

esp_err_t nvs_set_blob(nvs_handle_t handle, const char *key, const void *value, size_t length)
{
    nvs_slot_t *slot = slot_for_key(key);
    if (handle != 1U || slot == NULL || value == NULL || length != sizeof(pm_command_ledger_t)) {
        return ESP_ERR_INVALID_ARG;
    }
    memcpy(slot->bytes, value, length);
    slot->size = length;
    slot->present = true;
    return ESP_OK;
}

esp_err_t nvs_commit(nvs_handle_t handle)
{
    if (handle != 1U) {
        return ESP_ERR_INVALID_ARG;
    }
    s_commit_count++;
    return s_commit_fails ? ESP_FAIL : ESP_OK;
}

uint32_t pm_crc32_ieee(const void *data, size_t length)
{
    const uint8_t *bytes = (const uint8_t *)data;
    uint32_t crc = UINT32_C(0xFFFFFFFF);
    for (size_t index = 0U; index < length; ++index) {
        crc ^= bytes[index];
        for (unsigned int bit = 0U; bit < 8U; ++bit) {
            crc = (crc >> 1U) ^ (UINT32_C(0xEDB88320) & (uint32_t)-(int32_t)(crc & 1U));
        }
    }
    return ~crc;
}

void pm_sha256(const uint8_t *data, size_t length, uint8_t digest[PM_SHA256_SIZE])
{
    uint8_t combined = 0U;
    for (size_t index = 0U; index < length; ++index) {
        combined ^= data[index];
    }
    memset(digest, combined, PM_SHA256_SIZE);
}

bool pm_constant_time_equal(const uint8_t *left, const uint8_t *right, size_t length)
{
    uint8_t difference = 0U;
    for (size_t index = 0U; index < length; ++index) {
        difference |= left[index] ^ right[index];
    }
    return difference == 0U;
}

static void reset_nvs(void)
{
    memset(&s_slot_a, 0, sizeof(s_slot_a));
    memset(&s_slot_b, 0, sizeof(s_slot_b));
    s_open_fails = false;
    s_commit_fails = false;
    s_commit_count = 0U;
    s_get_count = 0U;
    s_fail_get_call = 0U;
    s_override_get_call = 0U;
    s_test_mutex_depth = 0U;
    s_test_mutex_max_depth = 0U;
    memset(&s_get_override, 0, sizeof(s_get_override));
    for (size_t index = 0U; index < 8U; ++index) {
        s_get_keys[index] = NULL;
    }
}

static pm_command_ledger_t ledger_with_generation(uint32_t generation, uint8_t next)
{
    pm_command_ledger_t ledger = {0};
    ledger.generation = generation;
    ledger.next = next;
    ledger.crc32 = pm_crc32_ieee(&ledger, offsetof(pm_command_ledger_t, crc32));
    return ledger;
}

static void put_slot(const char *key, const pm_command_ledger_t *ledger)
{
    nvs_slot_t *slot = slot_for_key(key);
    memcpy(slot->bytes, ledger, sizeof(*ledger));
    slot->size = sizeof(*ledger);
    slot->present = true;
}

static int test_newer_valid_slot_wins(void)
{
    reset_nvs();
    const pm_command_ledger_t a = ledger_with_generation(7U, 1U);
    const pm_command_ledger_t b = ledger_with_generation(8U, 2U);
    put_slot("slot_a", &a);
    put_slot("slot_b", &b);
    pm_command_ledger_t loaded = {0};
    CHECK(pm_commands_load(&loaded) == ESP_OK);
    CHECK(memcmp(&loaded, &b, sizeof(loaded)) == 0);
    CHECK(s_get_count == 5U);
    CHECK(strcmp(s_get_keys[4], "slot_b") == 0);

    reset_nvs();
    put_slot("slot_a", &b);
    put_slot("slot_b", &a);
    memset(&loaded, 0, sizeof(loaded));
    CHECK(pm_commands_load(&loaded) == ESP_OK);
    CHECK(memcmp(&loaded, &b, sizeof(loaded)) == 0);
    CHECK(s_get_count == 5U);
    CHECK(strcmp(s_get_keys[4], "slot_a") == 0);
    return 0;
}

static int test_generation_tie_with_different_content_fails_closed(void)
{
    reset_nvs();
    const pm_command_ledger_t a = ledger_with_generation(4U, 3U);
    const pm_command_ledger_t b = ledger_with_generation(4U, 5U);
    put_slot("slot_a", &a);
    put_slot("slot_b", &b);
    pm_command_ledger_t loaded = {0};
    memset(&loaded, 0xA5, sizeof(loaded));
    CHECK(pm_commands_load(&loaded) == ESP_ERR_INVALID_STATE);
    const pm_command_ledger_t empty = {0};
    CHECK(memcmp(&loaded, &empty, sizeof(loaded)) == 0);
    CHECK(s_get_count == 2U);
    CHECK(s_commit_count == 0U);
    return 0;
}

static int test_generation_tie_with_identical_content_selects_slot_a(void)
{
    reset_nvs();
    const pm_command_ledger_t a = ledger_with_generation(4U, 3U);
    put_slot("slot_a", &a);
    put_slot("slot_b", &a);
    pm_command_ledger_t loaded = {0};
    CHECK(pm_commands_load(&loaded) == ESP_OK);
    CHECK(memcmp(&loaded, &a, sizeof(loaded)) == 0);
    CHECK(s_get_count == 5U);
    CHECK(strcmp(s_get_keys[4], "slot_a") == 0);
    return 0;
}

static int test_corrupt_slot_falls_back(void)
{
    reset_nvs();
    const pm_command_ledger_t a = ledger_with_generation(9U, 1U);
    pm_command_ledger_t corrupt_b = ledger_with_generation(10U, 2U);
    corrupt_b.crc32 ^= 1U;
    put_slot("slot_a", &a);
    put_slot("slot_b", &corrupt_b);
    pm_command_ledger_t loaded = {0};
    CHECK(pm_commands_load(&loaded) == ESP_OK);
    CHECK(memcmp(&loaded, &a, sizeof(loaded)) == 0);
    CHECK(s_get_count == 5U);
    CHECK(strcmp(s_get_keys[4], "slot_a") == 0);

    reset_nvs();
    pm_command_ledger_t corrupt_a = ledger_with_generation(10U, 2U);
    const pm_command_ledger_t b = ledger_with_generation(9U, 1U);
    corrupt_a.crc32 ^= 1U;
    put_slot("slot_a", &corrupt_a);
    put_slot("slot_b", &b);
    memset(&loaded, 0, sizeof(loaded));
    CHECK(pm_commands_load(&loaded) == ESP_OK);
    CHECK(memcmp(&loaded, &b, sizeof(loaded)) == 0);
    CHECK(s_get_count == 5U);
    CHECK(strcmp(s_get_keys[4], "slot_b") == 0);
    return 0;
}

static int test_selected_slot_reload_failure_fails_closed(void)
{
    reset_nvs();
    const pm_command_ledger_t a = ledger_with_generation(7U, 1U);
    const pm_command_ledger_t b = ledger_with_generation(8U, 2U);
    put_slot("slot_a", &a);
    put_slot("slot_b", &b);
    s_fail_get_call = 5U;
    pm_command_ledger_t loaded;
    memset(&loaded, 0xA5, sizeof(loaded));
    CHECK(pm_commands_load(&loaded) == ESP_FAIL);
    const pm_command_ledger_t empty = {0};
    CHECK(memcmp(&loaded, &empty, sizeof(loaded)) == 0);
    CHECK(s_commit_count == 0U);
    CHECK(strcmp(s_get_keys[4], "slot_b") == 0);
    return 0;
}

static int test_selected_slot_generation_change_fails_closed(void)
{
    reset_nvs();
    const pm_command_ledger_t a = ledger_with_generation(7U, 1U);
    const pm_command_ledger_t b = ledger_with_generation(8U, 2U);
    put_slot("slot_a", &a);
    put_slot("slot_b", &b);
    s_override_get_call = 5U;
    s_get_override = ledger_with_generation(6U, 3U);
    pm_command_ledger_t loaded;
    memset(&loaded, 0xA5, sizeof(loaded));
    CHECK(pm_commands_load(&loaded) == ESP_ERR_INVALID_STATE);
    const pm_command_ledger_t empty = {0};
    CHECK(memcmp(&loaded, &empty, sizeof(loaded)) == 0);
    CHECK(s_commit_count == 0U);
    CHECK(strcmp(s_get_keys[4], "slot_b") == 0);
    return 0;
}

static int test_same_generation_content_change_fails_closed(void)
{
    reset_nvs();
    const pm_command_ledger_t a = ledger_with_generation(7U, 1U);
    const pm_command_ledger_t b = ledger_with_generation(8U, 2U);
    put_slot("slot_a", &a);
    put_slot("slot_b", &b);
    s_override_get_call = 5U;
    s_get_override = ledger_with_generation(8U, 6U);
    pm_command_ledger_t loaded;
    memset(&loaded, 0xA5, sizeof(loaded));
    CHECK(pm_commands_load(&loaded) == ESP_ERR_INVALID_STATE);
    const pm_command_ledger_t empty = {0};
    CHECK(memcmp(&loaded, &empty, sizeof(loaded)) == 0);
    CHECK(s_commit_count == 0U);
    return 0;
}

static int test_unselected_slot_change_during_rescan_fails_closed(void)
{
    reset_nvs();
    const pm_command_ledger_t a = ledger_with_generation(7U, 1U);
    const pm_command_ledger_t b = ledger_with_generation(8U, 2U);
    put_slot("slot_a", &a);
    put_slot("slot_b", &b);
    s_override_get_call = 3U;
    s_get_override = ledger_with_generation(9U, 4U);
    pm_command_ledger_t loaded;
    memset(&loaded, 0xA5, sizeof(loaded));
    CHECK(pm_commands_load(&loaded) == ESP_ERR_INVALID_STATE);
    const pm_command_ledger_t empty = {0};
    CHECK(memcmp(&loaded, &empty, sizeof(loaded)) == 0);
    CHECK(s_commit_count == 0U);
    return 0;
}

static int test_transient_slot_read_does_not_initialize_empty(void)
{
    reset_nvs();
    s_fail_get_call = 2U;
    pm_command_ledger_t loaded;
    memset(&loaded, 0xA5, sizeof(loaded));
    CHECK(pm_commands_load(&loaded) == ESP_FAIL);
    const pm_command_ledger_t empty = {0};
    CHECK(memcmp(&loaded, &empty, sizeof(loaded)) == 0);
    CHECK(s_commit_count == 0U);
    CHECK(!s_slot_a.present);
    CHECK(!s_slot_b.present);
    return 0;
}

static int test_corrupt_only_slot_does_not_initialize_empty(void)
{
    reset_nvs();
    pm_command_ledger_t corrupt = ledger_with_generation(3U, 1U);
    corrupt.crc32 ^= 1U;
    put_slot("slot_a", &corrupt);
    pm_command_ledger_t loaded;
    memset(&loaded, 0xA5, sizeof(loaded));
    CHECK(pm_commands_load(&loaded) == ESP_ERR_INVALID_CRC);
    const pm_command_ledger_t empty = {0};
    CHECK(memcmp(&loaded, &empty, sizeof(loaded)) == 0);
    CHECK(s_commit_count == 0U);
    return 0;
}

static int test_missing_slots_initialize_slot_a(void)
{
    reset_nvs();
    pm_command_ledger_t loaded;
    memset(&loaded, 0xA5, sizeof(loaded));
    CHECK(pm_commands_load(&loaded) == ESP_OK);
    CHECK(loaded.generation == 1U);
    CHECK(loaded.next == 0U);
    CHECK(loaded.crc32 == pm_crc32_ieee(&loaded, offsetof(pm_command_ledger_t, crc32)));
    CHECK(s_commit_count == 1U);
    CHECK(s_slot_a.present);
    CHECK(!s_slot_b.present);
    CHECK(memcmp(s_slot_a.bytes, &loaded, sizeof(loaded)) == 0);
    CHECK(s_get_count == 2U);
    return 0;
}

static int test_open_failure_preserves_caller(void)
{
    reset_nvs();
    s_open_fails = true;
    pm_command_ledger_t loaded;
    memset(&loaded, 0x5A, sizeof(loaded));
    pm_command_ledger_t before = loaded;
    CHECK(pm_commands_load(&loaded) == ESP_FAIL);
    CHECK(memcmp(&loaded, &before, sizeof(loaded)) == 0);
    return 0;
}

static pm_command_t incoming_command(void)
{
    pm_command_t command = {0};
    (void)snprintf(command.command_id, sizeof(command.command_id), "123e4567-e89b-42d3-a456-426614174000");
    (void)snprintf(command.idempotency_key, sizeof(command.idempotency_key), "test-command-1");
    (void)snprintf(command.payload, sizeof(command.payload), "{\"secret\":\"temporary\"}");
    command.type = PM_COMMAND_DIAGNOSTICS_SNAPSHOT;
    command.expires_utc_ms = INT64_C(2000000000000);
    return command;
}

static int load_and_accept(pm_command_ledger_t *ledger, pm_command_t **stored)
{
    CHECK(pm_commands_load(ledger) == ESP_OK);
    pm_command_t incoming = incoming_command();
    bool duplicate = false;
    CHECK(pm_command_accept(ledger, &incoming, INT64_C(1700000000000), stored, &duplicate) == ESP_OK);
    CHECK(!duplicate);
    return 0;
}

static int test_transition_commit_failure_restores_ram(void)
{
    reset_nvs();
    pm_command_ledger_t ledger = {0};
    pm_command_t *stored = NULL;
    CHECK(load_and_accept(&ledger, &stored) == 0);
    const pm_command_ledger_t before = ledger;
    s_commit_fails = true;
    CHECK(pm_command_transition(&ledger, stored, PM_COMMAND_RUNNING, 1U, ESP_OK) == ESP_FAIL);
    CHECK(memcmp(&ledger, &before, sizeof(ledger)) == 0);
    return 0;
}

static int test_ack_commit_failure_restores_ram(void)
{
    reset_nvs();
    pm_command_ledger_t ledger = {0};
    pm_command_t *stored = NULL;
    CHECK(load_and_accept(&ledger, &stored) == 0);
    stored->result_ack_required = true;
    CHECK(pm_command_transition(&ledger, stored, PM_COMMAND_SUCCEEDED, 100U, ESP_OK) == ESP_OK);
    const pm_command_ledger_t before = ledger;
    s_commit_fails = true;
    CHECK(pm_command_acknowledge_result(&ledger, stored->command_id) == ESP_FAIL);
    CHECK(memcmp(&ledger, &before, sizeof(ledger)) == 0);
    return 0;
}

static int test_zeroize_commit_failure_never_restores_plaintext(void)
{
    reset_nvs();
    pm_command_ledger_t ledger = {0};
    pm_command_t *stored = NULL;
    CHECK(load_and_accept(&ledger, &stored) == 0);
    s_commit_fails = true;
    CHECK(pm_command_zeroize_payload(&ledger, stored) == ESP_FAIL);
    CHECK(stored->payload_redacted);
    for (size_t index = 0U; index < sizeof(stored->payload); ++index) {
        CHECK(stored->payload[index] == '\0');
    }
    s_commit_fails = false;
    CHECK(pm_command_zeroize_payload(&ledger, stored) == ESP_OK);
    return 0;
}

static int test_caller_held_recursive_lock_does_not_deadlock(void)
{
    reset_nvs();
    pm_command_ledger_t ledger = {0};
    pm_command_t *stored = NULL;
    CHECK(load_and_accept(&ledger, &stored) == 0);
    CHECK(pm_commands_lock() == ESP_OK);
    CHECK(pm_command_transition(&ledger, stored, PM_COMMAND_RUNNING, 1U, ESP_OK) == ESP_OK);
    pm_commands_unlock();
    CHECK(s_test_mutex_depth == 0U);
    CHECK(s_test_mutex_max_depth >= 2U);
    return 0;
}

static int test_generation_exhaustion_fails_without_write_or_wrap(void)
{
    reset_nvs();
    pm_command_ledger_t ledger = ledger_with_generation(UINT32_MAX, 0U);
    pm_command_t *stored = NULL;
    pm_command_t incoming = incoming_command();
    bool duplicate = false;
    const pm_command_ledger_t before = ledger;
    CHECK(pm_command_accept(&ledger, &incoming, 1, &stored, &duplicate) == ESP_ERR_INVALID_STATE);
    CHECK(memcmp(&ledger, &before, sizeof(ledger)) == 0);
    CHECK(s_commit_count == 0U);
    CHECK(!s_slot_a.present && !s_slot_b.present);
    return 0;
}

static int test_boot_action_state_type_matrix(void)
{
    pm_command_t command = {0};
    static const pm_command_type_t replayable[] = {
        PM_COMMAND_DIAGNOSTICS_SNAPSHOT,
        PM_COMMAND_NETWORK_SELF_TEST,
        PM_COMMAND_METER_SELF_TEST,
    };
    for (size_t state_index = 0U; state_index < 2U; ++state_index) {
        command.state = state_index == 0U ? PM_COMMAND_ACCEPTED : PM_COMMAND_RUNNING;
        for (size_t type = 0U; type < PM_COMMAND_TYPE_COUNT; ++type) {
            command.type = (pm_command_type_t)type;
            pm_command_boot_action_t expected = PM_COMMAND_BOOT_FAIL_INTERRUPTED;
            for (size_t replay = 0U; replay < sizeof(replayable) / sizeof(replayable[0]); ++replay) {
                if (command.type == replayable[replay]) {
                    expected = PM_COMMAND_BOOT_REQUEUE;
                }
            }
            if (command.state == PM_COMMAND_RUNNING && command.type == PM_COMMAND_OTA_INSTALL) {
                expected = PM_COMMAND_BOOT_RECONCILE_OTA;
            }
            CHECK(pm_command_boot_action(&command) == expected);
        }
    }
    command.state = PM_COMMAND_AWAITING_REBOOT;
    command.type = PM_COMMAND_REBOOT;
    CHECK(pm_command_boot_action(&command) == PM_COMMAND_BOOT_COMPLETE_REBOOT);
    command.type = PM_COMMAND_OTA_INSTALL;
    CHECK(pm_command_boot_action(&command) == PM_COMMAND_BOOT_RECONCILE_OTA);
    command.type = PM_COMMAND_RESERVED_1;
    CHECK(pm_command_boot_action(&command) == PM_COMMAND_BOOT_FAIL_INTERRUPTED);
    command.state = PM_COMMAND_AWAITING_HEARTBEAT;
    command.type = PM_COMMAND_REBOOT;
    CHECK(pm_command_boot_action(&command) == PM_COMMAND_BOOT_FAIL_INTERRUPTED);
    command.state = PM_COMMAND_SUCCEEDED;
    CHECK(pm_command_boot_action(&command) == PM_COMMAND_BOOT_IGNORE);
    return 0;
}

static int test_boot_reconcile_is_durable_and_rolls_back_on_failure(void)
{
    reset_nvs();
    pm_command_ledger_t ledger = {0};
    pm_command_t *stored = NULL;
    CHECK(load_and_accept(&ledger, &stored) == 0);
    CHECK(pm_command_transition(&ledger, stored, PM_COMMAND_RUNNING, 9U, ESP_OK) == ESP_OK);
    CHECK(pm_command_reconcile_boot(&ledger, stored, PM_COMMAND_FAILED,
                                    ESP_ERR_INVALID_STATE, "interrupted_by_reboot") == ESP_OK);
    CHECK(stored->state == PM_COMMAND_FAILED);
    CHECK(stored->progress_percent == 9U);
    CHECK(strcmp(stored->result_text, "interrupted_by_reboot") == 0);

    reset_nvs();
    memset(&ledger, 0, sizeof(ledger));
    stored = NULL;
    CHECK(load_and_accept(&ledger, &stored) == 0);
    const pm_command_ledger_t before = ledger;
    s_commit_fails = true;
    CHECK(pm_command_reconcile_boot(&ledger, stored, PM_COMMAND_SUCCEEDED,
                                    ESP_OK, "reboot_observed") == ESP_FAIL);
    CHECK(memcmp(&ledger, &before, sizeof(ledger)) == 0);
    return 0;
}

int main(void)
{
    CHECK(test_newer_valid_slot_wins() == 0);
    CHECK(test_generation_tie_with_different_content_fails_closed() == 0);
    CHECK(test_generation_tie_with_identical_content_selects_slot_a() == 0);
    CHECK(test_corrupt_slot_falls_back() == 0);
    CHECK(test_selected_slot_reload_failure_fails_closed() == 0);
    CHECK(test_selected_slot_generation_change_fails_closed() == 0);
    CHECK(test_same_generation_content_change_fails_closed() == 0);
    CHECK(test_unselected_slot_change_during_rescan_fails_closed() == 0);
    CHECK(test_transient_slot_read_does_not_initialize_empty() == 0);
    CHECK(test_corrupt_only_slot_does_not_initialize_empty() == 0);
    CHECK(test_missing_slots_initialize_slot_a() == 0);
    CHECK(test_open_failure_preserves_caller() == 0);
    CHECK(test_transition_commit_failure_restores_ram() == 0);
    CHECK(test_ack_commit_failure_restores_ram() == 0);
    CHECK(test_zeroize_commit_failure_never_restores_plaintext() == 0);
    CHECK(test_caller_held_recursive_lock_does_not_deadlock() == 0);
    CHECK(test_generation_exhaustion_fails_without_write_or_wrap() == 0);
    CHECK(test_boot_action_state_type_matrix() == 0);
    CHECK(test_boot_reconcile_is_durable_and_rolls_back_on_failure() == 0);
    puts("pm_commands A/B load tests passed");
    return 0;
}
