#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "esp_err.h"
#include "pm_measurement.h"

#ifdef __cplusplus
extern "C" {
#endif

#define PM_JOURNAL_FORMAT_VERSION 1U
#define PM_JOURNAL_SEGMENT_MAGIC UINT32_C(0x504D5347) /* PMSG */
#define PM_JOURNAL_RECORD_MAGIC UINT32_C(0x504D5244)  /* PMRD */
#define PM_JOURNAL_SEGMENT_HEADER_SIZE 96U
#define PM_JOURNAL_RECORD_SIZE 128U
#define PM_SEQUENCE_RESERVATION_BLOCK 64U
#define PM_STORAGE_BATCH_MAX 16U

typedef enum {
    PM_STORAGE_UNINITIALIZED = 0,
    PM_STORAGE_READY,
    PM_STORAGE_MISSING,
    PM_STORAGE_READ_ONLY,
    PM_STORAGE_FULL,
    PM_STORAGE_CORRUPT,
    PM_STORAGE_IO_ERROR,
} pm_storage_status_t;

typedef struct {
    uint8_t device_id[16];
    uint8_t card_id[16];
    uint8_t segment_id[16];
    uint64_t first_sequence;
    int64_t created_utc_ms;
    int64_t created_monotonic_us;
    bool time_trusted;
} pm_segment_header_t;

typedef struct {
    uint8_t device_id[16];
    uint64_t sequence;
    uint32_t reset_generation;
    pm_durable_interval_t interval;
} pm_journal_record_t;

typedef struct {
    uint64_t next_sequence;
    uint64_t reserved_through;
    uint64_t maximum_seen;
    uint64_t acknowledged;
    uint32_t reset_generation;
    uint32_t generation;
} pm_sequence_state_t;

typedef struct {
    pm_storage_status_t status;
    uint8_t card_id[16];
    uint64_t oldest_sequence;
    uint64_t newest_sequence;
    uint64_t acknowledged_sequence;
    uint64_t unavailable_first;
    uint64_t unavailable_last;
    uint64_t bytes_total;
    uint64_t bytes_free;
    uint32_t corrupt_records;
    uint32_t quarantined_segments;
    bool read_only;
} pm_storage_health_t;

typedef struct {
    pm_journal_record_t records[PM_STORAGE_BATCH_MAX];
    size_t count;
    uint64_t after_sequence;
    bool more_available;
} pm_storage_batch_t;

typedef enum {
    PM_FORMAT_IDLE = 0,
    PM_FORMAT_PREPARED,
    PM_FORMAT_COMMITTING,
    PM_FORMAT_COMPLETE,
    PM_FORMAT_FAILED,
} pm_format_state_t;

typedef struct {
    uint8_t token[16];
    uint64_t acknowledged_records_lost;
    uint64_t unacknowledged_records_lost;
    uint64_t expires_monotonic_us;
    pm_format_state_t state;
} pm_format_transaction_t;

size_t pm_journal_encode_segment_header(const pm_segment_header_t *header, uint8_t *output, size_t capacity);
bool pm_journal_decode_segment_header(const uint8_t *data, size_t length, pm_segment_header_t *header);
size_t pm_journal_encode_record(const pm_journal_record_t *record, uint8_t *output, size_t capacity);
bool pm_journal_decode_record(const uint8_t *data, size_t length, pm_journal_record_t *record);

esp_err_t pm_sequence_load(pm_sequence_state_t *state);
esp_err_t pm_sequence_next(pm_sequence_state_t *state, uint64_t *sequence);
esp_err_t pm_sequence_acknowledge(pm_sequence_state_t *state, uint64_t acknowledged);
esp_err_t pm_sequence_raise_floor(pm_sequence_state_t *state, uint64_t floor, uint32_t reset_generation);

esp_err_t pm_storage_start(const uint8_t device_id[16], pm_storage_health_t *health);
esp_err_t pm_storage_append(const pm_journal_record_t *record, uint32_t timeout_ms);
esp_err_t pm_storage_read_batch(uint64_t after_sequence, pm_storage_batch_t *batch, uint32_t timeout_ms);
esp_err_t pm_storage_flush(uint32_t timeout_ms);
esp_err_t pm_storage_prepare_format(uint64_t now_us, uint64_t expires_us, const uint8_t token[16],
                                    pm_format_transaction_t *transaction);
esp_err_t pm_storage_commit_format(pm_format_transaction_t *transaction, const uint8_t token[16]);
/* Internal recovery primitive. The caller must first persist an authenticated,
 * token-zeroized destructive commit intent in the CRC A/B journal. */
esp_err_t pm_storage_recover_authenticated_format(void);
void pm_storage_cancel_format(pm_format_transaction_t *transaction);
esp_err_t pm_storage_rebuild_index(pm_storage_health_t *health);

#ifdef __cplusplus
}
#endif
