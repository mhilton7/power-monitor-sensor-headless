#include "pm_storage.h"

#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "driver/sdspi_host.h"
#include "driver/spi_common.h"
#include "esp_random.h"
#include "esp_timer.h"
#include "esp_vfs_fat.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/task.h"
#include "pm_board.h"
#include "sdmmc_cmd.h"

#define PM_STORAGE_QUEUE_DEPTH 16U
#define PM_STORAGE_TASK_STACK 6144U
#define PM_STORAGE_SEGMENT_LIMIT (1024U * 1024U)
#define PM_STORAGE_EMERGENCY_RESERVE (8U * 1024U * 1024U)
#define PM_JOURNAL_DIR PM_SD_MOUNT_POINT "/pmjournal"
#define PM_CURRENT_PATH PM_JOURNAL_DIR "/current.tmp"

typedef enum {
    STORAGE_MESSAGE_APPEND = 0,
    STORAGE_MESSAGE_FLUSH,
    STORAGE_MESSAGE_FORMAT,
    STORAGE_MESSAGE_RECOVER_AUTHENTICATED_FORMAT,
    STORAGE_MESSAGE_READ_BATCH,
    STORAGE_MESSAGE_REFRESH_INVENTORY,
} storage_message_type_t;

typedef struct {
    storage_message_type_t type;
    pm_journal_record_t record;
    TaskHandle_t caller;
    uint8_t format_token[16];
    uint64_t cursor;
    pm_storage_batch_t *batch;
} storage_message_t;

static QueueHandle_t s_queue;
static TaskHandle_t s_task;
static sdmmc_card_t *s_card;
static FILE *s_current;
static uint8_t s_device_id[16];
static pm_storage_health_t *s_health;
static uint64_t s_current_first;
static uint64_t s_current_last;
static size_t s_current_size;
static pm_format_transaction_t s_format;

static bool journal_path(char path[256], const char *name);

static bool all_zero(const uint8_t *bytes, size_t length)
{
    uint8_t combined = 0U;
    for (size_t i = 0U; i < length; ++i) {
        combined |= bytes[i];
    }
    return combined == 0U;
}

static esp_err_t sync_file(FILE *file)
{
    return file != NULL && fflush(file) == 0 && fsync(fileno(file)) == 0 ? ESP_OK : ESP_FAIL;
}

static esp_err_t update_capacity(void)
{
    if (s_health == NULL) {
        return ESP_ERR_INVALID_STATE;
    }
    uint64_t bytes_total = 0U;
    uint64_t bytes_free = 0U;
    const esp_err_t error = esp_vfs_fat_info(PM_SD_MOUNT_POINT, &bytes_total, &bytes_free);
    if (error != ESP_OK || bytes_total == 0U || bytes_free > bytes_total) {
        return error == ESP_OK ? ESP_ERR_INVALID_SIZE : error;
    }
    s_health->bytes_total = bytes_total;
    s_health->bytes_free = bytes_free;
    return ESP_OK;
}

static esp_err_t refresh_capacity(void)
{
    const esp_err_t error = update_capacity();
    if (error == ESP_OK && s_health->status == PM_STORAGE_FULL &&
        s_health->bytes_free >= PM_STORAGE_EMERGENCY_RESERVE) {
        /* A previous ENOSPC/no-reclaim condition is not permanent. Re-admit
         * writes only after the mounted FAT filesystem reports the complete
         * emergency reserve again. */
        s_health->status = PM_STORAGE_READY;
    }
    return error;
}

static esp_err_t card_identity(void)
{
    char path[128];
    (void)snprintf(path, sizeof(path), "%s/card.id", PM_JOURNAL_DIR);
    FILE *file = fopen(path, "rb");
    if (file != NULL) {
        const size_t read = fread(s_health->card_id, 1U, sizeof(s_health->card_id), file);
        fclose(file);
        if (read == sizeof(s_health->card_id) && !all_zero(s_health->card_id, sizeof(s_health->card_id))) {
            return ESP_OK;
        }
        return ESP_ERR_INVALID_CRC;
    }
    esp_fill_random(s_health->card_id, sizeof(s_health->card_id));
    char temporary[128];
    (void)snprintf(temporary, sizeof(temporary), "%s/card.id.new", PM_JOURNAL_DIR);
    file = fopen(temporary, "wb");
    if (file == NULL || fwrite(s_health->card_id, 1U, sizeof(s_health->card_id), file) != sizeof(s_health->card_id) ||
        sync_file(file) != ESP_OK) {
        if (file != NULL) {
            fclose(file);
        }
        return ESP_FAIL;
    }
    fclose(file);
    return rename(temporary, path) == 0 ? ESP_OK : ESP_FAIL;
}

static esp_err_t storage_self_test(void)
{
    char source[128];
    char target[128];
    (void)snprintf(source, sizeof(source), "%s/selftest.new", PM_JOURNAL_DIR);
    (void)snprintf(target, sizeof(target), "%s/selftest.ok", PM_JOURNAL_DIR);
    static const uint8_t evidence[] = {0x50U, 0x4DU, 0x53U, 0x44U, 0x01U};
    FILE *file = fopen(source, "wb");
    if (file == NULL || fwrite(evidence, 1U, sizeof(evidence), file) != sizeof(evidence) || sync_file(file) != ESP_OK) {
        if (file != NULL) {
            fclose(file);
        }
        return ESP_FAIL;
    }
    fclose(file);
    if (rename(source, target) != 0) {
        return ESP_FAIL;
    }
    uint8_t readback[sizeof(evidence)] = {0};
    file = fopen(target, "rb");
    const bool valid = file != NULL && fread(readback, 1U, sizeof(readback), file) == sizeof(readback) &&
                       memcmp(readback, evidence, sizeof(evidence)) == 0;
    if (file != NULL) {
        fclose(file);
    }
    (void)unlink(target);
    return valid ? ESP_OK : ESP_ERR_INVALID_CRC;
}

static esp_err_t mount_card(void)
{
    const spi_bus_config_t bus = {
        .mosi_io_num = PM_SD_MOSI,
        .miso_io_num = PM_SD_MISO,
        .sclk_io_num = PM_SD_SCK,
        .quadwp_io_num = -1,
        .quadhd_io_num = -1,
        .data4_io_num = -1,
        .data5_io_num = -1,
        .data6_io_num = -1,
        .data7_io_num = -1,
        .max_transfer_sz = 4096,
        .flags = 0,
        .isr_cpu_id = ESP_INTR_CPU_AFFINITY_AUTO,
        .intr_flags = 0,
    };
    esp_err_t error = spi_bus_initialize(PM_SD_SPI_HOST, &bus, SPI_DMA_CH_AUTO);
    if (error != ESP_OK && error != ESP_ERR_INVALID_STATE) {
        return error;
    }
    sdmmc_host_t host = SDSPI_HOST_DEFAULT();
    host.slot = PM_SD_SPI_HOST;
    host.max_freq_khz = CONFIG_PM_SD_SPI_KHZ;
    const sdspi_device_config_t slot = {
        .host_id = PM_SD_SPI_HOST,
        .gpio_cs = PM_SD_CS,
        .gpio_cd = SDSPI_SLOT_NO_CD,
        .gpio_wp = SDSPI_SLOT_NO_WP,
        .gpio_int = GPIO_NUM_NC,
    };
    const esp_vfs_fat_mount_config_t mount = {
        .format_if_mount_failed = false,
        .max_files = 6,
        .allocation_unit_size = 16U * 1024U,
        .disk_status_check_enable = true,
        .use_one_fat = false,
    };
    error = esp_vfs_fat_sdspi_mount(PM_SD_MOUNT_POINT, &host, &slot, &mount, &s_card);
    if (error != ESP_OK) {
        return error;
    }
    if (mkdir(PM_JOURNAL_DIR, 0750) != 0 && errno != EEXIST) {
        return ESP_FAIL;
    }
    error = card_identity();
    if (error == ESP_OK) {
        error = storage_self_test();
    }
    if (error == ESP_OK) {
        error = update_capacity();
    }
    return error;
}

static esp_err_t open_current(const pm_journal_record_t *record)
{
    s_current = fopen(PM_CURRENT_PATH, "ab+");
    if (s_current == NULL) {
        return ESP_FAIL;
    }
    if (fseek(s_current, 0, SEEK_END) != 0) {
        return ESP_FAIL;
    }
    const long end = ftell(s_current);
    if (end < 0) {
        return ESP_FAIL;
    }
    s_current_size = (size_t)end;
    if (s_current_size == 0U) {
        pm_segment_header_t header = {
            .first_sequence = record->sequence,
            .created_utc_ms = record->interval.start_utc_ms,
            .created_monotonic_us = record->interval.start_monotonic_us,
            .time_trusted = (record->interval.flags & PM_INTERVAL_FLAG_TIME_UNTRUSTED) == 0U,
        };
        memcpy(header.device_id, s_device_id, sizeof(header.device_id));
        memcpy(header.card_id, s_health->card_id, sizeof(header.card_id));
        esp_fill_random(header.segment_id, sizeof(header.segment_id));
        uint8_t encoded[PM_JOURNAL_SEGMENT_HEADER_SIZE];
        if (pm_journal_encode_segment_header(&header, encoded, sizeof(encoded)) != sizeof(encoded) ||
            fwrite(encoded, 1U, sizeof(encoded), s_current) != sizeof(encoded) || sync_file(s_current) != ESP_OK) {
            return ESP_FAIL;
        }
        s_current_size = sizeof(encoded);
        s_current_first = record->sequence;
    }
    return ESP_OK;
}

static esp_err_t rotate_current(void)
{
    if (s_current == NULL) {
        return ESP_OK;
    }
    const esp_err_t error = sync_file(s_current);
    fclose(s_current);
    s_current = NULL;
    if (error != ESP_OK || s_current_last == 0U) {
        return error;
    }
    char sealed[160];
    (void)snprintf(sealed, sizeof(sealed), "%s/seg_%020llu_%020llu.bin", PM_JOURNAL_DIR,
                   (unsigned long long)s_current_first, (unsigned long long)s_current_last);
    if (rename(PM_CURRENT_PATH, sealed) != 0) {
        return ESP_FAIL;
    }
    s_current_first = 0U;
    s_current_last = 0U;
    s_current_size = 0U;
    return ESP_OK;
}

static esp_err_t reclaim_acknowledged_segments(void)
{
    esp_err_t error = update_capacity();
    if (error != ESP_OK) {
        return error;
    }
    while (s_health->bytes_free < PM_STORAGE_EMERGENCY_RESERVE) {
        DIR *directory = opendir(PM_JOURNAL_DIR);
        if (directory == NULL) {
            return ESP_FAIL;
        }
        uint64_t oldest_first = UINT64_MAX;
        char reclaim_name[128] = {0};
        struct dirent *entry = NULL;
        while ((entry = readdir(directory)) != NULL) {
            unsigned long long first = 0U;
            unsigned long long last = 0U;
            char trailing = '\0';
            if (sscanf(entry->d_name, "seg_%20llu_%20llu.bin%c", &first, &last, &trailing) == 2 &&
                (uint64_t)last <= s_health->acknowledged_sequence && (uint64_t)first < oldest_first &&
                strlen(entry->d_name) < sizeof(reclaim_name)) {
                oldest_first = (uint64_t)first;
                const size_t name_length = strlen(entry->d_name);
                memcpy(reclaim_name, entry->d_name, name_length + 1U);
            }
        }
        closedir(directory);
        if (reclaim_name[0] == '\0') {
            return ESP_ERR_NO_MEM;
        }
        char path[256];
        if (!journal_path(path, reclaim_name) || unlink(path) != 0) {
            return ESP_FAIL;
        }
        error = update_capacity();
        if (error != ESP_OK) {
            return error;
        }
    }
    s_health->oldest_sequence = 0U;
    s_health->newest_sequence = 0U;
    return pm_storage_rebuild_index(s_health);
}

static esp_err_t append_record(const pm_journal_record_t *record)
{
    if (s_health == NULL || s_health->status != PM_STORAGE_READY) {
        return ESP_ERR_INVALID_STATE;
    }
    if (s_health->bytes_free < PM_STORAGE_EMERGENCY_RESERVE) {
        const esp_err_t error = reclaim_acknowledged_segments();
        if (error != ESP_OK) {
            s_health->status = error == ESP_ERR_NO_MEM ? PM_STORAGE_FULL : PM_STORAGE_IO_ERROR;
            return error;
        }
    }
    if (s_current == NULL) {
        const esp_err_t error = open_current(record);
        if (error != ESP_OK) {
            s_health->status = PM_STORAGE_IO_ERROR;
            return error;
        }
    }
    uint8_t encoded[PM_JOURNAL_RECORD_SIZE];
    if (pm_journal_encode_record(record, encoded, sizeof(encoded)) != sizeof(encoded) ||
        fwrite(encoded, 1U, sizeof(encoded), s_current) != sizeof(encoded) || sync_file(s_current) != ESP_OK) {
        s_health->status = errno == ENOSPC ? PM_STORAGE_FULL : PM_STORAGE_IO_ERROR;
        return ESP_FAIL;
    }
    s_current_size += sizeof(encoded);
    s_current_last = record->sequence;
    if (s_health->oldest_sequence == 0U || record->sequence < s_health->oldest_sequence) {
        s_health->oldest_sequence = record->sequence;
    }
    if (record->sequence > s_health->newest_sequence) {
        s_health->newest_sequence = record->sequence;
    }
    (void)update_capacity();
    return s_current_size >= PM_STORAGE_SEGMENT_LIMIT ? rotate_current() : ESP_OK;
}

static void insert_sorted(pm_storage_batch_t *batch, const pm_journal_record_t *record)
{
    if (record->sequence <= batch->after_sequence) {
        return;
    }
    size_t position = 0U;
    while (position < batch->count && batch->records[position].sequence < record->sequence) {
        position++;
    }
    if (position < batch->count && batch->records[position].sequence == record->sequence) {
        return;
    }
    if (batch->count == PM_STORAGE_BATCH_MAX && position == batch->count) {
        batch->more_available = true;
        return;
    }
    const size_t last = batch->count < PM_STORAGE_BATCH_MAX ? batch->count : PM_STORAGE_BATCH_MAX - 1U;
    for (size_t i = last; i > position; --i) {
        batch->records[i] = batch->records[i - 1U];
    }
    batch->records[position] = *record;
    if (batch->count < PM_STORAGE_BATCH_MAX) {
        batch->count++;
    } else {
        batch->more_available = true;
    }
}

static bool journal_path(char path[256], const char *name)
{
    const size_t directory_length = strlen(PM_JOURNAL_DIR);
    const size_t name_length = strlen(name);
    if (name_length == 0U || directory_length + 1U + name_length + 1U > 256U) {
        return false;
    }
    memcpy(path, PM_JOURNAL_DIR, directory_length);
    path[directory_length] = '/';
    memcpy(&path[directory_length + 1U], name, name_length + 1U);
    return true;
}

static void report_unavailable_range(pm_storage_health_t *health, uint64_t first, uint64_t last)
{
    if (health == NULL || first == 0U || last < first) {
        return;
    }
    if (health->unavailable_first == 0U || first < health->unavailable_first) {
        health->unavailable_first = first;
    }
    if (last > health->unavailable_last) {
        health->unavailable_last = last;
    }
}

static long next_valid_record(FILE *file, long start, long end, uint8_t bytes[PM_JOURNAL_RECORD_SIZE],
                              pm_journal_record_t *record)
{
    static const uint8_t magic[4] = {0x44U, 0x52U, 0x4DU, 0x50U};
    for (long offset = start; offset + (long)PM_JOURNAL_RECORD_SIZE <= end; ++offset) {
        if (fseek(file, offset, SEEK_SET) != 0 || fread(bytes, 1U, 4U, file) != 4U ||
            memcmp(bytes, magic, sizeof(magic)) != 0 || fseek(file, offset, SEEK_SET) != 0 ||
            fread(bytes, 1U, PM_JOURNAL_RECORD_SIZE, file) != PM_JOURNAL_RECORD_SIZE) {
            continue;
        }
        if (pm_journal_decode_record(bytes, PM_JOURNAL_RECORD_SIZE, record) &&
            memcmp(record->device_id, s_device_id, sizeof(s_device_id)) == 0) {
            return offset;
        }
    }
    return -1;
}

static esp_err_t scan_segment(FILE *file, pm_storage_batch_t *batch, pm_storage_health_t *health,
                              bool *corrupt)
{
    uint8_t header_bytes[PM_JOURNAL_SEGMENT_HEADER_SIZE];
    pm_segment_header_t header = {0};
    if (fseek(file, 0, SEEK_SET) != 0 || fread(header_bytes, 1U, sizeof(header_bytes), file) != sizeof(header_bytes) ||
        !pm_journal_decode_segment_header(header_bytes, sizeof(header_bytes), &header) ||
        memcmp(header.device_id, s_device_id, sizeof(s_device_id)) != 0 ||
        memcmp(header.card_id, s_health->card_id, sizeof(header.card_id)) != 0 ||
        fseek(file, 0, SEEK_END) != 0) {
        if (corrupt != NULL) {
            *corrupt = true;
        }
        return ESP_ERR_INVALID_CRC;
    }
    const long end = ftell(file);
    if (end < (long)PM_JOURNAL_SEGMENT_HEADER_SIZE) {
        return ESP_ERR_INVALID_SIZE;
    }
    long offset = (long)PM_JOURNAL_SEGMENT_HEADER_SIZE;
    uint64_t expected = header.first_sequence;
    uint8_t bytes[PM_JOURNAL_RECORD_SIZE];
    while (offset + (long)sizeof(bytes) <= end) {
        pm_journal_record_t record = {0};
        if (fseek(file, offset, SEEK_SET) != 0 || fread(bytes, 1U, sizeof(bytes), file) != sizeof(bytes) ||
            !pm_journal_decode_record(bytes, sizeof(bytes), &record) ||
            memcmp(record.device_id, s_device_id, sizeof(s_device_id)) != 0 || record.sequence < expected) {
            if (corrupt != NULL) {
                *corrupt = true;
            }
            if (health != NULL) {
                health->corrupt_records++;
            }
            const long recovered = next_valid_record(file, offset + 1L, end, bytes, &record);
            if (recovered < 0) {
                return ESP_ERR_INVALID_CRC;
            }
            report_unavailable_range(health, expected, record.sequence > expected ? record.sequence - 1U : expected);
            offset = recovered;
            continue;
        }
        if (record.sequence > expected) {
            report_unavailable_range(health, expected, record.sequence - 1U);
        }
        if (health != NULL) {
            if (health->oldest_sequence == 0U || record.sequence < health->oldest_sequence) {
                health->oldest_sequence = record.sequence;
            }
            if (record.sequence > health->newest_sequence) {
                health->newest_sequence = record.sequence;
            }
        }
        if (batch != NULL) {
            insert_sorted(batch, &record);
        }
        expected = record.sequence == UINT64_MAX ? UINT64_MAX : record.sequence + 1U;
        offset += (long)sizeof(bytes);
    }
    if (ferror(file) != 0) {
        return ESP_FAIL;
    }
    if (offset != end) {
        if (corrupt != NULL) {
            *corrupt = true;
        }
        return ESP_ERR_INVALID_SIZE;
    }
    return ESP_OK;
}

static esp_err_t read_batch_owner(uint64_t cursor, pm_storage_batch_t *batch)
{
    if (batch == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    if (s_health == NULL || !s_health->inventory_complete ||
        (s_health->status != PM_STORAGE_READY && s_health->status != PM_STORAGE_FULL &&
         s_health->status != PM_STORAGE_READ_ONLY)) {
        return ESP_ERR_INVALID_STATE;
    }
    *batch = (pm_storage_batch_t){.after_sequence = cursor};
    DIR *directory = opendir(PM_JOURNAL_DIR);
    if (directory == NULL) {
        return ESP_FAIL;
    }
    esp_err_t result = ESP_OK;
    struct dirent *entry = NULL;
    for (;;) {
        errno = 0;
        entry = readdir(directory);
        if (entry == NULL) {
            if (errno != 0) {
                result = ESP_FAIL;
            }
            break;
        }
        if (strncmp(entry->d_name, "seg_", 4U) != 0 && strcmp(entry->d_name, "current.tmp") != 0 &&
            strncmp(entry->d_name, "quarantine_", 11U) != 0) {
            continue;
        }
        char path[256];
        if (!journal_path(path, entry->d_name)) {
            result = ESP_ERR_INVALID_SIZE;
            break;
        }
        FILE *file = fopen(path, "rb");
        if (file == NULL) {
            result = ESP_FAIL;
            break;
        }
        bool corrupt = false;
        result = scan_segment(file, batch, NULL, &corrupt);
        fclose(file);
        if (result != ESP_OK) {
            break;
        }
    }
    closedir(directory);
    if (result != ESP_OK) {
        s_health->inventory_complete = false;
        s_health->status = PM_STORAGE_IO_ERROR;
    }
    return result;
}

static esp_err_t recover_current(void)
{
    FILE *file = fopen(PM_CURRENT_PATH, "rb+");
    if (file == NULL) {
        return errno == ENOENT ? ESP_OK : ESP_FAIL;
    }
    uint8_t header_bytes[PM_JOURNAL_SEGMENT_HEADER_SIZE];
    pm_segment_header_t header = {0};
    if (fread(header_bytes, 1U, sizeof(header_bytes), file) != sizeof(header_bytes) ||
        !pm_journal_decode_segment_header(header_bytes, sizeof(header_bytes), &header) ||
        memcmp(header.device_id, s_device_id, sizeof(s_device_id)) != 0 ||
        memcmp(header.card_id, s_health->card_id, sizeof(header.card_id)) != 0) {
        fclose(file);
        char quarantine[160];
        (void)snprintf(quarantine, sizeof(quarantine), "%s/quarantine_header_%llu.bin", PM_JOURNAL_DIR,
                       (unsigned long long)xTaskGetTickCount());
        (void)rename(PM_CURRENT_PATH, quarantine);
        s_health->quarantined_segments++;
        return ESP_OK;
    }
    if (fseek(file, 0, SEEK_END) != 0) {
        fclose(file);
        return ESP_FAIL;
    }
    const long file_end = ftell(file);
    if (file_end < (long)sizeof(header_bytes)) {
        fclose(file);
        return ESP_ERR_INVALID_SIZE;
    }
    const long valid_end = (long)sizeof(header_bytes) +
                           ((file_end - (long)sizeof(header_bytes)) / (long)PM_JOURNAL_RECORD_SIZE) *
                               (long)PM_JOURNAL_RECORD_SIZE;
    if (valid_end != file_end && ftruncate(fileno(file), valid_end) != 0) {
        fclose(file);
        return ESP_FAIL;
    }
    if (fseek(file, (long)sizeof(header_bytes), SEEK_SET) != 0) {
        fclose(file);
        return ESP_FAIL;
    }
    uint8_t record_bytes[PM_JOURNAL_RECORD_SIZE];
    pm_journal_record_t record = {0};
    while (fread(record_bytes, 1U, sizeof(record_bytes), file) == sizeof(record_bytes)) {
        if (!pm_journal_decode_record(record_bytes, sizeof(record_bytes), &record) ||
            memcmp(record.device_id, s_device_id, sizeof(s_device_id)) != 0) {
            s_health->corrupt_records++;
            fclose(file);
            char quarantine[160];
            (void)snprintf(quarantine, sizeof(quarantine), "%s/quarantine_current_%llu.bin", PM_JOURNAL_DIR,
                           (unsigned long long)xTaskGetTickCount());
            (void)rename(PM_CURRENT_PATH, quarantine);
            s_health->quarantined_segments++;
            s_current_first = 0U;
            s_current_last = 0U;
            s_current_size = 0U;
            return ESP_OK;
        }
        s_current_last = record.sequence;
    }
    if (ferror(file) != 0) {
        fclose(file);
        return ESP_FAIL;
    }
    fclose(file);
    s_current_first = header.first_sequence;
    s_current_size = (size_t)valid_end;
    return ESP_OK;
}

esp_err_t pm_storage_rebuild_index(pm_storage_health_t *health)
{
    if (health == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    health->inventory_complete = false;
    pm_storage_health_t inventory = *health;
    inventory.oldest_sequence = 0U;
    inventory.newest_sequence = 0U;
    inventory.unavailable_first = 0U;
    inventory.unavailable_last = 0U;
    inventory.corrupt_records = 0U;
    inventory.quarantined_segments = 0U;
    inventory.inventory_scanned_files = 0U;
    inventory.inventory_complete = false;
    DIR *directory = opendir(PM_JOURNAL_DIR);
    if (directory == NULL) {
        return ESP_FAIL;
    }
    esp_err_t result = ESP_OK;
    struct dirent *entry = NULL;
    for (;;) {
        errno = 0;
        entry = readdir(directory);
        if (entry == NULL) {
            if (errno != 0) {
                result = ESP_FAIL;
            }
            break;
        }
        if (strncmp(entry->d_name, "seg_", 4U) != 0 && strcmp(entry->d_name, "current.tmp") != 0 &&
            strncmp(entry->d_name, "quarantine_", 11U) != 0) {
            continue;
        }
        char path[256];
        if (!journal_path(path, entry->d_name)) {
            result = ESP_ERR_INVALID_SIZE;
            break;
        }
        FILE *file = fopen(path, "rb");
        if (file == NULL) {
            result = ESP_FAIL;
            break;
        }
        bool corrupt = false;
        const esp_err_t scan_error = scan_segment(file, NULL, &inventory, &corrupt);
        inventory.inventory_scanned_files++;
        if (scan_error != ESP_OK || corrupt) {
            inventory.quarantined_segments++;
        }
        fclose(file);
        if (scan_error != ESP_OK) {
            result = scan_error;
            break;
        }
    }
    closedir(directory);
    if (result != ESP_OK) {
        return result;
    }
    health->oldest_sequence = inventory.oldest_sequence;
    health->newest_sequence = inventory.newest_sequence;
    health->unavailable_first = inventory.unavailable_first;
    health->unavailable_last = inventory.unavailable_last;
    health->corrupt_records = inventory.corrupt_records;
    health->quarantined_segments = inventory.quarantined_segments;
    health->inventory_scanned_files = inventory.inventory_scanned_files;
    health->inventory_complete = true;
    return ESP_OK;
}

static esp_err_t format_storage(const uint8_t token[16], bool authenticated_recovery)
{
    if (s_card == NULL ||
        (!authenticated_recovery &&
         (token == NULL || s_format.state != PM_FORMAT_PREPARED ||
          memcmp(s_format.token, token, sizeof(s_format.token)) != 0 ||
          (uint64_t)esp_timer_get_time() > s_format.expires_monotonic_us))) {
        return ESP_ERR_INVALID_STATE;
    }
    s_format.state = PM_FORMAT_COMMITTING;
    (void)rotate_current();
    esp_err_t error = esp_vfs_fat_sdcard_format(PM_SD_MOUNT_POINT, s_card);
    if (error == ESP_OK && mkdir(PM_JOURNAL_DIR, 0750) != 0 && errno != EEXIST) {
        error = ESP_FAIL;
    }
    if (error == ESP_OK) {
        memset(s_health->card_id, 0, sizeof(s_health->card_id));
        error = card_identity();
    }
    if (error == ESP_OK) {
        error = storage_self_test();
    }
    if (error == ESP_OK) {
        error = update_capacity();
    }
    s_format.state = error == ESP_OK ? PM_FORMAT_COMPLETE : PM_FORMAT_FAILED;
    if (error == ESP_OK) {
        const uint8_t saved_card[16] = {0};
        (void)saved_card;
        s_health->oldest_sequence = 0U;
        s_health->newest_sequence = 0U;
        s_health->corrupt_records = 0U;
        s_health->quarantined_segments = 0U;
        s_health->status = PM_STORAGE_READY;
    }
    return error;
}

static void storage_task(void *context)
{
    (void)context;
    int64_t last_capacity_refresh_us = esp_timer_get_time();
    for (;;) {
        storage_message_t message = {0};
        if (xQueueReceive(s_queue, &message, pdMS_TO_TICKS(1000)) != pdTRUE) {
            const int64_t now_us = esp_timer_get_time();
            if (now_us - last_capacity_refresh_us >= INT64_C(60000000)) {
                (void)refresh_capacity();
                last_capacity_refresh_us = now_us;
            }
            continue;
        }
        esp_err_t result = ESP_ERR_NOT_SUPPORTED;
        if (message.type == STORAGE_MESSAGE_APPEND) {
            result = append_record(&message.record);
        } else if (message.type == STORAGE_MESSAGE_FLUSH) {
            result = s_current == NULL ? ESP_OK : sync_file(s_current);
        } else if (message.type == STORAGE_MESSAGE_FORMAT) {
            result = format_storage(message.format_token, false);
        } else if (message.type == STORAGE_MESSAGE_RECOVER_AUTHENTICATED_FORMAT) {
            result = format_storage(NULL, true);
        } else if (message.type == STORAGE_MESSAGE_READ_BATCH) {
            result = read_batch_owner(message.cursor, message.batch);
        } else if (message.type == STORAGE_MESSAGE_REFRESH_INVENTORY) {
            result = pm_storage_rebuild_index(s_health);
            if (result != ESP_OK) {
                s_health->inventory_complete = false;
            }
        }
        if (message.caller != NULL) {
            (void)xTaskNotify(message.caller, (uint32_t)result, eSetValueWithOverwrite);
        }
    }
}

esp_err_t pm_storage_start(const uint8_t device_id[16], pm_storage_health_t *health)
{
    if (device_id == NULL || health == NULL || s_task != NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    memset(health, 0, sizeof(*health));
    s_health = health;
    memcpy(s_device_id, device_id, sizeof(s_device_id));
    esp_err_t error = mount_card();
    if (error != ESP_OK) {
        health->status = s_card == NULL ? PM_STORAGE_MISSING : PM_STORAGE_IO_ERROR;
        return error;
    }
    health->status = PM_STORAGE_READY;
    error = recover_current();
    if (error == ESP_OK) {
        error = pm_storage_rebuild_index(health);
    }
    if (error != ESP_OK) {
        health->status = PM_STORAGE_CORRUPT;
    } else {
        error = refresh_capacity();
        if (error != ESP_OK) {
            health->status = PM_STORAGE_IO_ERROR;
        }
    }
    s_queue = xQueueCreate(PM_STORAGE_QUEUE_DEPTH, sizeof(storage_message_t));
    if (s_queue == NULL || xTaskCreate(storage_task, "pm_storage", PM_STORAGE_TASK_STACK, NULL, 8U, &s_task) != pdPASS) {
        return ESP_ERR_NO_MEM;
    }
    return error;
}

static esp_err_t send_and_wait(storage_message_t *message, uint32_t timeout_ms)
{
    if (s_queue == NULL || message == NULL) {
        return ESP_ERR_INVALID_STATE;
    }
    message->caller = xTaskGetCurrentTaskHandle();
    (void)xTaskNotifyStateClear(message->caller);
    if (xQueueSend(s_queue, message, pdMS_TO_TICKS(timeout_ms)) != pdTRUE) {
        return ESP_ERR_TIMEOUT;
    }
    uint32_t result = (uint32_t)ESP_ERR_TIMEOUT;
    return xTaskNotifyWait(0U, UINT32_MAX, &result, pdMS_TO_TICKS(timeout_ms)) == pdTRUE ? (esp_err_t)result :
                                                                                         ESP_ERR_TIMEOUT;
}

esp_err_t pm_storage_append(const pm_journal_record_t *record, uint32_t timeout_ms)
{
    if (record == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    storage_message_t message = {.type = STORAGE_MESSAGE_APPEND, .record = *record};
    return send_and_wait(&message, timeout_ms);
}

esp_err_t pm_storage_flush(uint32_t timeout_ms)
{
    storage_message_t message = {.type = STORAGE_MESSAGE_FLUSH};
    return send_and_wait(&message, timeout_ms);
}

esp_err_t pm_storage_read_batch(uint64_t after_sequence, pm_storage_batch_t *batch, uint32_t timeout_ms)
{
    if (batch == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    storage_message_t message = {
        .type = STORAGE_MESSAGE_READ_BATCH,
        .cursor = after_sequence,
        .batch = batch,
    };
    return send_and_wait(&message, timeout_ms);
}

esp_err_t pm_storage_refresh_inventory(uint32_t timeout_ms)
{
    storage_message_t message = {.type = STORAGE_MESSAGE_REFRESH_INVENTORY};
    return send_and_wait(&message, timeout_ms);
}

esp_err_t pm_storage_prepare_format(uint64_t now_us, uint64_t expires_us, const uint8_t token[16],
                                    pm_format_transaction_t *transaction)
{
    if (transaction == NULL || token == NULL || expires_us <= now_us || s_health == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    memset(&s_format, 0, sizeof(s_format));
    memcpy(s_format.token, token, sizeof(s_format.token));
    s_format.acknowledged_records_lost = s_health->acknowledged_sequence >= s_health->oldest_sequence &&
                                                s_health->oldest_sequence != 0U
                                            ? s_health->acknowledged_sequence - s_health->oldest_sequence + 1U
                                            : 0U;
    s_format.unacknowledged_records_lost = s_health->newest_sequence > s_health->acknowledged_sequence
                                              ? s_health->newest_sequence - s_health->acknowledged_sequence
                                              : 0U;
    s_format.expires_monotonic_us = expires_us;
    s_format.state = PM_FORMAT_PREPARED;
    *transaction = s_format;
    return ESP_OK;
}

esp_err_t pm_storage_commit_format(pm_format_transaction_t *transaction, const uint8_t token[16])
{
    uint8_t difference = 0U;
    if (transaction != NULL && token != NULL) {
        for (size_t i = 0U; i < sizeof(transaction->token); ++i) {
            difference |= transaction->token[i] ^ token[i];
        }
    }
    if (transaction == NULL || token == NULL || transaction->state != PM_FORMAT_PREPARED || difference != 0U) {
        return ESP_ERR_INVALID_ARG;
    }
    storage_message_t message = {.type = STORAGE_MESSAGE_FORMAT};
    memcpy(message.format_token, token, sizeof(message.format_token));
    const esp_err_t error = send_and_wait(&message, 120000U);
    *transaction = s_format;
    return error;
}

esp_err_t pm_storage_recover_authenticated_format(void)
{
    storage_message_t message = {.type = STORAGE_MESSAGE_RECOVER_AUTHENTICATED_FORMAT};
    return send_and_wait(&message, 120000U);
}

void pm_storage_cancel_format(pm_format_transaction_t *transaction)
{
    memset(&s_format, 0, sizeof(s_format));
    if (transaction != NULL) {
        memset(transaction, 0, sizeof(*transaction));
    }
}
