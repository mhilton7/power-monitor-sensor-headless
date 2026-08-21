#!/usr/bin/env python3
"""Read-only decoder for retired, unbuilt PowerMeter V2 journal evidence."""
from __future__ import annotations

import argparse
import json
import struct
import sys
import uuid
import zlib
from pathlib import Path

HEADER_SIZE = 96
RECORD_SIZE = 128
HEADER_MAGIC = 0x504D5347
RECORD_MAGIC = 0x504D5244


def crc_valid(block: bytes) -> bool:
    return len(block) >= 4 and zlib.crc32(block[:-4]) & 0xFFFFFFFF == struct.unpack_from('<I', block, len(block) - 4)[0]


def decode_header(data: bytes) -> dict[str, object]:
    if len(data) != HEADER_SIZE or not crc_valid(data):
        raise ValueError('invalid segment header length or CRC')
    magic, version, length = struct.unpack_from('<IHH', data)
    if (magic, version, length) != (HEADER_MAGIC, 1, HEADER_SIZE):
        raise ValueError('unsupported segment header')
    return {
        'format': 'pm-journal/1',
        'device_id': str(uuid.UUID(bytes=data[8:24])),
        'card_id': str(uuid.UUID(bytes=data[24:40])),
        'segment_id': str(uuid.UUID(bytes=data[40:56])),
        'first_sequence': struct.unpack_from('<Q', data, 56)[0],
        'created_utc_ms': struct.unpack_from('<q', data, 64)[0],
        'created_monotonic_us': struct.unpack_from('<q', data, 72)[0],
        'time_trusted': bool(data[80]),
    }


def decode_record(data: bytes) -> dict[str, object]:
    if len(data) != RECORD_SIZE or not crc_valid(data):
        raise ValueError('invalid record length or CRC')
    magic, version, length = struct.unpack_from('<IHH', data)
    if (magic, version, length) != (RECORD_MAGIC, 1, RECORD_SIZE):
        raise ValueError('unsupported record')
    result = {
        'sequence': struct.unpack_from('<Q', data, 24)[0],
        'reset_generation': struct.unpack_from('<I', data, 32)[0],
        'flags': struct.unpack_from('<I', data, 36)[0],
        'start_utc_ms': struct.unpack_from('<q', data, 40)[0],
        'end_utc_ms': struct.unpack_from('<q', data, 48)[0],
        'start_monotonic_us': struct.unpack_from('<q', data, 56)[0],
        'end_monotonic_us': struct.unpack_from('<q', data, 64)[0],
        'sample_count': struct.unpack_from('<I', data, 72)[0],
        'expected_samples': struct.unpack_from('<I', data, 76)[0],
        'completeness_permille': struct.unpack_from('<H', data, 80)[0],
        'selected_energy_source': struct.unpack_from('<H', data, 82)[0],
        'voltage_mv': struct.unpack_from('<i', data, 84)[0],
        'current_ma': struct.unpack_from('<i', data, 88)[0],
        'active_power_mw': struct.unpack_from('<i', data, 92)[0],
        'frequency_mhz': struct.unpack_from('<i', data, 96)[0],
        'power_factor_milli': struct.unpack_from('<i', data, 100)[0],
        'pzem_energy_start_wh': struct.unpack_from('<Q', data, 104)[0],
        'pzem_energy_end_wh': struct.unpack_from('<Q', data, 112)[0],
        'selected_energy_mwh': struct.unpack_from('<I', data, 120)[0],
    }
    result['device_id'] = str(uuid.UUID(bytes=data[8:24]))
    result['time_trusted'] = bool(result['flags'] & 1)
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('segment', type=Path)
    parser.add_argument('--skip-corrupt', action='store_true', help='scan forward by one byte for the next valid magic')
    args = parser.parse_args()
    data = args.segment.read_bytes()
    header = decode_header(data[:HEADER_SIZE])
    print(json.dumps({'type': 'segment', **header}, separators=(',', ':')))
    offset = HEADER_SIZE
    while offset < len(data):
        block = data[offset:offset + RECORD_SIZE]
        try:
            record = decode_record(block)
        except ValueError as error:
            if not args.skip_corrupt:
                print(json.dumps({'type':'error','offset':offset,'error':str(error)}, separators=(',', ':')), file=sys.stderr)
                return 2
            next_magic = data.find(struct.pack('<I', RECORD_MAGIC), offset + 1)
            if next_magic < 0:
                print(json.dumps({'type':'unavailable','offset_start':offset,'offset_end':len(data)}, separators=(',', ':')))
                break
            print(json.dumps({'type':'unavailable','offset_start':offset,'offset_end':next_magic}, separators=(',', ':')))
            offset = next_magic
            continue
        print(json.dumps({'type': 'record', 'offset': offset, **record}, separators=(',', ':')))
        offset += RECORD_SIZE
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
