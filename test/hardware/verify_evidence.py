#!/usr/bin/env python3
"""Fail-closed semantic verifier for stable marked-unit certification evidence."""
from __future__ import annotations

import argparse
import copy
import datetime as dt
import hashlib
import json
import re
from pathlib import Path

import jsonschema

REPOSITORY = 'https://github.com/mhilton7/power-monitor-sensor-headless'
TESTS = ('pzem_authenticated_samples','crc_rejection','wrong_slave_rejection',
         'no_sd_runtime_access','no_telemetry_nvs_writes','independent_sample_acceptance',
         'later_sample_after_gap','latest_value_after_outage','wifi_recovery','server_recovery',
         'identity_preserved','configuration_preserved','https_chain','https_hostname',
         'hmac_replay','ota_success','ota_rollback','ota_identity_confirmed','com_recovery',
         'watchdog_recovery')
MARKINGS = ('unit_id','esp32s3_marking','pzem_model_marking','pzem_revision_marking',
            'pzem_terminal_labels','ct_marking')


def digest(document: dict) -> str:
    copy_document = copy.deepcopy(document)
    copy_document['signoff'].pop('record_sha256', None)
    value = json.dumps(copy_document, sort_keys=True, separators=(',', ':'), ensure_ascii=False,
                       allow_nan=False).encode('utf-8')
    return hashlib.sha256(value).hexdigest()


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('evidence', type=Path)
    parser.add_argument('--firmware-commit', required=True)
    parser.add_argument('--firmware-sha256')
    args = parser.parse_args()
    document = json.loads(args.evidence.read_text(encoding='utf-8'), parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)))
    root = Path(__file__).resolve().parents[2]
    schema = json.loads((root / 'release' / 'hardware-certification.schema.json').read_text(encoding='utf-8'))
    jsonschema.Draft202012Validator(schema, format_checker=jsonschema.FormatChecker()).validate(document)
    require(document.get('schema') == 'pm-hardware-certification/2.0.0', 'wrong certification schema')
    require(document.get('result') == 'pass', 'certification result is not pass')
    firmware = document.get('firmware', {})
    require(firmware.get('repository') == REPOSITORY, 'wrong firmware repository')
    require(firmware.get('commit') == args.firmware_commit, 'firmware commit does not match release')
    require(firmware.get('esp_idf_version') == 'v6.0.2' and firmware.get('target') == 'esp32s3', 'wrong toolchain or target')
    require(firmware.get('board_profile') == 'esp32-s3-devkitc-n16r8-reference/1', 'wrong board profile')
    require(firmware.get('protocol') == 'pm-protocol/1.0.0', 'wrong protocol')
    require(firmware.get('telemetry_protocol') == 'pm-telemetry/2.0.0',
            'wrong telemetry protocol')
    require(bool(re.fullmatch(r'[0-9a-f]{64}', firmware.get('image_sha256',''))), 'invalid firmware SHA-256')
    if args.firmware_sha256:
        require(firmware['image_sha256'] == args.firmware_sha256, 'firmware image hash does not match release')
    marked = document.get('marked_unit', {})
    require(all(type(marked.get(name)) is str and marked[name].strip() for name in MARKINGS), 'physical markings incomplete')
    photos = marked.get('photo_sha256', [])
    require(bool(photos) and len(set(photos)) == len(photos) and all(re.fullmatch(r'[0-9a-f]{64}', item) for item in photos), 'photo evidence invalid')
    electrical = document.get('electrical', {})
    require(electrical.get('uart_baud') == 9600 and electrical.get('data_bits') == 8 and electrical.get('parity') == 'none' and electrical.get('stop_bits') == 1, 'UART evidence mismatch')
    require(all(type(document.get('tests',{}).get(name)) is bool and document['tests'][name] for name in TESTS), 'one or more HIL tests did not pass')
    soak = document.get('soak', {})
    require(soak.get('pass') is True and soak.get('duration_hours',0) >= 72, '72-hour soak did not pass')
    require(soak.get('unexplained_reboots') == 0 and soak.get('identity_changes') == 0 and
            soak.get('configuration_losses') == 0 and
            1 <= soak.get('maximum_resident_telemetry_samples', 3) <= 2,
            'stateless soak integrity failure')
    require(type(soak.get('samples_attempted')) is int and type(soak.get('samples_authenticated')) is int and 0 < soak['samples_authenticated'] <= soak['samples_attempted'], 'invalid soak sample counts')
    started = dt.datetime.fromisoformat(soak['started_at'].replace('Z','+00:00'))
    ended = dt.datetime.fromisoformat(soak['ended_at'].replace('Z','+00:00'))
    require((ended-started).total_seconds() >= 72*3600, 'soak timestamps are shorter than 72 hours')
    signoff = document.get('signoff', {})
    require(bool(signoff.get('operator')) and bool(signoff.get('reviewer')), 'dual signoff missing')
    require(signoff['operator'].strip() != signoff['reviewer'].strip(), 'operator and reviewer must be independent')
    require(signoff.get('record_sha256') == digest(document), 'certification canonical digest mismatch')
    print(json.dumps({'result':'pass','evidence_id':document.get('evidence_id'),'firmware_sha256':firmware['image_sha256']}))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
