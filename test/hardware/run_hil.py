#!/usr/bin/env python3
"""Orchestrate the physical marked-unit HIL suite and emit certification evidence."""
from __future__ import annotations

import argparse
import copy
import datetime as dt
import hashlib
import json
import os
import subprocess
import time
import urllib.request
import uuid
from pathlib import Path

import jsonschema
import serial

CASES = (
    'pzem_authenticated_samples', 'crc_rejection', 'wrong_slave_rejection', 'sd_recovery',
    'sequence_monotonic', 'ack_replay', 'https_chain', 'https_hostname', 'hmac_replay',
    'ota_success', 'ota_rollback', 'com_recovery', 'watchdog_recovery',
    'sd_write_endurance', 'wifi_ap_reboot', 'server_restart', 'dns_outage', 'physical_power_cycle',
)


def canonical_digest(document: dict) -> str:
    value = copy.deepcopy(document)
    value['signoff'].pop('record_sha256', None)
    encoded = json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False,
                         allow_nan=False).encode('utf-8')
    return hashlib.sha256(encoded).hexdigest()


def controller(origin: str, case: str, token: str) -> dict:
    request = urllib.request.Request(f"{origin.rstrip('/')}/hil/{case}", method='POST',
                                     headers={'Authorization': f'Bearer {token}', 'Content-Type':'application/json'},
                                     data=b'{}')
    with urllib.request.urlopen(request, timeout=180) as response:
        if response.status != 200:
            raise RuntimeError(f'fixture {case} returned HTTP {response.status}')
        result = json.load(response)
    if type(result.get('pass')) is not bool:
        raise RuntimeError(f'fixture {case} omitted boolean pass')
    return result


def serial_hello(port: str) -> dict:
    with serial.Serial(port, 115200, timeout=5, write_timeout=5) as stream:
        request_id = str(uuid.uuid4())
        line = json.dumps({'protocol':'pm-com/1.0.0','id':request_id,'op':'hello'}, separators=(',', ':'))
        stream.write((line + '\n').encode())
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            response_line = stream.readline()
            if not response_line.startswith(b'{'):
                continue
            response = json.loads(response_line)
            if response.get('protocol') == 'pm-com/1.0.0' and response.get('id') == request_id:
                if response.get('ok') is not True:
                    raise RuntimeError('device rejected HIL hello')
                forbidden = {'wifi_password','enrollment_token','device_secret','hmac_key','private_key'}
                if forbidden.intersection(response):
                    raise RuntimeError('secret field exposed by COM hello')
                return response
    raise TimeoutError('no matching COM hello response')


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('--port', required=True)
    parser.add_argument('--fixture', type=Path, required=True)
    parser.add_argument('--firmware-bin', type=Path, required=True)
    parser.add_argument('--version', required=True)
    parser.add_argument('--duration-hours', type=float, default=72.0)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.duration_hours < 72:
        raise ValueError('certification soak must be at least 72 hours')
    token = os.environ.get('PM_HIL_FIXTURE_TOKEN')
    if not token:
        raise RuntimeError('PM_HIL_FIXTURE_TOKEN must be supplied outside source control')
    root = Path(__file__).resolve().parents[2]
    fixture = json.loads(args.fixture.read_text(encoding='utf-8'))
    fixture_schema = json.loads((root / 'test' / 'hardware' / 'fixture.schema.json').read_text(encoding='utf-8'))
    certification_schema = json.loads(
        (root / 'release' / 'hardware-certification.schema.json').read_text(encoding='utf-8')
    )
    # Resolve the two local authoring references explicitly. This keeps the
    # fixture schema reviewable without allowing jsonschema to fetch an
    # attacker-controlled or unavailable URI during an offline HIL run.
    fixture_schema['properties']['marked_unit'] = copy.deepcopy(
        certification_schema['properties']['marked_unit']
    )
    fixture_schema['properties']['electrical'] = copy.deepcopy(
        certification_schema['properties']['electrical']
    )
    jsonschema.Draft202012Validator(fixture_schema, format_checker=jsonschema.FormatChecker()).validate(fixture)
    if fixture.get('operator', '').strip() == fixture.get('reviewer', '').strip():
        raise RuntimeError('hardware certification requires independent operator and reviewer')
    firmware_hash = hashlib.sha256(args.firmware_bin.read_bytes()).hexdigest()
    commit = subprocess.run(('git','rev-parse','HEAD'),cwd=root,text=True,check=True,capture_output=True).stdout.strip()
    hello = serial_hello(args.port)
    case_results: dict[str, dict] = {}
    for case in CASES:
        case_results[case] = controller(fixture['controller_origin'], case, token)
    started = dt.datetime.now(dt.timezone.utc)
    soak_samples = 0
    soak_authenticated = 0
    soak_reboots = 0
    soak_unexplained_reboots = 0
    soak_gaps = 0
    soak_regressions = 0
    end_monotonic = time.monotonic() + args.duration_hours * 3600
    while time.monotonic() < end_monotonic:
        result = controller(fixture['controller_origin'], 'soak_checkpoint', token)
        soak_samples += int(result.get('samples_attempted', 0))
        soak_authenticated += int(result.get('samples_authenticated', 0))
        soak_reboots += int(result.get('reboots', 0))
        soak_unexplained_reboots += int(result.get('unexplained_reboots', 0))
        soak_gaps += int(result.get('data_gaps', 0))
        soak_regressions += int(result.get('sequence_regressions', 0))
        time.sleep(min(60, max(1, end_monotonic - time.monotonic())))
    ended = dt.datetime.now(dt.timezone.utc)
    all_tests = {name: bool(case_results[name]['pass']) for name in CASES[:13]}
    all_fixture_cases_pass = all(result['pass'] for result in case_results.values())
    soak_pass = (0 < soak_authenticated <= soak_samples and soak_unexplained_reboots == 0 and
                 soak_regressions == 0 and all_fixture_cases_pass)
    document = {
        'schema':'pm-hardware-certification/1.0.0','evidence_id':str(uuid.uuid4()),
        'generated_at':ended.replace(microsecond=0).isoformat().replace('+00:00','Z'),
        'result':'pass' if all(all_tests.values()) and soak_pass else 'fail',
        'firmware':{'repository':'https://github.com/mhilton7/power-monitor-sensor-headless','commit':commit,'image_sha256':firmware_hash,
                    'version':args.version,'esp_idf_version':'v6.0.2','target':'esp32s3',
                    'board_profile':'esp32-s3-devkitc-n16r8-reference/1','protocol':'pm-protocol/1.0.0'},
        'marked_unit':fixture['marked_unit'],'electrical':fixture['electrical'],'tests':all_tests,
        'soak':{'started_at':started.replace(microsecond=0).isoformat().replace('+00:00','Z'),
                'ended_at':ended.replace(microsecond=0).isoformat().replace('+00:00','Z'),
                'duration_hours':(ended-started).total_seconds()/3600,'samples_attempted':soak_samples,
                'samples_authenticated':soak_authenticated,'reboots':soak_reboots,
                'unexplained_reboots':soak_unexplained_reboots,
                'data_gaps':soak_gaps,'sequence_regressions':soak_regressions,'pass':soak_pass},
        'signoff':{'operator':fixture['operator'],'reviewer':fixture['reviewer'],'record_sha256':''},
    }
    document['signoff']['record_sha256'] = canonical_digest(document)
    jsonschema.Draft202012Validator(
        certification_schema, format_checker=jsonschema.FormatChecker()
    ).validate(document)
    args.output.write_text(json.dumps(document, indent=2, sort_keys=True)+'\n',encoding='utf-8',newline='\n')
    print(json.dumps({'result':document['result'],'evidence':str(args.output),'device_fingerprint':hello['device_fingerprint']}))
    return 0 if document['result'] == 'pass' else 1


if __name__ == '__main__':
    raise SystemExit(main())
