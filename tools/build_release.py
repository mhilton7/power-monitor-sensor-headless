#!/usr/bin/env python3
"""Assemble a deterministic PowerMeter V2 release-candidate evidence directory."""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import jsonschema

PROJECT = "power-monitor-sensor-headless"
BOARD = "esp32-s3-devkitc-n16r8-reference/1"
PROTOCOL = "pm-protocol/1.0.0"


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def run(*args: str, cwd: Path | None = None) -> str:
    return subprocess.run(args, cwd=cwd, check=True, text=True, capture_output=True).stdout.strip()


def write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + '\n', encoding='utf-8', newline='\n')


def copy_required(source: Path, destination: Path) -> None:
    if not source.is_file():
        raise FileNotFoundError(source)
    shutil.copy2(source, destination)


def spdx_id(index: int, name: str) -> str:
    safe = re.sub(r"[^A-Za-z0-9.-]+", "-", name).strip("-") or "component"
    return f"SPDXRef-Component-{index}-{safe}"


def create_sbom(project: dict, version: str, commit: str, generated: str,
                firmware_sha256: str, idf_version: str, idf_commit: str) -> dict:
    info = project.get("build_component_info")
    raw_names = project.get("build_components")
    if not isinstance(info, dict) or not isinstance(raw_names, list):
        raise RuntimeError("ESP-IDF project description omitted the component graph")
    names = sorted(name for name in raw_names if isinstance(name, str) and name)
    if not names:
        raise RuntimeError("ESP-IDF project description has an empty component graph")
    component_ids = {name: spdx_id(index, name) for index, name in enumerate(names, 1)}
    packages: list[dict] = [{
        "SPDXID": "SPDXRef-Package-Firmware", "name": PROJECT, "versionInfo": version,
        "downloadLocation": "NOASSERTION", "filesAnalyzed": False,
        "licenseConcluded": "MIT", "licenseDeclared": "MIT",
        "checksums": [{"algorithm": "SHA256", "checksumValue": firmware_sha256}],
        "primaryPackagePurpose": "APPLICATION",
    }]
    relationships: list[dict] = [{
        "spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES",
        "relatedSpdxElement": "SPDXRef-Package-Firmware",
    }]
    for name in names:
        component = info.get(name)
        if not isinstance(component, dict):
            raise RuntimeError(f"missing ESP-IDF component metadata: {name}")
        if name == "espressif__cjson":
            package_name = "espressif/cjson"
            package_version = "1.7.19~2"
            download = "https://components.espressif.com/components/espressif/cjson"
            purl = "pkg:github/DaveGamble/cJSON@v1.7.19"
        elif name == "main" or name.startswith("pm_"):
            package_name = f"{PROJECT}/{name}"
            package_version = version
            download = "NOASSERTION"
            purl = f"pkg:generic/{PROJECT}-{name}@{version}"
        else:
            package_name = f"esp-idf/{name}"
            package_version = idf_version
            download = f"https://github.com/espressif/esp-idf/tree/{idf_commit}/components/{name}"
            purl = f"pkg:github/espressif/esp-idf@{idf_version}?commit={idf_commit}#{name}"
        identifier = component_ids[name]
        packages.append({
            "SPDXID": identifier, "name": package_name, "versionInfo": package_version,
            "downloadLocation": download, "filesAnalyzed": False,
            "licenseConcluded": "NOASSERTION", "licenseDeclared": "NOASSERTION",
            "primaryPackagePurpose": "LIBRARY" if component.get("type") == "LIBRARY" else "SOURCE",
            "externalRefs": [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl",
                              "referenceLocator": purl}],
        })
        relationships.append({"spdxElementId": "SPDXRef-Package-Firmware",
                              "relationshipType": "CONTAINS", "relatedSpdxElement": identifier})
        requirements = component.get("reqs", []) + component.get("priv_reqs", [])
        for required in sorted(set(requirements)):
            if required in component_ids:
                relationships.append({"spdxElementId": identifier, "relationshipType": "DEPENDS_ON",
                                      "relatedSpdxElement": component_ids[required]})
    return {
        "spdxVersion": "SPDX-2.3", "dataLicense": "CC0-1.0", "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"{PROJECT}-{version}",
        "documentNamespace": f"https://github.com/mhilton7/{PROJECT}/spdx/{commit}/{firmware_sha256}",
        "creationInfo": {"created": generated, "creators": ["Tool: power-meter-build-release/2.0.0"]},
        "packages": packages, "relationships": relationships,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('--build-dir', type=Path, required=True)
    parser.add_argument('--output-dir', type=Path, required=True)
    parser.add_argument('--version', required=True)
    parser.add_argument('--build-number', required=True, type=int)
    parser.add_argument('--download-base', required=True)
    parser.add_argument('--hardware-status', type=Path, required=True)
    parser.add_argument('--configuration', choices=('release-candidate', 'release'), default='release-candidate')
    parser.add_argument('--server-tag', default='v0.1.0-rc.9')
    parser.add_argument('--dependency-audit-report', type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    build = args.build_dir.resolve()
    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=True)
    if any(output.iterdir()):
        raise RuntimeError(f'refusing non-empty output directory: {output}')
    if not args.download_base.startswith('https://'):
        raise ValueError('download-base must use HTTPS')
    if not args.server_tag.startswith('v'):
        raise ValueError('server-tag must start with v')
    commit = run('git', 'rev-parse', 'HEAD', cwd=root)
    dirty = bool(run('git', 'status', '--porcelain', cwd=root))
    if dirty:
        raise RuntimeError('refusing to assemble release artifacts from a dirty source tree')
    generated = dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')
    project_description = json.loads((build / 'project_description.json').read_text(encoding='utf-8'))
    if project_description.get('project_name') != PROJECT or project_description.get('target') != 'esp32s3':
        raise RuntimeError('compiled project identity or target does not match the release contract')
    if project_description.get('project_version') != args.version:
        raise RuntimeError('release version does not match compiled ESP-IDF application version')
    hardware_document = json.loads(args.hardware_status.read_text(encoding='utf-8'))
    hardware_certified = hardware_document.get('schema') == 'pm-hardware-certification/1.0.0'
    if args.configuration == 'release' and not hardware_certified:
        raise RuntimeError('stable release configuration requires certified marked-unit evidence')

    files = {
        build / f'{PROJECT}.bin': output / 'firmware.bin',
        build / f'{PROJECT}.elf': output / 'firmware.elf',
        build / f'{PROJECT}.map': output / 'firmware.map',
        build / 'bootloader' / 'bootloader.bin': output / 'bootloader.bin',
        build / 'partition_table' / 'partition-table.bin': output / 'partition-table.bin',
        build / 'ota_data_initial.bin': output / 'ota_data_initial.bin',
    }
    for source, destination in files.items():
        copy_required(source, destination)

    images = [
        ('0x0', 'bootloader.bin'),
        ('0x8000', 'partition-table.bin'),
        ('0x2D000', 'ota_data_initial.bin'),
        ('0x40000', 'firmware.bin'),
    ]
    merge = [sys.executable, '-m', 'esptool', '--chip', 'esp32s3', 'merge-bin', '-o', str(output / 'merged-flash.bin')]
    for offset, name in images:
        merge.extend((offset, str(output / name)))
    subprocess.run(merge, check=True)
    write_json(output / 'flash_args.json', {
        'schema': 'pm-flash-args/1.0.0', 'chip': 'esp32s3', 'flash_size': '16MB',
        'images': [{'offset': offset, 'file': name, 'sha256': sha256(output / name)} for offset, name in images],
    })

    firmware = output / 'firmware.bin'
    manifest = {
        'schema': 'pm-firmware-release/1.0.0', 'version': args.version, 'build_number': args.build_number,
        'project_name': PROJECT, 'target_chip': 'esp32s3', 'board_profile': BOARD,
        'minimum_boot_version': 1, 'minimum_config_version': 1, 'minimum_protocol': PROTOCOL,
        'image_size': firmware.stat().st_size, 'image_sha256': sha256(firmware),
        'download_url': f"{args.download_base.rstrip('/')}/firmware.bin",
        'ota_authentication': {
            'mode': 'per-device-hmac-sha256',
            'canonical_prefix': 'PM-OTA-MANIFEST-V1',
            'required_runtime_fields': ['manifest_nonce', 'signature'],
            'note': 'The central server adds a fresh nonce and HMAC using the enrolled device server-to-device key; this release document is not accepted directly by firmware.'
        },
        'hardware_certification': 'certified' if hardware_certified else 'pending', 'git_commit': commit,
    }
    manifest_schema = json.loads((root / 'release' / 'manifest.schema.json').read_text(encoding='utf-8'))
    jsonschema.Draft202012Validator(manifest_schema, format_checker=jsonschema.FormatChecker()).validate(manifest)
    write_json(output / 'manifest.json', manifest)
    write_json(output / 'compatibility.json', {
        'schema':'pm-release-compatibility/1.0.0',
        'firmware':{'repository':'https://github.com/mhilton7/power-monitor-sensor-headless',
                    'tag':f'v{args.version}','commit':commit,'version':args.version,
                    'image_sha256':sha256(firmware),'project_name':PROJECT,'target':'esp32s3','board_profile':BOARD},
        'server':{'repository':'https://github.com/mhilton7/power-monitor-v2','tag':args.server_tag,'minimum_version':args.server_tag[1:]},
        'contracts':{'device_protocol':PROTOCOL,'com_protocol':'pm-com/1.0.0','config_schema':1,'journal_format':1}
    })

    idf_path = os.environ.get('IDF_PATH', r'C:\esp\v6.0.2\esp-idf')
    idf_version = run('git', '-C', idf_path, 'describe', '--tags', '--exact-match')
    idf_commit = run('git', '-C', idf_path, 'rev-parse', 'HEAD')
    if idf_version != 'v6.0.2':
        raise RuntimeError(f'ESP-IDF v6.0.2 required; found {idf_version}')
    builder_id = ('https://github.com/' + os.environ['GITHUB_REPOSITORY'] + '/actions/runs/' +
                  os.environ['GITHUB_RUN_ID'] if os.environ.get('GITHUB_REPOSITORY') and os.environ.get('GITHUB_RUN_ID')
                  else 'https://github.com/mhilton7/power-monitor-sensor-headless/tools/build_release.py')
    write_json(output / 'provenance.json', {
        '_type': 'https://in-toto.io/Statement/v1',
        'subject': [{'name': 'firmware.bin', 'digest': {'sha256': sha256(firmware)}}],
        'predicateType': 'https://slsa.dev/provenance/v1',
        'predicate': {'buildDefinition': {'buildType': 'https://espressif.com/esp-idf/idf.py',
            'externalParameters': {'target': 'esp32s3', 'version': args.version, 'configuration': args.configuration},
            'resolvedDependencies': [{'uri': 'pkg:github/espressif/esp-idf@v6.0.2', 'digest': {'gitCommit': idf_commit}}]},
            'runDetails': {'builder': {'id': builder_id}, 'metadata': {'invocationId': commit, 'startedOn': generated, 'finishedOn': generated}}},
        'source_dirty': dirty,
    })
    sbom = create_sbom(project_description, args.version, commit, generated, sha256(firmware),
                       idf_version, idf_commit)
    write_json(output / 'sbom.spdx.json', sbom)
    audit = json.loads(args.dependency_audit_report.read_text(encoding='utf-8'))
    lock_digest = hashlib.sha256((root / 'dependencies.lock').read_bytes()).hexdigest()
    audit_subjects = {item.get('name'): item for item in audit.get('subjects', []) if isinstance(item, dict)}
    managed_manifest = (root / 'managed_components' / 'espressif__cjson' / 'idf_component.yml').read_text(encoding='utf-8')
    cjson_match = re.search(r'^\s*commit_sha:\s*([0-9a-f]{40})\s*$', managed_manifest, flags=re.MULTILINE)
    if cjson_match is None:
        raise RuntimeError('managed cJSON source commit is missing')
    audit_time = dt.datetime.fromisoformat(audit.get('generated_at', '').replace('Z', '+00:00'))
    audit_age = dt.datetime.now(dt.timezone.utc) - audit_time
    if (audit.get('schema') != 'pm-dependency-audit/1.0.0' or audit.get('result') != 'pass' or
            audit.get('dependencies_lock_sha256') != lock_digest or audit.get('vulnerabilities') != [] or
            audit.get('scanner', {}).get('endpoint') != 'https://api.osv.dev/v1/querybatch' or
            audit_age < dt.timedelta(minutes=-5) or audit_age > dt.timedelta(hours=24) or
            audit_subjects.get('espressif/esp-idf', {}).get('commit') != idf_commit or
            audit_subjects.get('espressif/esp-idf', {}).get('version') != 'v6.0.2' or
            audit_subjects.get('espressif/idf-extra-components/cjson', {}).get('version') != '1.7.19~2' or
            audit_subjects.get('espressif/idf-extra-components/cjson', {}).get('commit') != cjson_match.group(1) or
            audit_subjects.get('DaveGamble/cJSON', {}).get('purl') != 'pkg:github/DaveGamble/cJSON@v1.7.19'):
        raise RuntimeError('dependency audit is missing, failed, stale, or does not cover the compiled dependency set')
    shutil.copy2(args.dependency_audit_report, output / 'dependency-audit.json')
    map_size = (output / 'firmware.map').stat().st_size
    write_json(output / 'memory-report.json', {
        'schema':'pm-memory-report/1.0.0','generated_at':generated,'firmware_bytes':firmware.stat().st_size,
        'ota_slot_bytes':0x780000,'ota_slot_free_bytes':0x780000-firmware.stat().st_size,
        'map_bytes':map_size,'runtime_heap_hil_measurement':'pending_physical_hardware'
    })
    write_json(output / 'stack-report.json', {
        'schema':'pm-stack-report/1.0.0','generated_at':generated,
        'configured_bytes':{'main_boot':8192,'measurement':4096,'interval':4096,'storage':6144,
                            'network':16384,'control':8192,'supervisor':4096,
                            'usb_recovery':16384,'ota_ephemeral':16384},
        'hardware_high_water_marks':'pending_physical_hardware'
    })
    test_result_path = root / 'test-results' / 'host' / 'results.json'
    test_result = json.loads(test_result_path.read_text(encoding='utf-8')) if test_result_path.is_file() else {'result':'not_run'}
    write_json(output / 'test-report.json', {'schema':'pm-test-report/1.0.0','generated_at':generated,
                                              'host':test_result,
                                              'hardware':'certified' if hardware_certified else 'pending'})
    hardware_name = ('hardware-certification.json' if hardware_document.get('schema') == 'pm-hardware-certification/1.0.0'
                     else 'hardware-certification-status.json')
    shutil.copy2(args.hardware_status, output / hardware_name)
    for source, name in ((root/'release'/'RELEASE_NOTES.md','RELEASE_NOTES.md'),(root/'release'/'MIGRATION.md','MIGRATION.md'),
                         (root/'tools'/'Flash-PowerMeterSensor.ps1','Flash-PowerMeterSensor.ps1'),
                         (root/'tools'/'Provision-PowerMeterSensor.ps1','Provision-PowerMeterSensor.ps1'),
                         (root/'tools'/'Repair-PowerMeterSensor.ps1','Repair-PowerMeterSensor.ps1'),
                         (root/'tools'/'PowerMeterSerial.psm1','PowerMeterSerial.psm1')):
        copy_required(source, output / name)
    checksum_files = sorted(path for path in output.iterdir() if path.is_file() and path.name != 'SHA256SUMS')
    (output / 'SHA256SUMS').write_text(''.join(f'{sha256(path)}  {path.name}\n' for path in checksum_files), encoding='ascii', newline='\n')
    print(json.dumps({'result':'pass','output':str(output),'firmware_sha256':sha256(firmware),'artifact_count':len(list(output.iterdir()))}))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
