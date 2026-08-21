from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

from jsonschema import Draft202012Validator, FormatChecker


ROOT = Path(__file__).resolve().parents[2]


class StatelessHardwareEvidenceTests(unittest.TestCase):
    def build_release_module(self):
        path = ROOT / "tools" / "build_release.py"
        spec = importlib.util.spec_from_file_location("pm_build_release", path)
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def schema(self) -> dict[str, object]:
        return json.loads(
            (ROOT / "release" / "hardware-certification.schema.json").read_text(
                encoding="utf-8"
            )
        )

    def evidence(self) -> dict[str, object]:
        required_tests = self.schema()["properties"]["tests"]["required"]
        document: dict[str, object] = {
            "schema": "pm-hardware-certification/2.0.0",
            "evidence_id": "123e4567-e89b-42d3-a456-426614174000",
            "generated_at": "2026-08-20T12:00:00Z",
            "result": "pass",
            "firmware": {
                "repository": "https://github.com/mhilton7/power-monitor-sensor-headless",
                "commit": "a" * 40,
                "image_sha256": "b" * 64,
                "version": "0.1.0-rc.22",
                "esp_idf_version": "v6.0.2",
                "target": "esp32s3",
                "board_profile": "esp32-s3-devkitc-n16r8-reference/1",
                "protocol": "pm-protocol/1.0.0",
                "telemetry_protocol": "pm-telemetry/2.0.0",
            },
            "marked_unit": {
                "unit_id": "marked-unit-1",
                "esp32s3_marking": "ESP32-S3",
                "pzem_model_marking": "PZEM-004T",
                "pzem_revision_marking": "marked revision",
                "pzem_terminal_labels": "5V GND RX TX",
                "ct_marking": "100A",
                "photo_sha256": ["c" * 64],
            },
            "electrical": {
                "qualified_person": "operator",
                "isolated_test_fixture": "fixture-1",
                "ttl_idle_voltage_v": 5.0,
                "logic_high_voltage_v": 3.3,
                "logic_low_voltage_v": 0.0,
                "uart_baud": 9600,
                "data_bits": 8,
                "parity": "none",
                "stop_bits": 1,
                "register_map_variant": "pzem-004t-v4-classic-candidate",
            },
            "tests": {name: True for name in required_tests},
            "soak": {
                "started_at": "2026-08-17T12:00:00Z",
                "ended_at": "2026-08-20T12:00:00Z",
                "duration_hours": 72,
                "samples_attempted": 1000,
                "samples_authenticated": 900,
                "reboots": 2,
                "unexplained_reboots": 0,
                "data_gaps": 10,
                "maximum_resident_telemetry_samples": 2,
                "identity_changes": 0,
                "configuration_losses": 0,
                "pass": True,
            },
            "signoff": {
                "operator": "operator-a",
                "reviewer": "reviewer-b",
                "record_sha256": "0" * 64,
            },
        }
        canonical = copy.deepcopy(document)
        canonical["signoff"].pop("record_sha256")
        encoded = json.dumps(
            canonical,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
        document["signoff"]["record_sha256"] = hashlib.sha256(encoded).hexdigest()
        return document

    def test_stateless_evidence_shape_validates(self) -> None:
        Draft202012Validator(
            self.schema(), format_checker=FormatChecker()
        ).validate(self.evidence())

    def test_retired_storage_and_ack_evidence_is_not_accepted(self) -> None:
        schema = self.schema()
        test_properties = schema["properties"]["tests"]["properties"]
        marked_properties = schema["properties"]["marked_unit"]["properties"]
        for retired in ("sd_recovery", "sequence_monotonic", "ack_replay"):
            self.assertNotIn(retired, test_properties)
        self.assertNotIn("sd_module_marking", marked_properties)

        old = self.evidence()
        old["tests"]["sd_recovery"] = True
        errors = list(Draft202012Validator(schema).iter_errors(old))
        self.assertTrue(errors)

    def test_soak_bounds_stateless_resident_samples(self) -> None:
        schema = self.schema()
        invalid = self.evidence()
        invalid["soak"]["maximum_resident_telemetry_samples"] = 3
        errors = list(Draft202012Validator(schema).iter_errors(invalid))
        self.assertTrue(errors)

    def test_well_formed_failed_evidence_cannot_be_certified(self) -> None:
        failed = self.evidence()
        failed["result"] = "fail"
        canonical = copy.deepcopy(failed)
        canonical["signoff"].pop("record_sha256")
        failed["signoff"]["record_sha256"] = hashlib.sha256(
            json.dumps(
                canonical,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
                allow_nan=False,
            ).encode("utf-8")
        ).hexdigest()
        Draft202012Validator(
            self.schema(), format_checker=FormatChecker()
        ).validate(failed)

        with tempfile.TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / "failed-certification.json"
            path.write_text(json.dumps(failed), encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "result is not pass"):
                self.build_release_module().verify_hardware_certification(
                    ROOT, path, "a" * 40, "b" * 64
                )

    def test_runner_verifier_status_and_release_builder_use_v2(self) -> None:
        required_tests = self.schema()["properties"]["tests"]["required"]
        runner = (ROOT / "test" / "hardware" / "run_hil.py").read_text(
            encoding="utf-8"
        )
        verifier = (ROOT / "test" / "hardware" / "verify_evidence.py").read_text(
            encoding="utf-8"
        )
        builder = (ROOT / "tools" / "build_release.py").read_text(encoding="utf-8")
        host_runner = (ROOT / "tools" / "Run-HostTests.ps1").read_text(
            encoding="utf-8"
        )
        status = json.loads(
            (ROOT / "release" / "hardware-certification-status.json").read_text(
                encoding="utf-8"
            )
        )
        for name in required_tests:
            self.assertIn(repr(name), runner)
            self.assertIn(repr(name), verifier)
        for source in (runner, verifier, builder):
            self.assertIn("pm-hardware-certification/2.0.0", source)
            self.assertNotIn("pm-hardware-certification/1.0.0", source)
        self.assertEqual("pending", status["status"])
        self.assertEqual(
            "pm-hardware-certification/2.0.0",
            status["required_evidence_schema"],
        )
        self.assertIn('import jsonschema', host_runner)
        self.assertLess(
            host_runner.index('Split-Path -Parent $repo'),
            host_runner.index('C:\\Espressif\\tools\\python\\v6.0.2'),
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
