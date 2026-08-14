from __future__ import annotations

import hashlib
import json
from pathlib import Path
import struct
import unittest

import jsonschema

from pm_model import Interval, encode_record


ROOT = Path(__file__).resolve().parents[2]
VECTORS = ROOT / "test" / "vectors"
CONTRACTS = ROOT / "test" / "contracts"
PROTOCOL = "pm-protocol/1.0.0"


class ServerContractTests(unittest.TestCase):
    def load(self, directory: Path, name: str) -> dict:
        return json.loads((directory / name).read_text(encoding="utf-8"))

    def validate(self, fixture: str, schema: str) -> dict:
        document = self.load(VECTORS, fixture)
        validator = jsonschema.Draft202012Validator(
            self.load(CONTRACTS, schema), format_checker=jsonschema.FormatChecker()
        )
        errors = sorted(validator.iter_errors(document), key=lambda error: list(error.path))
        self.assertEqual([], [error.message for error in errors])
        return document

    def test_locked_fixtures_validate_against_exact_server_schema_snapshots(self) -> None:
        self.validate("device-enrollment.json", "device-enrollment.schema.json")
        self.validate("device-heartbeat.json", "device-heartbeat.schema.json")
        self.validate("device-reading-batch.json", "device-reading-batch.schema.json")
        self.validate("device-permanent-loss.json", "device-permanent-loss.schema.json")

    def test_manifest_has_only_inspected_post_endpoints(self) -> None:
        manifest = self.load(VECTORS, "server-contract.json")
        self.assertEqual(PROTOCOL, manifest["protocol_id"])
        self.assertEqual(
            {
                ("enrollment", "POST", "/api/v1/devices/enroll"),
                ("heartbeat", "POST", "/api/v1/device/heartbeat"),
                ("reading_batch", "POST", "/api/v1/device/readings"),
                ("permanent_loss", "POST", "/api/v1/device/permanent-loss"),
            },
            {(item["name"], item["method"], item["path"]) for item in manifest["requests"]},
        )
        header = (ROOT / "components" / "pm_network" / "include" / "pm_network.h").read_text(encoding="utf-8")
        source = (ROOT / "components" / "pm_network" / "pm_network.c").read_text(encoding="utf-8")
        for item in manifest["requests"]:
            self.assertIn(item["path"], header)
        self.assertNotIn("/api/device/v1/", header + source)

    def test_snapshots_are_byte_identical_to_sibling_server_when_present(self) -> None:
        shared = ROOT.parent / "shared" / "schemas"
        manifest = self.load(VECTORS, "server-contract.json")
        for name, expected in manifest["shared_contract_sha256"].items():
            if name == "power-meter-v2.openapi.json":
                candidate = ROOT.parent / "shared" / "openapi" / name
            else:
                candidate = shared / name
            if not candidate.exists():
                continue
            self.assertEqual(expected, hashlib.sha256(candidate.read_bytes()).hexdigest(), name)
            if name in {
                "device-heartbeat.schema.json",
                "device-reading-batch.schema.json",
                "device-permanent-loss.schema.json",
                "server-device-response.schema.json",
            }:
                self.assertEqual(candidate.read_bytes(), (CONTRACTS / name).read_bytes(), name)

    def test_zero_is_preserved_and_missing_evidence_is_null(self) -> None:
        heartbeat = self.load(VECTORS, "device-heartbeat.json")
        measurement = heartbeat["measurement"]
        self.assertEqual("0.000", measurement["current_a"])
        self.assertEqual("0.000", measurement["active_power_w"])
        self.assertEqual(0, measurement["pzem_energy_wh"])
        self.assertIsNone(measurement["pzem_error_code"])
        batch = self.load(VECTORS, "device-reading-batch.json")
        self.assertEqual(0, batch["records"][0]["interval_energy_mwh"])
        self.assertIsNone(batch["records"][1]["interval_energy_mwh"])
        self.assertIsNone(batch["records"][1]["interval_start_utc"])
        self.assertFalse(batch["records"][1]["time_trusted"])

    def test_record_crc_values_are_the_firmware_journal_crc(self) -> None:
        document = self.load(VECTORS, "device-reading-batch.json")
        device_id = bytes.fromhex("123e4567e89b12d3a456426614174000")
        records = (
            Interval(
                sequence=1, start_utc_ms=1786651200000, end_utc_ms=1786651260000,
                start_monotonic_us=60_000_000, end_monotonic_us=120_000_000,
                voltage_mv=120_000, current_ma=0, active_power_mw=0, frequency_mhz=60_000,
                power_factor_milli=0, pzem_energy_start_wh=100, pzem_energy_end_wh=100,
                selected_energy_mwh=0,
            ),
            Interval(
                sequence=2, flags=5, start_monotonic_us=120_000_000,
                end_monotonic_us=180_000_000, sample_count=55, completeness_permille=916,
                energy_source=0, voltage_mv=119_500, current_ma=0, active_power_mw=0,
                frequency_mhz=60_000, power_factor_milli=0, pzem_energy_start_wh=100,
                pzem_energy_end_wh=2, selected_energy_mwh=0,
            ),
        )
        actual = [struct.unpack_from("<I", encode_record(device_id, record), 124)[0] for record in records]
        self.assertEqual(actual, [item["record_crc32"] for item in document["records"]])

    def test_permanent_loss_evidence_is_deterministic(self) -> None:
        document = self.load(VECTORS, "device-permanent-loss.json")
        item = document["ranges"][0]
        canonical = "\n".join(
            (PROTOCOL, "3", "3", "segment_corrupt", "00112233445566778899aabbccddeeff", "1", "1")
        )
        self.assertEqual(hashlib.sha256(canonical.encode()).hexdigest(), item["evidence_sha256"])

    def test_vector_bytes_are_runtime_minified_json_shape(self) -> None:
        for path in sorted(VECTORS.glob("device-*.json")):
            text = path.read_text(encoding="utf-8").rstrip("\n")
            self.assertEqual(text, json.dumps(json.loads(text), separators=(",", ":"), ensure_ascii=False), path.name)


if __name__ == "__main__":
    unittest.main()
