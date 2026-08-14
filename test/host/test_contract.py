from __future__ import annotations

import base64
import hashlib
import hmac
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
        self.validate("device-ota-command.json", "device-ota-command.schema.json")
        self.validate("device-destructive-commands.json", "device-destructive-commands.schema.json")
        self.validate("device-credential-rotation.json", "device-credential-rotation.schema.json")

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

    def test_ota_command_and_authenticated_download_contract(self) -> None:
        command = self.validate("device-ota-command.json", "device-ota-command.schema.json")
        payload = command["payload"]
        runtime_schema = self.load(ROOT / "release", "ota-device-manifest.schema.json")
        runtime_validator = jsonschema.Draft202012Validator(
            runtime_schema, format_checker=jsonschema.FormatChecker()
        )
        self.assertEqual([], [error.message for error in runtime_validator.iter_errors(payload)])
        fields = (
            "schema", "device_id", "deployment_id", "release_id", "semantic_version",
            "build_number", "project_name", "target_chip", "board_profile",
            "minimum_boot_version", "minimum_config_version", "minimum_protocol",
            "image_size", "sha256", "download_path", "manifest_nonce",
        )
        canonical = "PM-OTA-MANIFEST-V1\n" + "\n".join(str(payload[name]) for name in fields)
        secret = bytes(range(32))
        salt = (PROTOCOL + "\0" + payload["device_id"]).encode()
        pseudorandom_key = hmac.new(salt, secret, hashlib.sha256).digest()
        server_key = hmac.new(
            pseudorandom_key, b"PowerMeter V2\0server-to-device\x01", hashlib.sha256
        ).digest()
        expected = base64.b64encode(hmac.new(server_key, canonical.encode(), hashlib.sha256).digest()).decode()
        self.assertEqual("82573a65e513e39fd5f0888de9a4494dc0e36055298691ac9bd6b30ddefb6a53",
                         server_key.hex())
        self.assertEqual("776085e83a14c0ecc89ee3170712fed6f841d5c06ba8e948ff702b3ec46d6469",
                         hashlib.sha256(canonical.encode()).hexdigest())
        self.assertEqual(expected, payload["signature"])
        self.assertEqual(f"/api/v1/device/firmware/{payload['release_id']}", payload["download_path"])
        manifest = self.load(VECTORS, "server-contract.json")
        self.assertEqual("/api/v1/device/firmware/{release_id}", manifest["downloads"][0]["path_template"])
        self.assertEqual("safe_restart_without_range", manifest["downloads"][0]["range_policy"])
        command_header = (ROOT / "components" / "pm_commands" / "include" / "pm_commands.h").read_text(encoding="utf-8")
        self.assertIn("#define PM_COMMAND_PAYLOAD_MAX 1536U", command_header)

    def test_destructive_command_payloads_and_results_are_exact(self) -> None:
        vectors = self.validate(
            "device-destructive-commands.json", "device-destructive-commands.schema.json"
        )
        response_schema = self.load(CONTRACTS, "server-device-response.schema.json")
        command_validator = jsonschema.Draft202012Validator(
            response_schema["$defs"]["CommandEnvelope"],
            format_checker=jsonschema.FormatChecker(),
        )
        heartbeat_schema = self.load(CONTRACTS, "device-heartbeat.schema.json")
        result_validator = jsonschema.Draft202012Validator(
            heartbeat_schema["$defs"]["CommandResult"],
            format_checker=jsonschema.FormatChecker(),
        )
        for command in vectors["commands"]:
            self.assertEqual([], [error.message for error in command_validator.iter_errors(command)])
        for result in vectors["results"]:
            self.assertEqual([], [error.message for error in result_validator.iter_errors(result)])

        commands = {item["command_type"]: item for item in vectors["commands"]}
        token_pattern = "00112233445566778899aabbccddeeff"
        self.assertEqual({"confirmation_token": token_pattern}, commands["format_storage_prepare"]["payload"])
        self.assertEqual(
            {"prepare_command_id", "confirmation_token"},
            set(commands["format_storage_commit"]["payload"]),
        )
        reset_prepare = commands["data_reset_prepare"]
        reset_commit = commands["data_reset_commit"]
        self.assertEqual(
            {"confirmation_token", "reset_generation", "server_sequence_floor"},
            set(reset_prepare["payload"]),
        )
        self.assertEqual(
            {"prepare_command_id", "confirmation_token", "reset_generation", "sequence_floor"},
            set(reset_commit["payload"]),
        )
        self.assertEqual(
            reset_prepare["command_id"], reset_commit["payload"]["prepare_command_id"]
        )
        self.assertEqual(
            {"prepare_command_id"}, set(commands["data_reset_cancel"]["payload"])
        )

        results = {item["command_id"]: item for item in vectors["results"]}
        prepare_evidence = results[reset_prepare["command_id"]]["evidence"]
        self.assertEqual(
            {
                "prepare_command_id", "reset_generation", "server_sequence_floor",
                "sequence_floor", "ready",
            },
            set(prepare_evidence),
        )
        self.assertGreaterEqual(
            prepare_evidence["sequence_floor"], prepare_evidence["server_sequence_floor"]
        )
        commit_evidence = results[reset_commit["command_id"]]["evidence"]
        self.assertEqual(
            {"prepare_command_id", "reset_generation", "sequence_floor"},
            set(commit_evidence),
        )
        self.assertEqual(prepare_evidence["sequence_floor"], reset_commit["payload"]["sequence_floor"])
        self.assertEqual(reset_commit["payload"]["sequence_floor"], commit_evidence["sequence_floor"])
        self.assertNotIn("confirmation_token", json.dumps(vectors["results"]))

        source = (ROOT / "main" / "app_main.c").read_text(encoding="utf-8")
        network = (ROOT / "components" / "pm_network" / "pm_network.c").read_text(encoding="utf-8")
        self.assertIn("#define PM_PREPARE_EXPIRY_US UINT64_C(600000000)", source)
        self.assertIn("floor != s_prepare_record.internal_sequence_floor", source)
        self.assertIn("prepare_state_boot_load", source)
        self.assertIn("PM_PREPARE_PHASE_COMMIT_INTENT_TOKEN_ZEROIZED", source)
        self.assertIn("PM_PREPARE_PHASE_RESULT_ACKNOWLEDGED", source)
        self.assertIn("if (!structured_evidence)", network)
        self.assertIn('strcmp(capability, "ota_v1")', network)
        self.assertIn('strcmp(capability, "destructive_commands_v1")', network)

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

    def test_credential_rotation_payloads_results_and_key_cutover_are_exact(self) -> None:
        vectors = self.validate(
            "device-credential-rotation.json", "device-credential-rotation.schema.json"
        )
        response_schema = self.load(CONTRACTS, "server-device-response.schema.json")
        command_validator = jsonschema.Draft202012Validator(
            response_schema["$defs"]["CommandEnvelope"],
            format_checker=jsonschema.FormatChecker(),
        )
        heartbeat_schema = self.load(CONTRACTS, "device-heartbeat.schema.json")
        result_validator = jsonschema.Draft202012Validator(
            heartbeat_schema["$defs"]["CommandResult"],
            format_checker=jsonschema.FormatChecker(),
        )
        for command in vectors["commands"]:
            self.assertEqual([], [error.message for error in command_validator.iter_errors(command)])
        for result in vectors["results"]:
            self.assertEqual([], [error.message for error in result_validator.iter_errors(result)])

        prepare, commit, cancel = (item["payload"] for item in vectors["commands"])
        self.assertEqual(
            {"schema", "rotation_id", "device_secret_hex", "credential_fingerprint",
             "overlap_expires_at"},
            set(prepare),
        )
        self.assertEqual(
            {"schema", "rotation_id", "credential_fingerprint"}, set(commit)
        )
        self.assertEqual({"schema", "rotation_id", "cancelled"}, set(cancel))
        self.assertEqual(
            hashlib.sha256(bytes.fromhex(prepare["device_secret_hex"])).hexdigest(),
            prepare["credential_fingerprint"],
        )
        self.assertEqual(prepare["rotation_id"], commit["rotation_id"])
        self.assertEqual(prepare["rotation_id"], cancel["rotation_id"])
        self.assertNotIn("device_secret", json.dumps(vectors["results"]))
        self.assertEqual("old_device_to_server", vectors["authentication"]["prepare_result"])
        self.assertEqual("new_device_to_server", vectors["authentication"]["commit_result"])

        prepare_result, commit_result, cancel_result = (
            item["evidence"] for item in vectors["results"]
        )
        self.assertEqual(
            {"rotation_id", "credential_fingerprint", "ready"}, set(prepare_result)
        )
        self.assertEqual(
            {"rotation_id", "credential_fingerprint", "activated"}, set(commit_result)
        )
        self.assertEqual({"rotation_id", "cancelled"}, set(cancel_result))

        source = (ROOT / "main" / "app_main.c").read_text(encoding="utf-8")
        network = (ROOT / "components" / "pm_network" / "pm_network.c").read_text(encoding="utf-8")
        command_source = (ROOT / "components" / "pm_commands" / "pm_commands.c").read_text(
            encoding="utf-8"
        )
        self.assertIn("PM_ROTATION_PHASE_COMMIT_INTENT_SECRET_ZEROIZED", source)
        self.assertIn("PM_ROTATION_PHASE_COMMAND_RESULT_DURABLE", source)
        self.assertIn("rotation_cleanup_acknowledged", source)
        self.assertIn("pm_command_zeroize_payload(&s_commands, prepare)", source)
        self.assertIn(
            "if (!prepare->payload_redacted || s_rotation_payload_redaction_retry)",
            source,
        )
        self.assertIn("s_rotation_payload_redaction_retry = error != ESP_OK", source)
        self.assertIn("now_utc_ms > s_rotation_record.overlap_expires_utc_ms", source)
        self.assertNotIn("s_rotation_record.phase = PM_ROTATION_PHASE_NONE", source)
        self.assertIn("enqueue_interrupted_rotation_commands", source)
        self.assertIn('strcmp(capability, "credential_rotation_v1")', network)
        self.assertIn("zeroize_rotation_secrets(commands)", network)
        self.assertIn("secure_zero_memory(serialized, strlen(serialized))", network)
        self.assertIn("secure_zero_memory(response, sizeof(response))", network)
        self.assertIn("!ledger->entries[index].result_ack_required", command_source)
        self.assertIn("ledger->entries[selected] = *previous", command_source)
        self.assertIn("secure_zero_memory(&candidate, sizeof(candidate))", command_source)
        self.assertIn("pm_command_acknowledge_result", source)
        partitions = (ROOT / "partitions.csv").read_text(encoding="utf-8")
        self.assertIn("nvs,         data, nvs,       0x9000,   0x22000,", partitions)
        self.assertNotIn("pm_recovery", partitions)
        self.assertIn("PM_NVS_RAW_DURABLE_BLOB_BUDGET", source)
        release_builder = (ROOT / "tools" / "build_release.py").read_text(encoding="utf-8")
        self.assertIn("('0x2D000', 'ota_data_initial.bin')", release_builder)
        self.assertIn("('0x40000', 'firmware.bin')", release_builder)

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
