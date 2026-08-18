from __future__ import annotations

import json
import hashlib
from pathlib import Path
import re
import unittest

from jsonschema import Draft202012Validator, FormatChecker


ROOT = Path(__file__).resolve().parents[2]


class StatelessTelemetryContractTests(unittest.TestCase):
    def load(self, directory: str, name: str) -> object:
        return json.loads((ROOT / "test" / directory / name).read_text(encoding="utf-8"))

    def accepted_response(self, request: dict[str, object]) -> dict[str, object]:
        return {
            "protocol_id": "pm-protocol/1.0.0",
            "telemetry_protocol": "pm-telemetry/2.0.0",
            "status": "accepted",
            "server_received_at": "2026-08-17T12:00:01Z",
            "sample": {
                "sensor_id": request["sensor_id"],
                "boot_id": request["boot_id"],
                "sample_sequence": request["sample_sequence"],
            },
            "timestamp_source": "sensor",
            "configuration": {"version": 7, "telemetry_interval_seconds": 5},
            "commands": [],
        }

    def test_exact_request_and_response_vectors_validate(self) -> None:
        generated = self.load("vectors", "stateless-telemetry-v2.json")
        request = generated["request"]
        request_schema = self.load(
            "contracts", "device-stateless-telemetry-v2.schema.json"
        )
        response_schema = self.load(
            "contracts", "server-stateless-telemetry-v2-response.schema.json"
        )
        Draft202012Validator(
            request_schema, format_checker=FormatChecker()
        ).validate(request)
        Draft202012Validator(
            response_schema, format_checker=FormatChecker()
        ).validate(self.accepted_response(request))

    def test_generated_server_snapshots_are_byte_identical_and_self_consistent(self) -> None:
        snapshots = (
            (
                ROOT.parent / "shared" / "schemas" / "device-stateless-telemetry-v2.schema.json",
                ROOT / "test" / "contracts" / "device-stateless-telemetry-v2.schema.json",
            ),
            (
                ROOT.parent / "shared" / "schemas" / "server-stateless-telemetry-v2-response.schema.json",
                ROOT / "test" / "contracts" / "server-stateless-telemetry-v2-response.schema.json",
            ),
            (
                ROOT.parent / "shared" / "telemetry-test-vectors" / "stateless-telemetry-v2.json",
                ROOT / "test" / "vectors" / "stateless-telemetry-v2.json",
            ),
        )
        for sibling, firmware in snapshots:
            if sibling.exists():
                self.assertEqual(sibling.read_bytes(), firmware.read_bytes(), sibling.name)
        generated = self.load("vectors", "stateless-telemetry-v2.json")
        schema = self.load("contracts", "device-stateless-telemetry-v2.schema.json")
        Draft202012Validator(schema, format_checker=FormatChecker()).validate(
            generated["request"]
        )
        canonical_body = generated["canonical_body_utf8"].encode("utf-8")
        self.assertEqual(
            generated["body_sha256"], hashlib.sha256(canonical_body).hexdigest()
        )
        self.assertEqual(["accepted", "duplicate"], generated["success_status_values"])
        self.assertEqual(
            "authenticated/schema/semantic failures use ordinary 4xx problems",
            generated["rejection_semantics"],
        )

    def test_wire_contract_is_additive_and_independent(self) -> None:
        request = self.load("vectors", "stateless-telemetry-v2.json")["request"]
        response = self.accepted_response(request)
        self.assertEqual("pm-telemetry/2.0.0", request["telemetry_protocol"])
        self.assertNotIn("protocol_id", request)
        self.assertEqual("pm-protocol/1.0.0", response["protocol_id"])
        self.assertEqual("pm-telemetry/2.0.0", response["telemetry_protocol"])
        self.assertEqual(
            (request["sensor_id"], request["boot_id"], request["sample_sequence"]),
            (
                response["sample"]["sensor_id"],
                response["sample"]["boot_id"],
                response["sample"]["sample_sequence"],
            ),
        )
        for retired in ("highest_contiguous_sequence", "gaps", "acknowledged_sequence"):
            self.assertNotIn(retired, response)

    def test_production_component_graph_has_no_sd_or_persistent_telemetry(self) -> None:
        main_cmake = (ROOT / "main" / "CMakeLists.txt").read_text(encoding="utf-8")
        network_cmake = (
            ROOT / "components" / "pm_network" / "CMakeLists.txt"
        ).read_text(encoding="utf-8")
        commands_cmake = (
            ROOT / "components" / "pm_commands" / "CMakeLists.txt"
        ).read_text(encoding="utf-8")
        top_cmake = (ROOT / "CMakeLists.txt").read_text(encoding="utf-8")
        graph = "\n".join((main_cmake, network_cmake, commands_cmake))
        self.assertIn("set(COMPONENTS main)", top_cmake)
        self.assertIn('SRCS "app_main_stateless.c"', main_cmake)
        self.assertIn('SRCS "pm_network_v2.c"', network_cmake)
        for forbidden in ("pm_storage", "fatfs", "sdmmc", "pm_backlog_policy"):
            self.assertNotIn(forbidden, graph)
        self.assertFalse((ROOT / "components" / "pm_storage" / "CMakeLists.txt").exists())

    def test_active_runtime_never_mounts_formats_or_persists_telemetry(self) -> None:
        active_files = [
            ROOT / "main" / "app_main_stateless.c",
            ROOT / "components" / "pm_network" / "pm_network_v2.c",
            ROOT / "components" / "pm_telemetry" / "pm_telemetry.c",
            ROOT / "components" / "pm_provisioning" / "pm_provisioning.c",
            ROOT / "components" / "pm_ota" / "pm_ota.c",
            ROOT / "components" / "pm_config" / "pm_state.c",
            ROOT / "components" / "pm_config" / "include" / "pm_board.h",
        ]
        source = "\n".join(path.read_text(encoding="utf-8") for path in active_files)
        for forbidden in (
            "pm_storage_", "sdmmc", "SD.begin", "fopen(", "nvs_flash_erase",
            "nvs_erase_all", "nvs_erase_key", "highest_contiguous_sequence",
            "missing_prefix", "writeBacklog", "syncBacklog",
        ):
            self.assertNotIn(forbidden, source)
        telemetry_sources = "\n".join(
            path.read_text(encoding="utf-8") for path in active_files[1:3]
        )
        self.assertNotRegex(telemetry_sources, r"\bnvs_(?:open|set|commit|erase)")
        state = (
            ROOT / "components" / "pm_config" / "include" / "pm_state.h"
        ).read_text(encoding="utf-8")
        self.assertNotIn("STORAGE", state)
        self.assertNotIn("MAINTENANCE_SLEEP", state)

    def test_identity_wifi_tls_hmac_ota_and_watchdogs_are_preserved(self) -> None:
        app = (ROOT / "main" / "app_main_stateless.c").read_text(encoding="utf-8")
        network = (
            ROOT / "components" / "pm_network" / "pm_network_v2.c"
        ).read_text(encoding="utf-8")
        self.assertIn('nvs_open("pm_identity"', app)
        self.assertIn("pm_config_load(&s_config)", app)
        self.assertIn("pm_provisioning_start_usb", app)
        self.assertIn("pm_ota_install", app)
        self.assertIn("pm_ota_post_boot_validate", app)
        self.assertIn("esp_task_wdt_reset", app)
        self.assertIn("pm_sign_request", network)
        self.assertIn("pm_verify_response", network)
        self.assertIn(".cert_pem = auth_snapshot->ca_pem", network)
        self.assertNotIn("factory_reset_config_only", app)

    def test_ota_boot_validation_is_local_and_server_acceptance_is_later(self) -> None:
        app = (ROOT / "main" / "app_main_stateless.c").read_text(encoding="utf-8")
        network = (
            ROOT / "components" / "pm_network" / "pm_network_v2.c"
        ).read_text(encoding="utf-8")
        validation = app.index("pm_ota_post_boot_validate")
        network_release = app.index(
            "xEventGroupSetBits(s_runtime_start_gate, PM_NETWORK_START_BIT)"
        )
        self.assertLess(validation, network_release)
        self.assertIn("server separately keeps an OTA deployment", app)
        self.assertIn('cJSON_AddStringToObject(root, "firmware_version"', network)
        self.assertIn('cJSON_AddStringToObject(root, "firmware_build_id"', network)
        self.assertIn("char build_id[PM_SHA256_HEX_SIZE + 1U]", network)

    def test_server_or_wifi_outage_uses_bounded_retry_without_reboot_loop(self) -> None:
        app = (ROOT / "main" / "app_main_stateless.c").read_text(encoding="utf-8")
        network = (
            ROOT / "components" / "pm_network" / "pm_network_v2.c"
        ).read_text(encoding="utf-8")
        start = network.split("esp_err_t pm_network_start", 1)[1]
        self.assertNotIn("connect_wifi_bounded", start.split("static int hex_nibble", 1)[0])
        self.assertNotIn("esp_restart", network)
        self.assertIn("pm_telemetry_backoff_fail(&wifi_backoff", network)
        self.assertIn("pm_network_telemetry_complete", network)
        self.assertIn("network_error == ESP_OK", app)

    def test_exact_v2_payload_and_build_identity_are_serialized(self) -> None:
        source = (
            ROOT / "components" / "pm_network" / "pm_network_v2.c"
        ).read_text(encoding="utf-8")
        fields = self.load("vectors", "stateless-telemetry-v2.json")["request"].keys()
        for field in fields:
            self.assertIn(f'"{field}"', source)
        self.assertIn("PM_TELEMETRY_ENDPOINT", source)
        self.assertIn("pm_hex_lower((const uint8_t *)description->app_elf_sha256", source)
        self.assertRegex(source, re.compile(r"char build_id\[PM_SHA256_HEX_SIZE \+ 1U\]"))
        raw_descriptor_hash = bytes(range(32))
        exact_build_id = raw_descriptor_hash.hex()
        self.assertEqual(
            "000102030405060708090a0b0c0d0e0f"
            "101112131415161718191a1b1c1d1e1f",
            exact_build_id,
        )
        self.assertRegex(exact_build_id, r"^[0-9a-f]{64}$")

    def test_removed_command_names_are_not_accepted(self) -> None:
        commands = (
            ROOT / "components" / "pm_commands" / "pm_commands.c"
        ).read_text(encoding="utf-8")
        mapping = commands.split("bool pm_command_type_from_name", 1)[1]
        for retired in (
            "sync_now", "storage_self_test", "format_storage_prepare",
            "format_storage_commit", "data_reset_prepare", "data_reset_commit",
        ):
            self.assertNotIn(retired, mapping)
        network = (
            ROOT / "components" / "pm_network" / "pm_network_v2.c"
        ).read_text(encoding="utf-8")
        self.assertIn('"required_firmware_capability"', network)
        for retired_capability in ("storage-journal-v1", "destructive_commands_v1"):
            self.assertNotIn(retired_capability, network)

    def test_esp_idf_dependency_lock_remains_pinned_to_6_0_2(self) -> None:
        manifest = (ROOT / "main" / "idf_component.yml").read_text(encoding="utf-8")
        lock = (ROOT / "dependencies.lock").read_text(encoding="utf-8")
        self.assertIn('version: "==6.0.2"', manifest)
        self.assertRegex(lock, r"(?m)^    version: 6\.0\.2$")
        self.assertRegex(lock, r"(?m)^version: 3\.0\.0$")

    def test_reconnect_backoff_is_strictly_bounded_to_sixty_seconds(self) -> None:
        source = (
            ROOT / "components" / "pm_telemetry" / "pm_telemetry.c"
        ).read_text(encoding="utf-8")
        self.assertIn("if (delay_ms > 60000U)", source)
        self.assertIn("delay_ms = 60000U;", source)

    def test_only_frozen_telemetry_intervals_are_accepted(self) -> None:
        source = (
            ROOT / "components" / "pm_network" / "pm_network_v2.c"
        ).read_text(encoding="utf-8")
        self.assertIn("telemetry_period_is_supported", source)
        for interval in (2, 5, 10, 15, 30, 60):
            self.assertIn(f"seconds == {interval}U", source)


if __name__ == "__main__":
    unittest.main(verbosity=2)
