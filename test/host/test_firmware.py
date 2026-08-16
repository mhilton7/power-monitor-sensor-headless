from __future__ import annotations

import base64
import hashlib
import hmac
import re
import struct
import unittest
from pathlib import Path

from pm_model import (
    ABStore,
    CommandLedger,
    command_boot_action,
    Interval,
    Journal,
    Scheduler,
    SequenceState,
    SimulatedDevice,
    canonical_query,
    canonical_request,
    decode_record,
    directional_keys,
    encode_record,
    hkdf,
    modbus_crc16,
    protocol_vector,
    pzem_parse,
    pzem_request,
    redact,
)


def response_frame(*, address=1, voltage=1201, current=12345, power=14822, energy=123456, frequency=600, pf=98):
    frame = bytearray((address, 4, 20))
    frame += struct.pack(">H", voltage)
    frame += struct.pack(">HH", current & 0xFFFF, current >> 16)
    frame += struct.pack(">HH", power & 0xFFFF, power >> 16)
    frame += struct.pack(">HH", energy & 0xFFFF, energy >> 16)
    frame += struct.pack(">HHH", frequency, pf, 0)
    frame += struct.pack("<H", modbus_crc16(frame))
    return bytes(frame)


class PzemTests(unittest.TestCase):
    def test_request_crc_vector(self):
        self.assertEqual(pzem_request(), bytes.fromhex("01040000000a700d"))

    def test_response_parse(self):
        value = pzem_parse(response_frame())
        self.assertEqual(value["voltage_mv"], 120100)
        self.assertEqual(value["current_ma"], 12345)
        self.assertEqual(value["energy_wh"], 123456)

    def test_timeout_short_frame(self):
        with self.assertRaisesRegex(ValueError, "short_frame"):
            pzem_parse(b"")

    def test_bad_crc(self):
        frame = bytearray(response_frame())
        frame[-1] ^= 1
        with self.assertRaisesRegex(ValueError, "bad_crc"):
            pzem_parse(bytes(frame))

    def test_wrong_slave(self):
        with self.assertRaisesRegex(ValueError, "wrong_slave"):
            pzem_parse(response_frame(), 2)

    def test_invalid_ranges(self):
        with self.assertRaisesRegex(ValueError, "invalid_range"):
            pzem_parse(response_frame(frequency=100))


class ProtocolTests(unittest.TestCase):
    def test_query_order(self):
        self.assertEqual(canonical_query("b=two&a=one%20value"), "a=one%20value&b=two")

    def test_query_rejects_ambiguous_plus(self):
        with self.assertRaises(ValueError):
            canonical_query("a=one+two")

    def test_canonical(self):
        canonical = canonical_request("post", "/x", "z=2&a=1", "1", "00", "AB")
        self.assertEqual(canonical, "PM-HMAC-SHA256-V1\nPOST\n/x?a=1&z=2\n1\n00\nab")

    def test_hkdf_rfc5869(self):
        ikm = bytes.fromhex("0b" * 22)
        salt = bytes.fromhex("000102030405060708090a0b0c")
        info = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9")
        self.assertEqual(
            hkdf(ikm, salt, info, 42).hex(),
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
        )

    def test_directional_keys_are_distinct(self):
        outbound, inbound = directional_keys(bytes(range(32)), bytes(range(16)))
        self.assertNotEqual(outbound, inbound)

    def test_signature_vector_self_consistent(self):
        vector = protocol_vector()
        signature = hmac.new(bytes.fromhex(vector["device_to_server_key_hex"]), vector["canonical"].encode(),
                             hashlib.sha256).digest()
        signature_base64 = base64.b64encode(signature).decode()
        self.assertEqual(signature_base64, vector["signature_base64"])
        self.assertEqual(vector["device_to_server_key_hex"],
                         "8c7c04e1e3615e5e9f53e30d7087e10b00c9a7a1fe1ad59289b20c6f16901a37")
        self.assertEqual(signature_base64, "aPPEsKXCXz8qhZ2sGkrCSjtXIJIDG6gugpSOXlrWxBQ=")


class StorageTests(unittest.TestCase):
    def test_record_roundtrip(self):
        record = Interval(sequence=42, selected_energy_mwh=1234, completeness_permille=999)
        self.assertEqual(decode_record(encode_record(bytes(range(16)), record)), record)

    def test_record_crc(self):
        encoded = bytearray(encode_record(bytes(range(16)), Interval(sequence=1)))
        encoded[84] ^= 1
        with self.assertRaisesRegex(ValueError, "record_crc"):
            decode_record(bytes(encoded))

    def test_trailing_write_recovery(self):
        journal = Journal()
        data = encode_record(bytes(range(16)), Interval(sequence=1))
        self.assertFalse(journal.append(data, "partial_write"))
        self.assertEqual(journal.recover(), [])
        self.assertEqual(journal.trailing, b"")

    def test_corrupt_record_does_not_block_following(self):
        journal = Journal()
        one = bytearray(encode_record(bytes(range(16)), Interval(sequence=1)))
        one[90] ^= 1
        journal.records = [bytes(one), encode_record(bytes(range(16)), Interval(sequence=2))]
        self.assertEqual([record.sequence for record in journal.recover()], [2])

    def test_full_card_preserves_unacknowledged(self):
        journal = Journal(records=[encode_record(bytes(16), Interval(sequence=i)) for i in range(1, 5)])
        journal.retain(acknowledged=2, maximum_records=1)
        self.assertTrue(journal.full)
        self.assertEqual(decode_record(journal.records[0]).sequence, 3)

    def test_acknowledged_retention(self):
        journal = Journal(records=[encode_record(bytes(16), Interval(sequence=i)) for i in range(1, 5)])
        journal.retain(acknowledged=4, maximum_records=2)
        self.assertEqual([decode_record(item).sequence for item in journal.records], [3, 4])


class PersistenceTests(unittest.TestCase):
    def test_config_ab_transaction(self):
        store = ABStore()
        self.assertTrue(store.commit(b"one"))
        self.assertFalse(store.commit(b"two", "after_write"))
        self.assertEqual(store.load(), b"two")
        self.assertEqual(store.active, "b")

    def test_config_corrupt_slot_falls_back(self):
        store = ABStore()
        store.commit(b"one")
        store.commit(b"two")
        generation, payload, crc = store.slots[store.active]
        store.slots[store.active] = (generation, payload, crc ^ 1)
        self.assertEqual(store.load(), b"one")

    def test_sequence_no_reuse_after_reboot(self):
        state = SequenceState()
        self.assertEqual(state.allocate(), 1)
        state.reboot()
        self.assertEqual(state.allocate(), 65)

    def test_ack_monotonic(self):
        state = SequenceState()
        for _ in range(3):
            state.allocate()
        state.acknowledge(2)
        with self.assertRaises(ValueError):
            state.acknowledge(1)

    def test_card_replacement_does_not_reset_sequence(self):
        state = SequenceState()
        state.allocate()
        replacement = Journal()
        state.reboot()
        value = state.allocate()
        replacement.append(encode_record(bytes(16), Interval(sequence=value)))
        self.assertEqual(value, 65)

    def test_reset_boundary(self):
        state = SequenceState()
        state.allocate()
        state.reset(100, 1)
        self.assertEqual(state.allocate(), 101)
        self.assertEqual(state.acknowledged, 100)


class NetworkAndCommandTests(unittest.TestCase):
    def test_heartbeat_priority(self):
        scheduler = Scheduler()
        backlog = 1000
        beats = []
        for now in range(61):
            beat, backlog = scheduler.tick(now, True, backlog)
            if beat:
                beats.append(now)
        self.assertEqual(beats, [0, 15, 30, 45, 60])
        self.assertLess(backlog, 1000)

    def test_wifi_outage_does_not_stop_measurement(self):
        device = SimulatedDevice()
        for _ in range(10):
            device.measure_interval()
            device.synchronize(False)
        self.assertEqual(device.measurement_count, 600)
        self.assertFalse(device.sync_latched)

    def test_reconnect_and_backfill(self):
        device = SimulatedDevice()
        for _ in range(100):
            device.measure_interval()
        device.synchronize(False)
        device.synchronize(True)
        self.assertEqual(device.sequence.acknowledged, device.sequence.maximum_seen)

    def test_command_idempotency(self):
        ledger = CommandLedger()
        self.assertEqual(ledger.accept("c", "k", "sync_now", "{}"), "accepted")
        ledger.transition("c", "succeeded")
        self.assertEqual(ledger.accept("c", "k", "sync_now", "{}"), "succeeded")

    def test_command_conflict(self):
        ledger = CommandLedger()
        ledger.accept("c", "k", "sync_now", "{}")
        with self.assertRaisesRegex(ValueError, "command_conflict"):
            ledger.accept("c", "k", "reboot", "{}")

    def test_terminal_command_is_stable(self):
        ledger = CommandLedger()
        ledger.accept("c", "k", "sync_now", "{}")
        ledger.transition("c", "failed")
        with self.assertRaisesRegex(ValueError, "terminal_transition"):
            ledger.transition("c", "running")

    def test_boot_recovery_policy_is_explicit_for_every_active_state(self):
        replayable = {
            "sync_now",
            "diagnostics_snapshot",
            "network_self_test",
            "meter_self_test",
            "storage_self_test",
        }
        all_types = replayable | {
            "reboot",
            "maintenance_sleep",
            "apply_configuration",
            "rotate_device_credentials",
            "ota_install",
            "format_storage_commit",
            "data_reset_commit",
        }
        for command_type in all_types:
            self.assertEqual(
                command_boot_action(command_type, "accepted"),
                "requeue" if command_type in replayable else "fail_interrupted",
            )
            expected_running = (
                "reconcile_ota" if command_type == "ota_install"
                else "requeue" if command_type in replayable
                else "fail_interrupted"
            )
            self.assertEqual(command_boot_action(command_type, "running"), expected_running)
        self.assertEqual(command_boot_action("reboot", "awaiting_reboot"), "complete_reboot")
        self.assertEqual(command_boot_action("ota_install", "awaiting_reboot"), "reconcile_ota")
        self.assertEqual(command_boot_action("maintenance_sleep", "awaiting_heartbeat"), "complete_wake")
        self.assertEqual(command_boot_action("apply_configuration", "awaiting_reboot"), "fail_interrupted")
        self.assertEqual(command_boot_action("sync_now", "succeeded"), "ignore")


class SecurityTests(unittest.TestCase):
    def test_secret_redaction(self):
        sanitized = redact('password="hunter2",token=abc,voltage=120')
        self.assertNotIn("hunter2", sanitized)
        self.assertNotIn("abc", sanitized)
        self.assertIn("voltage=120", sanitized)

    def test_missing_is_not_zero(self):
        device = SimulatedDevice()
        device.inject("pzem_absent")
        self.assertEqual(device.server_sequences, set())

    def test_untrusted_time_not_uploaded_as_history(self):
        device = SimulatedDevice()
        sequence = device.measure_interval(trusted=False)
        device.synchronize(True)
        self.assertNotIn(sequence, device.server_sequences)
        self.assertIn(sequence, device.unavailable)


class ReleaseWorkflowTests(unittest.TestCase):
    @staticmethod
    def _ci_workflow() -> str:
        return (
            Path(__file__).resolve().parents[2] / ".github" / "workflows" / "ci.yml"
        ).read_text(encoding="utf-8")

    @staticmethod
    def _release_workflow() -> str:
        return (
            Path(__file__).resolve().parents[2] / ".github" / "workflows" / "release.yml"
        ).read_text(encoding="utf-8")

    def test_signed_tag_object_is_fetched_into_an_isolated_ref(self):
        workflow = self._release_workflow()
        self.assertIn('signed_tag_ref="refs/powermeter-release-tags/${GITHUB_REF_NAME}"', workflow)
        self.assertIn('"+refs/tags/${GITHUB_REF_NAME}:${signed_tag_ref}"', workflow)
        self.assertIn('git rev-parse "${signed_tag_ref}^{tag}"', workflow)
        self.assertIn('git rev-parse "${signed_tag_ref}^{}"', workflow)
        trust_step = 'git config --global --add safe.directory "$GITHUB_WORKSPACE"'
        idf_trust_step = 'git config --global --add safe.directory "$IDF_PATH"'
        verify_step = "Verify checked-out release source and pinned framework"
        self.assertIn(trust_step, workflow)
        self.assertIn(idf_trust_step, workflow)
        self.assertLess(workflow.index(trust_step), workflow.index(verify_step))
        self.assertLess(workflow.index(idf_trust_step), workflow.index(verify_step))

    def test_release_container_uses_only_the_idf_python_environment(self):
        workflow = self._release_workflow()
        build_release = workflow.split("\n  build_release:\n", 1)[1].split(
            "\n  attest_release:\n", 1
        )[0]
        wrapper = "/opt/esp/entrypoint.sh python"
        self.assertEqual(build_release.count(wrapper), 8)
        raw_python_commands = [
            line.strip()
            for line in build_release.splitlines()
            if line.strip().startswith(("run: python", "python "))
        ]
        self.assertEqual(raw_python_commands, [])

    def test_ci_validates_release_requirements_in_the_pinned_idf_container(self):
        workflow = self._ci_workflow()
        esp_idf_build = workflow.split("\n  esp-idf-build:\n", 1)[1].split(
            "\n  powershell-contract:\n", 1
        )[0]
        image = (
            "container: espressif/idf:v6.0.2@sha256:"
            "0d8c9773d48a327233f9c1d7c654ff0bcf133ae24503ea2e97a57cfe02b8cb67"
        )
        install = "/opt/esp/entrypoint.sh python -m pip install"
        self.assertIn(image, esp_idf_build)
        self.assertEqual(esp_idf_build.count(install), 1)
        self.assertIn("--require-hashes -r test/host/requirements.txt", esp_idf_build)
        self.assertLess(
            esp_idf_build.index(install),
            esp_idf_build.index("Release-candidate build"),
        )

    def test_rpds_python_311_and_312_wheel_hashes_are_exact(self):
        requirements = (
            Path(__file__).resolve().parent / "requirements.txt"
        ).read_text(encoding="utf-8")
        rpds_030 = requirements.split(
            'rpds-py==0.30.0; python_version < "3.13"', 1
        )[1].split("rpds-py==2026.6.3", 1)[0]
        self.assertEqual(
            set(re.findall(r"--hash=sha256:([0-9a-f]{64})", rpds_030)),
            {
                "33f559f3104504506a44bb666b93a33f5d33133765b0c216a5bf2f1e1503af89",
                "47f236970bccb2233267d89173d3ad2703cd36a0e2a6e92d0560d333871a3d23",
                "a51033ff701fca756439d641c0ad09a41d9242fa69121c7d8769604a0a629825",
            },
        )


class PersistenceSafetySourceTests(unittest.TestCase):
    @staticmethod
    def _source(relative: str) -> str:
        return (Path(__file__).resolve().parents[2] / relative).read_text(encoding="utf-8")

    def test_sequence_recovery_never_reinitializes_corrupt_or_unreadable_slots(self):
        source = self._source("components/pm_storage/pm_sequence.c")
        self.assertIn("error_a != ESP_ERR_NVS_NOT_FOUND || error_b != ESP_ERR_NVS_NOT_FOUND", source)
        self.assertIn("a.state.generation == b.state.generation", source)
        self.assertIn("memcmp(&a.state, &b.state, sizeof(a.state)) != 0", source)
        self.assertIn("state->generation == UINT32_MAX", source)

    def test_identity_is_created_only_when_the_nvs_key_is_absent(self):
        source = self._source("main/app_main.c")
        load = source.split("static esp_err_t load_or_create_identity", 1)[1].split(
            "static esp_err_t persist_identity", 1
        )[0]
        self.assertIn("error == ESP_ERR_NVS_NOT_FOUND", load)
        self.assertIn("error != ESP_OK", load)
        self.assertIn("return ESP_ERR_INVALID_CRC", load)
        self.assertIn("prior.generation == UINT32_MAX", source)

    def test_ota_checkpoint_writes_are_blocking_and_ota_is_single_flight(self):
        ota = self._source("components/pm_ota/pm_ota.c")
        app = self._source("main/app_main.c")
        self.assertNotIn("(void)persist_checkpoint", ota)
        self.assertIn("checkpoint->generation == UINT32_MAX", ota)
        self.assertIn("error_a != ESP_ERR_NVS_NOT_FOUND || error_b != ESP_ERR_NVS_NOT_FOUND", ota)
        self.assertIn("a.generation == b.generation && memcmp(&a, &b, sizeof(a)) != 0", ota)
        self.assertIn("static bool claim_ota_task", app)
        self.assertIn("result = claim_ota_task() ? ESP_OK : ESP_ERR_INVALID_STATE", app)

    def test_authenticated_http_uses_bounded_response_header_events(self):
        network = self._source("components/pm_network/pm_network.c")
        ota = self._source("components/pm_ota/pm_ota.c")
        capture = self._source("components/pm_protocol/pm_http_response.c")
        self.assertNotIn("esp_http_client_get_header", network + ota)
        self.assertEqual((network + ota).count("HTTP_EVENT_ON_HEADER"), 2)
        self.assertEqual((network + ota).count("pm_http_response_capture_validate"), 2)
        self.assertIn("PM_HTTP_REQUIRED_AUTH_MASK", capture)
        self.assertIn("(capture->seen_mask & field) != 0U", capture)
        self.assertIn("length >= capacity", capture)

    def test_ota_requires_a_strict_semantic_version_upgrade(self):
        ota = self._source("components/pm_ota/pm_ota.c")
        policy = self._source("components/pm_ota/pm_ota_version.c")
        network = self._source("components/pm_network/pm_network.c")
        self.assertIn("pm_ota_version_require_upgrade(running->version, manifest->version)", ota)
        self.assertIn('strncmp(cursor, "-rc.", 4U)', policy)
        self.assertIn("wire_value > UINT8_MAX ? UINT8_MAX", self._source(
            "components/pm_network/pm_command_envelope.c"
        ))
        self.assertIn("pm_command_attempt_from_json_number", network)

    def test_wifi_plaintext_stack_copy_is_zeroized(self):
        source = self._source("components/pm_network/pm_network.c")
        configure = source.split("static esp_err_t configure_wifi", 1)[1].split(
            "static esp_err_t connect_wifi_bounded", 1
        )[0]
        self.assertIn("secure_zero_memory(&wifi, sizeof(wifi))", configure)


if __name__ == "__main__":
    unittest.main(verbosity=2)
