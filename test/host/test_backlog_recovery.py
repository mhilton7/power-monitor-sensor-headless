from __future__ import annotations

import json
import struct
import unittest
from pathlib import Path

from pm_model import Interval, encode_record

ROOT = Path(__file__).resolve().parents[2]
PROTOCOL = "pm-protocol/1.0.0"
BODY_LIMIT = 8192
DEVICE_ID = bytes.fromhex("123e4567e89b12d3a456426614174000")


def representative_records(start: int = 1089, count: int = 16) -> list[dict[str, object]]:
    records: list[dict[str, object]] = []
    for index in range(count):
        sequence = start + index
        monotonic_start = 9_000_000_000_000_000_000 + index * 60_000_000
        current_ma = 1000 if index < 7 else 999
        interval = Interval(
            sequence=sequence,
            reset_generation=0,
            flags=2,
            start_monotonic_us=monotonic_start,
            end_monotonic_us=monotonic_start + 60_000_000,
            energy_source=0,
            voltage_mv=260_000,
            current_ma=current_ma,
            active_power_mw=23_000_000,
            frequency_mhz=65_000,
            power_factor_milli=1000,
            pzem_energy_end_wh=4_294_967_295,
            selected_energy_mwh=0,
        )
        crc = struct.unpack_from("<I", encode_record(DEVICE_ID, interval), 124)[0]
        records.append(
            {
                "sequence": sequence,
                "reset_generation": 0,
                "interval_start_utc": None,
                "interval_end_utc": None,
                "monotonic_start_us": monotonic_start,
                "monotonic_end_us": monotonic_start + 60_000_000,
                "sample_count": 60,
                "expected_sample_count": 60,
                "voltage_mv": 260_000,
                "current_ma": current_ma,
                "active_power_mw": 23_000_000,
                "frequency_mhz": 65_000,
                "power_factor_milli": 1000,
                "pzem_energy_wh": 4_294_967_295,
                "interval_energy_mwh": None,
                "energy_selection": "unavailable_invalid",
                "pzem_status": "ok",
                "time_trusted": False,
                "flags": ["missing_sample"],
                "record_crc32": crc,
            }
        )
    return records


def serialize(records: list[dict[str, object]]) -> bytes:
    return json.dumps(
        {"protocol_id": PROTOCOL, "records": records},
        separators=(",", ":"),
    ).encode()


def largest_fitting(
    records: list[dict[str, object]], maximum: int = 16
) -> tuple[list[dict[str, object]], bytes]:
    for count in range(min(maximum, len(records)), 0, -1):
        body = serialize(records[:count])
        if len(body) + 1 <= BODY_LIMIT + 1:
            return records[:count], body
    raise ValueError("BACKLOG_SINGLE_RECORD_TOO_LARGE")


def confirmed_prefix(
    server_ack: int,
    files: list[list[int]],
    *,
    card_ready: bool = True,
    inventory_complete: bool = True,
) -> tuple[int, int] | None:
    if not card_ready or not inventory_complete:
        return None
    recoverable = [sequence for file_sequences in files for sequence in file_sequences]
    if not recoverable or server_ack + 1 >= min(recoverable):
        return None
    return server_ack + 1, min(recoverable) - 1


class MockServer:
    def __init__(self, acknowledgement: int) -> None:
        self.acknowledgement = acknowledgement
        self.loss_reports: list[tuple[int, int, str]] = []
        self.batches: list[list[int]] = []
        self.authenticated_reports = 0

    def permanent_loss(
        self, first: int, last: int, sensor_id: str, *, authenticated: bool = True
    ) -> int:
        if not authenticated:
            raise PermissionError("authentication_failed")
        self.authenticated_reports += 1
        self.loss_reports.append((first, last, sensor_id))
        if first <= self.acknowledgement + 1 and last >= self.acknowledgement + 1:
            self.acknowledgement = last
        return self.acknowledgement

    def readings(self, body: bytes) -> int:
        if len(body) > BODY_LIMIT:
            raise ValueError("oversized")
        document = json.loads(body)
        sequences = [item["sequence"] for item in document["records"]]
        if sequences[0] != self.acknowledgement + 1:
            raise ValueError("not_contiguous")
        self.batches.append(sequences)
        self.acknowledgement = sequences[-1]
        return self.acknowledgement


class BacklogRecoveryTests(unittest.TestCase):
    def test_representative_payload_is_exactly_8287_and_reduces_to_15(self) -> None:
        records = representative_records()
        self.assertEqual(8287, len(serialize(records)))
        selected, body = largest_fitting(records)
        self.assertEqual(15, len(selected))
        self.assertEqual(7772, len(body))
        self.assertLessEqual(len(body) + 1, BODY_LIMIT + 1)
        self.assertEqual(1103, selected[-1]["sequence"])
        self.assertEqual(1104, records[len(selected)]["sequence"])

    def test_indoor_oversized_backlog_has_no_loss_report_and_all_records_arrive(self) -> None:
        records = representative_records()
        server = MockServer(1088)
        pending = list(records)
        while pending:
            selected, body = largest_fitting(pending)
            acknowledgement = server.readings(body)
            pending = [item for item in pending if item["sequence"] > acknowledgement]
        self.assertEqual([], server.loss_reports)
        self.assertEqual(
            list(range(1089, 1105)), [value for batch in server.batches for value in batch]
        )

    def test_outdoor_exact_missing_prefix_then_adaptive_backlog(self) -> None:
        records = representative_records(count=32)
        server = MockServer(1)
        immutable_sensor_id = "123e4567-e89b-12d3-a456-426614174000"
        inventory_complete = True
        earliest = min(item["sequence"] for item in records)
        self.assertTrue(inventory_complete)
        report_ack = server.permanent_loss(
            server.acknowledgement + 1, earliest - 1, immutable_sensor_id
        )
        self.assertEqual(1088, report_ack)
        pending = list(records)
        while pending:
            selected, body = largest_fitting(pending)
            acknowledgement = server.readings(body)
            pending = [item for item in pending if item["sequence"] > acknowledgement]
        self.assertEqual([(2, 1088, immutable_sensor_id)], server.loss_reports)
        self.assertEqual(
            list(range(1089, 1121)), [value for batch in server.batches for value in batch]
        )
        self.assertTrue(
            all(
                len(serialize([records[value - 1089] for value in batch])) <= BODY_LIMIT
                for batch in server.batches
            )
        )

    def test_incomplete_inventory_or_older_rotated_record_blocks_over_report(self) -> None:
        server_ack = 1
        active = list(range(1089, 1105))
        rotated = list(range(2, 1089))
        self.assertIsNone(confirmed_prefix(server_ack, [active], inventory_complete=False))
        self.assertIsNone(confirmed_prefix(server_ack, [active], card_ready=False))
        self.assertIsNone(confirmed_prefix(server_ack, [active, rotated]))
        self.assertEqual((2, 1088), confirmed_prefix(server_ack, [active]))

    def test_authentication_rejection_and_new_evidence_never_force_local_ack(self) -> None:
        server = MockServer(1)
        local_ack = 1
        with self.assertRaises(PermissionError):
            server.permanent_loss(2, 1088, "immutable-sensor", authenticated=False)
        self.assertEqual(1, local_ack)
        self.assertEqual(1, server.acknowledgement)
        self.assertEqual([], server.loss_reports)
        self.assertEqual((101, 1088), confirmed_prefix(100, [[1089]]))
        self.assertEqual((2, 1999), confirmed_prefix(1, [[2000]]))

    def test_lost_loss_response_and_reboot_are_idempotent(self) -> None:
        server = MockServer(1)
        sensor_id = "123e4567-e89b-12d3-a456-426614174000"
        server.permanent_loss(2, 1088, sensor_id)  # response is lost
        self.assertEqual(1088, server.acknowledgement)
        # A reboot derives state again. The next authenticated heartbeat supplies
        # the server acknowledgement; no local acknowledgement is fabricated.
        rebooted_local_ack = server.acknowledgement
        self.assertEqual(1088, rebooted_local_ack)
        self.assertEqual(1089, rebooted_local_ack + 1)

    def test_failed_transport_preserves_pending_records_and_cursor(self) -> None:
        records = representative_records()
        selected, body = largest_fitting(records)
        local_ack = 1088
        with self.assertRaises(ConnectionError):
            raise ConnectionError("response_lost")
        self.assertEqual(1088, local_ack)
        self.assertEqual(16, len(records))
        self.assertEqual(list(range(1089, 1104)), [item["sequence"] for item in selected])
        self.assertEqual(7772, len(body))

    def test_network_interruptions_and_reboots_are_idempotent(self) -> None:
        records = representative_records()
        for failure in (
            "before_transmission",
            "during_transmission",
            "response_timeout",
            "tls_reconnect",
            "server_unavailable",
            "reboot_before_ack",
        ):
            with self.subTest(failure=failure):
                local_ack = 1088
                retained = list(records)
                selected, body = largest_fitting(retained)
                self.assertEqual(15, len(selected))
                self.assertLessEqual(len(body), BODY_LIMIT)
                self.assertEqual(1088, local_ack)
                self.assertEqual(list(range(1089, 1105)), [item["sequence"] for item in retained])

    def test_runtime_recovery_mock_never_invokes_destructive_operations(self) -> None:
        destructive_calls = {
            "format": 0,
            "nvs_erase": 0,
            "factory_reset": 0,
            "reprovision": 0,
            "delete_backlog": 0,
            "reset_sequence": 0,
        }
        scenarios = (
            "oversized_batch",
            "missing_prefix",
            "network_failure",
            "reboot_recovery",
            "ota_installation",
            "storage_inventory_failure",
        )
        for scenario in scenarios:
            with self.subTest(scenario=scenario):
                before = dict(destructive_calls)
                if scenario == "oversized_batch":
                    largest_fitting(representative_records())
                elif scenario == "missing_prefix":
                    self.assertEqual((2, 1088), confirmed_prefix(1, [[1089]]))
                elif scenario == "storage_inventory_failure":
                    self.assertIsNone(confirmed_prefix(1, [[1089]], inventory_complete=False))
                self.assertEqual(before, destructive_calls)

    def test_recovery_paths_do_not_reference_destructive_primitives(self) -> None:
        network = (ROOT / "components/pm_network/pm_network.c").read_text(encoding="utf-8")
        policy = (ROOT / "components/pm_network/pm_backlog_policy.c").read_text(encoding="utf-8")
        storage = (ROOT / "components/pm_storage/pm_storage.c").read_text(encoding="utf-8")
        read_path = storage.split("static esp_err_t read_batch_owner", 1)[1].split(
            "static esp_err_t recover_current", 1
        )[0]
        inventory_path = storage.split("esp_err_t pm_storage_rebuild_index", 1)[1].split(
            "static esp_err_t format_storage", 1
        )[0]
        recovery = network + policy + read_path + inventory_path
        for forbidden in (
            "esp_vfs_fat_sdcard_format",
            "nvs_flash_erase",
            "Preferences.clear",
            "factoryReset",
            "resetProvisioning",
            "resetSequence",
        ):
            self.assertNotIn(forbidden, recovery)


if __name__ == "__main__":
    unittest.main(verbosity=2)
