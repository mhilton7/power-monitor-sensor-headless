from __future__ import annotations

import base64
import hashlib
import hmac
import struct
import unittest

from pm_model import (
    ABStore, CommandLedger, Interval, Journal, Scheduler, SequenceState, SimulatedDevice, canonical_query,
    canonical_request, decode_record, directional_keys, encode_record, hkdf, modbus_crc16, protocol_vector,
    pzem_parse, pzem_request, redact,
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


if __name__ == "__main__":
    unittest.main(verbosity=2)
