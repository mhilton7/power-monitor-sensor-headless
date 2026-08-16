"""Deterministic host model for PowerMeter V2 firmware invariants.

This model deliberately uses only the Python standard library. It shares the
wire/storage constants with the C implementation and is used for exhaustive
power-cut schedules that are impractical to execute on every firmware build.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
import base64
import hashlib
import hmac
import json
import random
import struct
import uuid
import zlib

PROTOCOL = "pm-protocol/1.0.0"
SEGMENT_MAGIC = 0x504D5347
RECORD_MAGIC = 0x504D5244
SEGMENT_SIZE = 96
RECORD_SIZE = 128


def modbus_crc16(data: bytes) -> int:
    crc = 0xFFFF
    for value in data:
        crc ^= value
        for _ in range(8):
            crc = (crc >> 1) ^ (0xA001 if crc & 1 else 0)
    return crc


def pzem_request(address: int = 1) -> bytes:
    prefix = bytes((address, 4, 0, 0, 0, 10))
    return prefix + struct.pack("<H", modbus_crc16(prefix))


def pzem_parse(frame: bytes, address: int = 1) -> dict[str, int]:
    if len(frame) != 25:
        raise ValueError("short_frame")
    if modbus_crc16(frame[:-2]) != struct.unpack("<H", frame[-2:])[0]:
        raise ValueError("bad_crc")
    if frame[0] != address:
        raise ValueError("wrong_slave")
    if frame[1:3] != bytes((4, 20)):
        raise ValueError("wrong_function")

    def word(offset: int) -> int:
        return struct.unpack(">H", frame[offset : offset + 2])[0]

    def low_high(offset: int) -> int:
        return word(offset) | word(offset + 2) << 16

    result = {
        "voltage_mv": word(3) * 100,
        "current_ma": low_high(5),
        "active_power_mw": low_high(9) * 100,
        "energy_wh": low_high(13),
        "frequency_mhz": word(17) * 100,
        "power_factor_milli": word(19) * 10,
        "alarm": word(21),
    }
    if not (
        0 <= result["voltage_mv"] <= 300_000
        and 0 <= result["current_ma"] <= 110_000
        and 0 <= result["active_power_mw"] <= 30_000_000
        and 40_000 <= result["frequency_mhz"] <= 70_000
        and 0 <= result["power_factor_milli"] <= 1000
    ):
        raise ValueError("invalid_range")
    return result


def canonical_query(query: str) -> str:
    if not query:
        return ""
    if len(query) >= 384 or "+" in query or "#" in query:
        raise ValueError("invalid_query")
    parts = query.split("&")
    if len(parts) > 32 or any(not part or any(ord(c) <= 0x20 for c in part) for part in parts):
        raise ValueError("invalid_query")
    for part in parts:
        index = 0
        while index < len(part):
            if part[index] == "%":
                if index + 2 >= len(part) or any(c not in "0123456789abcdefABCDEF" for c in part[index + 1 : index + 3]):
                    raise ValueError("invalid_escape")
                index += 3
            else:
                index += 1
    normalized = []
    for part in parts:
        chars = list(part)
        for index, char in enumerate(chars[:-2]):
            if char == "%":
                chars[index + 1] = chars[index + 1].upper()
                chars[index + 2] = chars[index + 2].upper()
        normalized.append("".join(chars))
    return "&".join(sorted(normalized))


def canonical_request(method: str, path: str, query: str, timestamp: str, nonce: str, body_hash: str) -> str:
    if not path.startswith("/"):
        raise ValueError("invalid_path")
    target = path
    normalized = canonical_query(query)
    if normalized:
        target += "?" + normalized
    return "\n".join(("PM-HMAC-SHA256-V1", method.upper(), target, timestamp, nonce, body_hash.lower()))


def hkdf(secret: bytes, salt: bytes, info: bytes, length: int = 32) -> bytes:
    prk = hmac.new(salt, secret, hashlib.sha256).digest()
    result = b""
    previous = b""
    counter = 1
    while len(result) < length:
        previous = hmac.new(prk, previous + info + bytes((counter,)), hashlib.sha256).digest()
        result += previous
        counter += 1
    return result[:length]


def directional_keys(secret: bytes, device_id: bytes | str) -> tuple[bytes, bytes]:
    device_id_text = str(uuid.UUID(bytes=device_id)) if isinstance(device_id, bytes) else str(uuid.UUID(device_id))
    salt = (PROTOCOL + "\0" + device_id_text).encode()
    return (
        hkdf(secret, salt, b"PowerMeter V2\0device-to-server"),
        hkdf(secret, salt, b"PowerMeter V2\0server-to-device"),
    )


@dataclass(frozen=True)
class Interval:
    sequence: int
    reset_generation: int = 0
    flags: int = 0
    start_utc_ms: int = 0
    end_utc_ms: int = 0
    start_monotonic_us: int = 0
    end_monotonic_us: int = 60_000_000
    sample_count: int = 60
    expected_samples: int = 60
    completeness_permille: int = 1000
    energy_source: int = 1
    voltage_mv: int = 120_000
    current_ma: int = 1_000
    active_power_mw: int = 120_000
    frequency_mhz: int = 60_000
    power_factor_milli: int = 990
    pzem_energy_start_wh: int = 0
    pzem_energy_end_wh: int = 1
    selected_energy_mwh: int = 1_000


def encode_record(device_id: bytes, interval: Interval) -> bytes:
    if len(device_id) != 16 or interval.sequence <= 0:
        raise ValueError("invalid_record")
    data = bytearray(RECORD_SIZE)
    struct.pack_into("<IHH", data, 0, RECORD_MAGIC, 1, RECORD_SIZE)
    data[8:24] = device_id
    struct.pack_into("<QIIqqqqIIHHiiiiiQQI", data, 24, interval.sequence, interval.reset_generation,
                     interval.flags, interval.start_utc_ms, interval.end_utc_ms, interval.start_monotonic_us,
                     interval.end_monotonic_us, interval.sample_count, interval.expected_samples,
                     interval.completeness_permille, interval.energy_source, interval.voltage_mv,
                     interval.current_ma, interval.active_power_mw, interval.frequency_mhz,
                     interval.power_factor_milli, interval.pzem_energy_start_wh, interval.pzem_energy_end_wh,
                     min(interval.selected_energy_mwh, 0xFFFFFFFF))
    struct.pack_into("<I", data, 124, zlib.crc32(data[:124]) & 0xFFFFFFFF)
    return bytes(data)


def decode_record(data: bytes) -> Interval:
    if len(data) != RECORD_SIZE:
        raise ValueError("record_size")
    magic, version, length = struct.unpack_from("<IHH", data)
    if (magic, version, length) != (RECORD_MAGIC, 1, RECORD_SIZE):
        raise ValueError("record_header")
    if zlib.crc32(data[:124]) & 0xFFFFFFFF != struct.unpack_from("<I", data, 124)[0]:
        raise ValueError("record_crc")
    values = struct.unpack_from("<QIIqqqqIIHHiiiiiQQI", data, 24)
    if values[0] <= 0 or values[9] > 1000:
        raise ValueError("record_semantics")
    return Interval(
        sequence=values[0], reset_generation=values[1], flags=values[2], start_utc_ms=values[3],
        end_utc_ms=values[4], start_monotonic_us=values[5], end_monotonic_us=values[6],
        sample_count=values[7], expected_samples=values[8], completeness_permille=values[9],
        energy_source=values[10], voltage_mv=values[11], current_ma=values[12],
        active_power_mw=values[13], frequency_mhz=values[14], power_factor_milli=values[15],
        pzem_energy_start_wh=values[16], pzem_energy_end_wh=values[17], selected_energy_mwh=values[18],
    )


@dataclass
class ABStore:
    slots: dict[str, tuple[int, bytes, int]] = field(default_factory=dict)
    active: str = "a"

    def commit(self, payload: bytes, fail_after: str | None = None) -> bool:
        inactive = "b" if self.active == "a" else "a"
        generation = max((entry[0] for entry in self.slots.values()), default=0) + 1
        encoded = (generation, payload, zlib.crc32(payload) & 0xFFFFFFFF)
        if fail_after == "before_write":
            return False
        self.slots[inactive] = encoded
        if fail_after == "after_write":
            return False
        if zlib.crc32(self.slots[inactive][1]) & 0xFFFFFFFF != self.slots[inactive][2]:
            return False
        if fail_after == "after_readback":
            return False
        self.active = inactive
        return True

    def load(self) -> bytes | None:
        valid = [entry for entry in self.slots.values() if zlib.crc32(entry[1]) & 0xFFFFFFFF == entry[2]]
        return max(valid, default=(0, None, 0), key=lambda entry: entry[0])[1]


@dataclass
class SequenceState:
    next_sequence: int = 1
    reserved_through: int = 0
    maximum_seen: int = 0
    acknowledged: int = 0
    reset_generation: int = 0

    def allocate(self) -> int:
        if self.next_sequence > self.reserved_through:
            self.reserved_through = self.next_sequence + 63
        value = self.next_sequence
        self.next_sequence += 1
        self.maximum_seen = value
        return value

    def reboot(self) -> None:
        self.next_sequence = max(self.next_sequence, self.reserved_through + 1)

    def acknowledge(self, sequence: int) -> None:
        if not self.acknowledged <= sequence <= self.maximum_seen:
            raise ValueError("ack_regression_or_future")
        self.acknowledged = sequence

    def reset(self, floor: int, generation: int) -> None:
        if floor < self.maximum_seen or generation <= self.reset_generation:
            raise ValueError("reset_regression")
        self.maximum_seen = floor
        self.acknowledged = floor
        self.reserved_through = floor
        self.next_sequence = floor + 1
        self.reset_generation = generation


@dataclass
class Journal:
    records: list[bytes] = field(default_factory=list)
    trailing: bytes = b""
    corrupt_ranges: list[tuple[int, int]] = field(default_factory=list)
    full: bool = False
    read_only: bool = False

    def append(self, data: bytes, fail_after: str | None = None) -> bool:
        if self.full or self.read_only:
            return False
        if fail_after == "before_write":
            return False
        if fail_after == "partial_write":
            self.trailing = data[: len(data) // 2]
            return False
        self.trailing = data
        if fail_after == "before_flush":
            return False
        self.records.append(data)
        self.trailing = b""
        return True

    def recover(self) -> list[Interval]:
        self.trailing = b""
        valid: list[Interval] = []
        for data in self.records:
            try:
                valid.append(decode_record(data))
            except ValueError:
                continue
        return valid

    def retain(self, acknowledged: int, maximum_records: int) -> None:
        while len(self.records) > maximum_records:
            sequence = decode_record(self.records[0]).sequence
            if sequence > acknowledged:
                self.full = True
                return
            self.records.pop(0)


@dataclass
class Scheduler:
    heartbeat_period: int = 15
    next_heartbeat: int = 0
    missed: int = 0
    last_heartbeat: int = -1

    def tick(self, now: int, server_up: bool, backlog: int) -> tuple[bool, int]:
        heartbeat = now >= self.next_heartbeat
        if heartbeat:
            if server_up:
                self.last_heartbeat = now
                self.missed = 0
            else:
                self.missed += 1
            self.next_heartbeat = now + self.heartbeat_period
            return True, backlog
        if server_up and backlog and now + 5 < self.next_heartbeat:
            return False, backlog - min(backlog, 16)
        return False, backlog


@dataclass
class CommandLedger:
    entries: dict[str, tuple[str, str, str]] = field(default_factory=dict)

    def accept(self, command_id: str, key: str, command_type: str, payload: str) -> str:
        fingerprint = hashlib.sha256((command_type + "\0" + payload).encode()).hexdigest()
        for existing_id, (existing_key, existing_fingerprint, state) in self.entries.items():
            if existing_id == command_id or existing_key == key:
                if existing_fingerprint != fingerprint:
                    raise ValueError("command_conflict")
                return state
        self.entries[command_id] = (key, fingerprint, "accepted")
        return "accepted"

    def transition(self, command_id: str, state: str) -> None:
        key, fingerprint, old = self.entries[command_id]
        if old in {"succeeded", "failed", "expired", "cancelled", "rolled_back"} and state != old:
            raise ValueError("terminal_transition")
        self.entries[command_id] = (key, fingerprint, state)


REPLAYABLE_AFTER_REBOOT = {
    "sync_now",
    "diagnostics_snapshot",
    "network_self_test",
    "meter_self_test",
    "storage_self_test",
}


def command_boot_action(command_type: str, state: str) -> str:
    if state in {"accepted", "running"}:
        if state == "running" and command_type == "ota_install":
            return "reconcile_ota"
        return "requeue" if command_type in REPLAYABLE_AFTER_REBOOT else "fail_interrupted"
    if state == "awaiting_reboot":
        if command_type == "reboot":
            return "complete_reboot"
        if command_type == "ota_install":
            return "reconcile_ota"
        return "fail_interrupted"
    if state == "awaiting_heartbeat":
        return "complete_wake" if command_type == "maintenance_sleep" else "fail_interrupted"
    return "ignore"


def redact(text: str) -> str:
    result = text
    for key in ("password", "secret", "token", "authorization", "cookie", "private_key", "hmac_key"):
        for separator in ("=", ":"):
            start = 0
            while True:
                index = result.lower().find(key + separator, start)
                if index < 0:
                    break
                value_start = index + len(key) + 1
                quote = result[value_start] if value_start < len(result) and result[value_start] in "\"'" else ""
                if quote:
                    value_start += 1
                    end = result.find(quote, value_start)
                else:
                    endings = [position for char in ",}\r\n " if (position := result.find(char, value_start)) >= 0]
                    end = min(endings, default=len(result))
                result = result[:value_start] + "[REDACTED]" + result[end:]
                start = value_start + len("[REDACTED]")
    return result


FAULTS = (
    "power_loss_storage_header", "power_loss_storage_record", "power_loss_storage_flush",
    "power_loss_config_write", "power_loss_config_readback", "power_loss_config_commit",
    "power_loss_format_prepare", "power_loss_format_commit", "power_loss_ota_begin", "power_loss_ota_write",
    "power_loss_ota_verify", "power_loss_ota_boot_select", "sd_removal_append", "sd_removal_sync",
    "corrupt_record", "corrupt_segment_header", "corrupt_index", "full_card", "read_only_card", "pzem_absent",
    "pzem_intermittent", "wifi_ap_loss", "dhcp_failure", "dns_failure", "tls_handshake_timeout", "wrong_ca",
    "wrong_hostname", "server_connection_reset", "server_429", "server_500", "server_timeout",
    "partial_response", "large_backlog", "command_duplicated", "command_expired", "reboot_during_command",
)


@dataclass
class SimulatedDevice:
    device_id: bytes = bytes(range(16))
    sequence: SequenceState = field(default_factory=SequenceState)
    journal: Journal = field(default_factory=Journal)
    scheduler: Scheduler = field(default_factory=Scheduler)
    commands: CommandLedger = field(default_factory=CommandLedger)
    server_sequences: set[int] = field(default_factory=set)
    unavailable: set[int] = field(default_factory=set)
    measurement_count: int = 0
    heartbeat_count: int = 0
    config: ABStore = field(default_factory=ABStore)
    credentials_present: bool = True
    sync_latched: bool = False
    ota_bootable: bool = False
    upload_index: int = 0

    def measure_interval(self, trusted: bool = True, store: bool = True) -> int:
        sequence = self.sequence.allocate()
        self.measurement_count += 60
        interval = Interval(
            sequence=sequence,
            reset_generation=self.sequence.reset_generation,
            flags=0 if trusted else 1,
            start_utc_ms=1_760_000_000_000 + sequence * 60_000 if trusted else 0,
            end_utc_ms=1_760_000_060_000 + sequence * 60_000 if trusted else 0,
            pzem_energy_start_wh=sequence - 1,
            pzem_energy_end_wh=sequence,
        )
        if not store or not self.journal.append(encode_record(self.device_id, interval)):
            self.unavailable.add(sequence)
        return sequence

    def synchronize(self, server_up: bool = True) -> None:
        self.sync_latched = True
        try:
            if not server_up:
                return
            for encoded in self.journal.records[self.upload_index :]:
                try:
                    interval = decode_record(encoded)
                except ValueError:
                    continue
                if interval.flags & 1:
                    self.unavailable.add(interval.sequence)
                    continue
                self.server_sequences.add(interval.sequence)
            self.upload_index = len(self.journal.records)
            contiguous = self.sequence.acknowledged
            while contiguous + 1 in self.server_sequences or contiguous + 1 in self.unavailable:
                contiguous += 1
            if contiguous <= self.sequence.maximum_seen:
                self.sequence.acknowledge(contiguous)
        finally:
            self.sync_latched = False

    def reboot(self) -> None:
        first_lost = self.sequence.next_sequence
        last_lost = self.sequence.reserved_through
        if first_lost <= last_lost:
            self.unavailable.update(range(first_lost, last_lost + 1))
        self.sequence.reboot()

    def inject(self, fault: str) -> None:
        if fault.startswith("power_loss_config"):
            stage = {"power_loss_config_write": "after_write", "power_loss_config_readback": "after_readback",
                     "power_loss_config_commit": None}[fault]
            self.config.commit(b"valid-config", stage)
        elif fault in {"power_loss_storage_header", "power_loss_storage_record", "power_loss_storage_flush"}:
            sequence = self.sequence.allocate()
            data = encode_record(self.device_id, Interval(sequence=sequence))
            stage = "before_write" if fault.endswith("header") else ("partial_write" if fault.endswith("record") else "before_flush")
            if not self.journal.append(data, stage):
                self.unavailable.add(sequence)
            self.journal.recover()
        elif fault in {"sd_removal_append", "read_only_card"}:
            self.journal.read_only = True
            self.measure_interval(store=True)
            self.journal.read_only = False
        elif fault in {"full_card"}:
            self.journal.full = True
            self.measure_interval(store=True)
            self.journal.full = False
        elif fault == "corrupt_record":
            self.measure_interval()
            corrupt = bytearray(self.journal.records[-1])
            corrupt[84] ^= 1
            self.journal.records[-1] = bytes(corrupt)
            self.unavailable.add(self.sequence.maximum_seen)
            self.journal.recover()
        elif fault == "large_backlog":
            for _ in range(1000):
                self.measure_interval()
            backlog = 1000
            for now in range(0, 61):
                heartbeat, backlog = self.scheduler.tick(now, True, backlog)
                self.heartbeat_count += int(heartbeat)
        elif fault == "command_duplicated":
            self.commands.accept("c1", "k1", "sync_now", "{}")
            self.commands.accept("c1", "k1", "sync_now", "{}")
        elif fault == "command_expired":
            self.commands.accept("c2", "k2", "reboot", "{}")
            self.commands.transition("c2", "expired")
        elif fault == "reboot_during_command":
            self.commands.accept("c3", "k3", "ota_install", "{}")
            self.commands.transition("c3", "running")
            self.reboot()
            self.commands.transition("c3", "failed")
        elif fault.startswith("power_loss_ota"):
            self.ota_bootable = fault == "power_loss_ota_boot_select"
        elif fault in {"wifi_ap_loss", "dhcp_failure", "dns_failure", "tls_handshake_timeout", "wrong_ca",
                       "wrong_hostname", "server_connection_reset", "server_429", "server_500", "server_timeout",
                       "partial_response", "sd_removal_sync"}:
            self.measure_interval()
            self.synchronize(server_up=False)
            self.synchronize(server_up=True)
        elif fault in {"pzem_absent", "pzem_intermittent"}:
            self.measurement_count += 60
        elif fault in {"corrupt_segment_header", "corrupt_index", "power_loss_format_prepare", "power_loss_format_commit"}:
            self.measure_interval()
            self.journal.recover()
        else:
            raise ValueError(f"unhandled fault {fault}")

    def assert_invariants(self) -> None:
        valid = self.journal.recover()
        sequences = [record.sequence for record in valid]
        if len(sequences) != len(set(sequences)):
            raise AssertionError("sequence reuse")
        if self.sequence.acknowledged > self.sequence.maximum_seen:
            raise AssertionError("ack beyond maximum")
        if not self.credentials_present:
            raise AssertionError("credential loss")
        if self.sync_latched:
            raise AssertionError("permanent sync latch")


def accelerated_simulation(days: int = 120, seed: int = 0x504D5632) -> dict[str, int]:
    random_source = random.Random(seed)
    device = SimulatedDevice()
    total_intervals = days * 24 * 60
    outage_intervals = 0
    restarts = 0
    corruptions = 0
    for minute in range(total_intervals):
        server_up = random_source.random() >= 0.015
        trusted = random_source.random() >= 0.002
        device.measure_interval(trusted=trusted)
        outage_intervals += int(not server_up)
        if random_source.random() < 0.0008:
            device.reboot()
            restarts += 1
        if random_source.random() < 0.0003 and device.journal.records:
            corrupt = bytearray(device.journal.records[-1])
            corrupt[90] ^= 1
            device.journal.records[-1] = bytes(corrupt)
            device.unavailable.add(device.sequence.maximum_seen)
            corruptions += 1
        if minute % 5 == 0:
            device.synchronize(server_up)
        if minute % 15 == 0:
            heartbeat, _ = device.scheduler.tick(minute * 60, server_up, 0)
            device.heartbeat_count += int(heartbeat)
    device.synchronize(True)
    device.assert_invariants()
    if device.sequence.acknowledged != device.sequence.maximum_seen:
        raise AssertionError("final contiguous acknowledgement did not converge")
    return {
        "days": days,
        "intervals": total_intervals,
        "samples": device.measurement_count,
        "outage_intervals": outage_intervals,
        "restarts": restarts,
        "corruptions": corruptions,
        "heartbeats": device.heartbeat_count,
        "highest_sequence": device.sequence.maximum_seen,
        "acknowledged": device.sequence.acknowledged,
    }


def protocol_vector() -> dict[str, str]:
    secret = bytes(range(32))
    device_id = "123e4567-e89b-12d3-a456-426614174000"
    outbound, inbound = directional_keys(secret, device_id)
    body = b"sample-body"
    body_hash = hashlib.sha256(body).hexdigest()
    canonical = canonical_request("post", "/api/v1/device/readings", "b=two&a=1", "1786641600",
                                  "0123456789abcdef0123456789abcdef", body_hash)
    signature = base64.b64encode(hmac.new(outbound, canonical.encode(), hashlib.sha256).digest()).decode()
    return {
        "protocol": PROTOCOL,
        "device_secret_hex": secret.hex(),
        "device_id": device_id,
        "device_to_server_key_hex": outbound.hex(),
        "server_to_device_key_hex": inbound.hex(),
        "body_hex": body.hex(),
        "content_sha256": body_hash,
        "canonical": canonical,
        "signature_base64": signature,
    }


if __name__ == "__main__":
    print(json.dumps(accelerated_simulation(), sort_keys=True))
