"""Deterministic destructive-command recovery model.

The ESP-IDF implementation spans NVS, the sequence journal, and the SD card.
This model makes the required durable ordering explicit and lets the host test
suite cut power after every committed phase.  A checkpoint is atomic here; a
power cut can happen only before or after it, never turn it into a valid-looking
partial record.  The lower-level NVS/SD torn-write tests cover that assumption.

This is a safety model, not a second firmware implementation.  It intentionally
contains no clock, randomness, locally generated confirmation token, network,
or sensor behavior.
"""

from __future__ import annotations

import hmac
import json
import re
from dataclasses import dataclass, field
from enum import Enum

LOWER_HEX_128 = re.compile(r"^[0-9a-f]{32}$")


class DestructiveKind(str, Enum):
    FORMAT_STORAGE = "format_storage"
    DATA_RESET = "data_reset"


class DurablePhase(str, Enum):
    PREPARE_PERSISTED = "PREPARE_PERSISTED"
    COMMIT_INTENT_PERSISTED_TOKEN_ZEROIZED = (
        "COMMIT_INTENT_PERSISTED_TOKEN_ZEROIZED"  # noqa: S105 -- phase label
    )
    RESET_SEQUENCE_FLOOR_PERSISTED = "RESET_SEQUENCE_FLOOR_PERSISTED"
    STORAGE_FORMATTED = "STORAGE_FORMATTED"
    RESET_CONFIG_PERSISTED = "RESET_CONFIG_PERSISTED"
    RESULT_PERSISTED = "RESULT_PERSISTED"
    RESULT_ACKNOWLEDGED = "RESULT_ACKNOWLEDGED"
    CLEANUP_COMPLETE = "CLEANUP_COMPLETE"


FORMAT_PHASES = (
    DurablePhase.PREPARE_PERSISTED,
    DurablePhase.COMMIT_INTENT_PERSISTED_TOKEN_ZEROIZED,
    DurablePhase.STORAGE_FORMATTED,
    DurablePhase.RESULT_PERSISTED,
    DurablePhase.RESULT_ACKNOWLEDGED,
    DurablePhase.CLEANUP_COMPLETE,
)

RESET_PHASES = (
    DurablePhase.PREPARE_PERSISTED,
    DurablePhase.COMMIT_INTENT_PERSISTED_TOKEN_ZEROIZED,
    DurablePhase.RESET_SEQUENCE_FLOOR_PERSISTED,
    DurablePhase.STORAGE_FORMATTED,
    DurablePhase.RESET_CONFIG_PERSISTED,
    DurablePhase.RESULT_PERSISTED,
    DurablePhase.RESULT_ACKNOWLEDGED,
    DurablePhase.CLEANUP_COMPLETE,
)


def recovery_phases(kind: DestructiveKind) -> tuple[DurablePhase, ...]:
    return FORMAT_PHASES if kind is DestructiveKind.FORMAT_STORAGE else RESET_PHASES


class SimulatedPowerLoss(RuntimeError):
    def __init__(self, phase: DurablePhase):
        super().__init__(f"power lost after {phase.value}")
        self.phase = phase


@dataclass
class CrashPlan:
    """Crash once after each selected durable checkpoint."""

    phases: frozenset[DurablePhase]
    triggered: set[DurablePhase] = field(default_factory=set)

    @classmethod
    def after(cls, *phases: DurablePhase) -> CrashPlan:
        return cls(frozenset(phases))

    def checkpoint(self, phase: DurablePhase) -> None:
        if phase in self.phases and phase not in self.triggered:
            self.triggered.add(phase)
            raise SimulatedPowerLoss(phase)


@dataclass
class PrepareRecord:
    kind: DestructiveKind
    prepare_command_id: str
    confirmation_token: bytearray
    acknowledged_records_lost: int = 0
    unacknowledged_records_lost: int = 0
    reset_generation: int = 0
    server_sequence_floor: int = 0
    sequence_floor: int = 0


@dataclass
class CommitIntent:
    kind: DestructiveKind
    prepare_command_id: str
    commit_command_id: str
    phase: DurablePhase
    acknowledged_records_lost: int = 0
    unacknowledged_records_lost: int = 0
    reset_generation: int = 0
    server_sequence_floor: int = 0
    sequence_floor: int = 0


@dataclass(frozen=True)
class DurableCommandResult:
    command_id: str
    state: str
    progress_percent: int
    result_code: str
    evidence_json: str

    @property
    def evidence(self) -> dict[str, object]:
        value = json.loads(self.evidence_json)
        if not isinstance(value, dict):
            raise ValueError("result evidence was not an object")
        return value

    def canonical_bytes(self) -> bytes:
        envelope = {
            "command_id": self.command_id,
            "state": self.state,
            "progress_percent": self.progress_percent,
            "result_code": self.result_code,
            "evidence": self.evidence,
        }
        return json.dumps(envelope, sort_keys=True, separators=(",", ":")).encode()


@dataclass
class DurableDestructiveStore:
    """State that survives a simulated boot."""

    prepare: PrepareRecord | None = None
    intent: CommitIntent | None = None
    retained_result: DurableCommandResult | None = None
    result_acknowledged: bool = False
    completed_results: dict[str, DurableCommandResult] = field(default_factory=dict)

    # Representative durable device state and exactly-once effect receipts.
    storage_records: tuple[int, ...] = tuple(range(1, 48))
    acknowledged_sequence: int = 42
    maximum_sequence: int = 47
    sequence_floor: int = 47
    reset_generation: int = 3
    reset_config: tuple[int, int] = (3, 47)
    credentials_present: bool = True
    format_effects: set[str] = field(default_factory=set)
    sequence_floor_effects: set[str] = field(default_factory=set)
    reset_config_effects: set[str] = field(default_factory=set)
    phase_log: list[tuple[str, DurablePhase]] = field(default_factory=list)
    boot_count: int = 0
    zeroized_token_count: int = 0

    def checkpoint(
        self, command_id: str, phase: DurablePhase, crash_plan: CrashPlan | None
    ) -> None:
        self.phase_log.append((command_id, phase))
        if crash_plan is not None:
            crash_plan.checkpoint(phase)


def _zeroize(value: bytearray) -> None:
    for index in range(len(value)):
        value[index] = 0


def _canonical_evidence(value: dict[str, object]) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


class DurableDestructiveDevice:
    """Boot-scoped driver over :class:`DurableDestructiveStore`."""

    def __init__(self, store: DurableDestructiveStore):
        self.store = store
        self.store.boot_count += 1

    def reboot(self) -> DurableDestructiveDevice:
        """Lose all boot-local state while retaining only the durable store."""

        return DurableDestructiveDevice(self.store)

    def persist_prepare(
        self,
        *,
        kind: DestructiveKind,
        prepare_command_id: str,
        confirmation_token_hex: str,
        origin: str,
        reset_generation: int = 0,
        server_sequence_floor: int = 0,
        crash_plan: CrashPlan | None = None,
    ) -> None:
        if origin != "server":
            raise ValueError("confirmation token must be server-generated")
        if LOWER_HEX_128.fullmatch(confirmation_token_hex) is None:
            raise ValueError("confirmation token must be 128-bit lowercase hexadecimal")
        if self.store.intent is not None or self.store.retained_result is not None:
            raise ValueError("another destructive transaction is active")

        token = bytearray.fromhex(confirmation_token_hex)
        if kind is DestructiveKind.FORMAT_STORAGE:
            prepare = PrepareRecord(
                kind=kind,
                prepare_command_id=prepare_command_id,
                confirmation_token=token,
                acknowledged_records_lost=sum(
                    sequence <= self.store.acknowledged_sequence
                    for sequence in self.store.storage_records
                ),
                unacknowledged_records_lost=sum(
                    sequence > self.store.acknowledged_sequence
                    for sequence in self.store.storage_records
                ),
            )
        else:
            if reset_generation <= self.store.reset_generation:
                raise ValueError("reset generation must advance")
            if server_sequence_floor < 0:
                raise ValueError("server sequence floor must not be negative")
            prepare = PrepareRecord(
                kind=kind,
                prepare_command_id=prepare_command_id,
                confirmation_token=token,
                reset_generation=reset_generation,
                server_sequence_floor=server_sequence_floor,
                sequence_floor=max(
                    server_sequence_floor,
                    self.store.maximum_sequence,
                    self.store.sequence_floor,
                ),
            )
        self.store.prepare = prepare
        self.store.checkpoint(
            prepare_command_id, DurablePhase.PREPARE_PERSISTED, crash_plan
        )

    def persist_commit_intent(
        self,
        *,
        kind: DestructiveKind,
        prepare_command_id: str,
        commit_command_id: str,
        supplied_token: bytearray,
        reset_generation: int = 0,
        server_sequence_floor: int = 0,
        crash_plan: CrashPlan | None = None,
    ) -> None:
        # A duplicate authenticated delivery needs no token after the intent is
        # durable.  Its boot-local copy is still wiped before returning.
        existing = self.store.intent
        if existing is not None:
            matches = (
                existing.kind is kind
                and existing.prepare_command_id == prepare_command_id
                and existing.commit_command_id == commit_command_id
                and (
                    kind is DestructiveKind.FORMAT_STORAGE
                    or (
                        existing.reset_generation == reset_generation
                        and existing.server_sequence_floor == server_sequence_floor
                    )
                )
            )
            _zeroize(supplied_token)
            if not matches:
                raise ValueError("commit conflicts with durable intent")
            return

        prepare = self.store.prepare
        if prepare is None:
            _zeroize(supplied_token)
            if commit_command_id in self.store.completed_results:
                return
            raise ValueError("commit has no durable prepare")

        valid = (
            prepare.kind is kind
            and prepare.prepare_command_id == prepare_command_id
            and hmac.compare_digest(prepare.confirmation_token, supplied_token)
        )
        if kind is DestructiveKind.DATA_RESET:
            valid = (
                valid
                and prepare.reset_generation == reset_generation
                and prepare.server_sequence_floor == server_sequence_floor
            )
        if not valid:
            _zeroize(supplied_token)
            raise ValueError("commit validation failed")

        # This assignment models one atomic NVS transaction: the resumable,
        # non-secret intent becomes durable at the same boundary at which both
        # device and boot-local token copies are wiped.  There is deliberately
        # no crash point between these operations.
        intent = CommitIntent(
            kind=kind,
            prepare_command_id=prepare.prepare_command_id,
            commit_command_id=commit_command_id,
            phase=DurablePhase.COMMIT_INTENT_PERSISTED_TOKEN_ZEROIZED,
            acknowledged_records_lost=prepare.acknowledged_records_lost,
            unacknowledged_records_lost=prepare.unacknowledged_records_lost,
            reset_generation=prepare.reset_generation,
            server_sequence_floor=prepare.server_sequence_floor,
            sequence_floor=prepare.sequence_floor,
        )
        durable_token_reference = prepare.confirmation_token
        _zeroize(durable_token_reference)
        _zeroize(supplied_token)
        self.store.zeroized_token_count += 1
        self.store.prepare = None
        self.store.intent = intent
        self.store.checkpoint(
            commit_command_id,
            DurablePhase.COMMIT_INTENT_PERSISTED_TOKEN_ZEROIZED,
            crash_plan,
        )

    def advance(self, crash_plan: CrashPlan | None = None) -> bool:
        """Commit one next durable phase; return false while waiting for ack."""

        intent = self.store.intent
        if intent is None:
            return False

        if intent.phase is DurablePhase.COMMIT_INTENT_PERSISTED_TOKEN_ZEROIZED:
            if intent.kind is DestructiveKind.DATA_RESET:
                if intent.commit_command_id not in self.store.sequence_floor_effects:
                    self.store.sequence_floor = intent.sequence_floor
                    self.store.maximum_sequence = intent.sequence_floor
                    self.store.acknowledged_sequence = intent.sequence_floor
                    self.store.reset_generation = intent.reset_generation
                    self.store.sequence_floor_effects.add(intent.commit_command_id)
                intent.phase = DurablePhase.RESET_SEQUENCE_FLOOR_PERSISTED
                self.store.checkpoint(
                    intent.commit_command_id,
                    DurablePhase.RESET_SEQUENCE_FLOOR_PERSISTED,
                    crash_plan,
                )
                return True
            self._format_storage(intent, crash_plan)
            return True

        if intent.phase is DurablePhase.RESET_SEQUENCE_FLOOR_PERSISTED:
            self._format_storage(intent, crash_plan)
            return True

        if intent.phase is DurablePhase.STORAGE_FORMATTED:
            if intent.kind is DestructiveKind.DATA_RESET:
                if intent.commit_command_id not in self.store.reset_config_effects:
                    self.store.reset_config = (
                        intent.reset_generation,
                        intent.sequence_floor,
                    )
                    self.store.reset_config_effects.add(intent.commit_command_id)
                intent.phase = DurablePhase.RESET_CONFIG_PERSISTED
                self.store.checkpoint(
                    intent.commit_command_id,
                    DurablePhase.RESET_CONFIG_PERSISTED,
                    crash_plan,
                )
                return True
            self._persist_result(intent, crash_plan)
            return True

        if intent.phase is DurablePhase.RESET_CONFIG_PERSISTED:
            self._persist_result(intent, crash_plan)
            return True

        if intent.phase is DurablePhase.RESULT_PERSISTED:
            # A signed successful heartbeat response must acknowledge this
            # retained result before cleanup is allowed.
            return False

        if intent.phase is DurablePhase.RESULT_ACKNOWLEDGED:
            if self.store.retained_result is None:
                raise AssertionError("acknowledged transaction lost its result")
            self.store.completed_results[intent.commit_command_id] = (
                self.store.retained_result
            )
            self.store.retained_result = None
            self.store.result_acknowledged = False
            self.store.intent = None
            self.store.checkpoint(
                intent.commit_command_id, DurablePhase.CLEANUP_COMPLETE, crash_plan
            )
            return True

        raise AssertionError(f"unhandled durable phase {intent.phase.value}")

    def _format_storage(
        self, intent: CommitIntent, crash_plan: CrashPlan | None
    ) -> None:
        if intent.commit_command_id not in self.store.format_effects:
            self.store.storage_records = ()
            self.store.format_effects.add(intent.commit_command_id)
        intent.phase = DurablePhase.STORAGE_FORMATTED
        self.store.checkpoint(
            intent.commit_command_id, DurablePhase.STORAGE_FORMATTED, crash_plan
        )

    def _persist_result(
        self, intent: CommitIntent, crash_plan: CrashPlan | None
    ) -> None:
        if intent.kind is DestructiveKind.FORMAT_STORAGE:
            evidence: dict[str, object] = {
                "prepare_command_id": intent.prepare_command_id,
                "acknowledged_records_lost": intent.acknowledged_records_lost,
                "unacknowledged_records_lost": intent.unacknowledged_records_lost,
                "formatted": True,
            }
        else:
            evidence = {
                "prepare_command_id": intent.prepare_command_id,
                "reset_generation": intent.reset_generation,
                "sequence_floor": intent.sequence_floor,
            }
        self.store.retained_result = DurableCommandResult(
            command_id=intent.commit_command_id,
            state="succeeded",
            progress_percent=100,
            result_code="ok",
            evidence_json=_canonical_evidence(evidence),
        )
        self.store.result_acknowledged = False
        intent.phase = DurablePhase.RESULT_PERSISTED
        self.store.checkpoint(
            intent.commit_command_id, DurablePhase.RESULT_PERSISTED, crash_plan
        )

    def result_bytes(self, command_id: str) -> bytes | None:
        result = self.store.retained_result
        if result is not None and result.command_id == command_id:
            return result.canonical_bytes()
        completed = self.store.completed_results.get(command_id)
        return completed.canonical_bytes() if completed is not None else None

    def acknowledge_result(
        self,
        *,
        command_id: str,
        submitted_result: bytes,
        authenticated_server_response: bool,
        crash_plan: CrashPlan | None = None,
    ) -> None:
        intent = self.store.intent
        result = self.store.retained_result
        if not authenticated_server_response:
            raise ValueError("result acknowledgement was not authenticated")
        if (
            intent is None
            or result is None
            or intent.phase is not DurablePhase.RESULT_PERSISTED
            or intent.commit_command_id != command_id
            # ``submitted_result`` is the result bytes in the heartbeat whose
            # authenticated success response is being processed.  The server
            # does not need to echo the bytes in its response.
            or not hmac.compare_digest(result.canonical_bytes(), submitted_result)
        ):
            raise ValueError("result acknowledgement did not match retained result")
        self.store.result_acknowledged = True
        intent.phase = DurablePhase.RESULT_ACKNOWLEDGED
        self.store.checkpoint(
            command_id, DurablePhase.RESULT_ACKNOWLEDGED, crash_plan
        )

    def assert_safety_invariants(self) -> None:
        intent = self.store.intent
        if (
            intent is not None
            and intent.phase is not DurablePhase.RESULT_ACKNOWLEDGED
            and self.store.result_acknowledged
        ):
            raise AssertionError("result ack flag precedes durable ack phase")
        if (
            intent is not None
            and intent.phase
            in {
                DurablePhase.COMMIT_INTENT_PERSISTED_TOKEN_ZEROIZED,
                DurablePhase.RESET_SEQUENCE_FLOOR_PERSISTED,
                DurablePhase.STORAGE_FORMATTED,
                DurablePhase.RESET_CONFIG_PERSISTED,
                DurablePhase.RESULT_PERSISTED,
                DurablePhase.RESULT_ACKNOWLEDGED,
            }
            and self.store.prepare is not None
        ):
            raise AssertionError("confirmation token survived durable validation")
        if not self.store.credentials_present:
            raise AssertionError("destructive data operation erased credentials")
        if self.store.reset_generation != self.store.reset_config[0] and (
            intent is None
            or intent.kind is not DestructiveKind.DATA_RESET
            or intent.phase
            not in {
                DurablePhase.RESET_SEQUENCE_FLOOR_PERSISTED,
                DurablePhase.STORAGE_FORMATTED,
            }
        ):
            raise AssertionError("reset sequence and config generations diverged")
