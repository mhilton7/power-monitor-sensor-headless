from __future__ import annotations

import hashlib
import hmac
import re
from dataclasses import dataclass, field
from enum import IntEnum

SCHEMA = "pm-credential-rotation/1.0.0"
UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")


class PowerLoss(RuntimeError):
    pass


class RotationPhase(IntEnum):
    NONE = 0
    CANDIDATE_PERSISTED = 1
    CONFIG_STAGED = 2
    COMMIT_INTENT_SECRET_ZEROIZED = 3
    CONFIG_ACTIVATED = 4
    RESULT_PERSISTED = 5
    RESULT_ACKNOWLEDGED = 6


@dataclass
class RotationJournal:
    phase: RotationPhase
    rotation_id: str
    prepare_command_id: str
    fingerprint: str
    overlap_expires_ms: int
    candidate_secret: bytes
    commit_command_id: str = ""


@dataclass
class RotationStore:
    active_secret: bytes
    inactive_secret: bytes | None = None
    journal: RotationJournal | None = None
    results: dict[str, dict] = field(default_factory=dict)
    result_authentication: dict[str, str] = field(default_factory=dict)
    phase_log: list[RotationPhase | str] = field(default_factory=list)


class CredentialRotationDevice:
    def __init__(self, store: RotationStore, crash_after: set[RotationPhase] | None = None):
        self.store = store
        self.crash_after = crash_after or set()

    def _boundary(self, phase: RotationPhase) -> None:
        self.store.phase_log.append(phase)
        if phase in self.crash_after:
            self.crash_after.remove(phase)
            raise PowerLoss(phase.name)

    @staticmethod
    def _validate_identity(rotation_id: str, fingerprint: str) -> None:
        if (
            UUID.fullmatch(rotation_id) is None
            or re.fullmatch(r"[0-9a-f]{64}", fingerprint) is None
        ):
            raise ValueError("noncanonical rotation identity")

    def prepare(
        self,
        *,
        prepare_command_id: str,
        rotation_id: str,
        candidate_secret: bytes,
        fingerprint: str,
        overlap_expires_ms: int,
        now_ms: int,
    ) -> None:
        self._validate_identity(rotation_id, fingerprint)
        if UUID.fullmatch(prepare_command_id) is None or len(candidate_secret) != 32:
            raise ValueError("invalid prepare")
        if hashlib.sha256(candidate_secret).hexdigest() != fingerprint:
            raise ValueError("fingerprint mismatch")
        if overlap_expires_ms <= now_ms or self.store.journal is not None:
            raise ValueError("expired or conflicting prepare")
        self.store.journal = RotationJournal(
            phase=RotationPhase.CANDIDATE_PERSISTED,
            rotation_id=rotation_id,
            prepare_command_id=prepare_command_id,
            fingerprint=fingerprint,
            overlap_expires_ms=overlap_expires_ms,
            candidate_secret=bytes(candidate_secret),
        )
        self._boundary(RotationPhase.CANDIDATE_PERSISTED)
        self.resume(now_ms=now_ms, trusted_time=True)

    def commit(
        self,
        *,
        commit_command_id: str,
        rotation_id: str,
        fingerprint: str,
        now_ms: int,
        authenticated_with: str,
    ) -> None:
        self._validate_identity(rotation_id, fingerprint)
        journal = self.store.journal
        if UUID.fullmatch(commit_command_id) is None or journal is None:
            raise ValueError("not prepared")
        if journal.phase != RotationPhase.CONFIG_STAGED:
            raise ValueError("not commit-ready")
        if authenticated_with != "old_server_to_device":
            raise PermissionError("commit not authenticated by old active key")
        if now_ms > journal.overlap_expires_ms:
            self.expire(now_ms=now_ms, trusted_time=True)
            raise TimeoutError("rotation expired")
        if not hmac.compare_digest(rotation_id, journal.rotation_id) or not hmac.compare_digest(
            fingerprint, journal.fingerprint
        ):
            raise PermissionError("rotation binding mismatch")
        journal.commit_command_id = commit_command_id
        journal.candidate_secret = b""
        journal.phase = RotationPhase.COMMIT_INTENT_SECRET_ZEROIZED
        self._boundary(RotationPhase.COMMIT_INTENT_SECRET_ZEROIZED)
        self.resume(now_ms=now_ms, trusted_time=True)

    def cancel(self, *, rotation_id: str) -> dict:
        journal = self.store.journal
        if journal is None or journal.phase >= RotationPhase.COMMIT_INTENT_SECRET_ZEROIZED:
            raise ValueError("not cancellable")
        if not hmac.compare_digest(rotation_id, journal.rotation_id):
            raise PermissionError("mismatched rotation")
        journal.candidate_secret = b""
        self.store.inactive_secret = None
        self.store.journal = None
        return {"rotation_id": rotation_id, "cancelled": True}

    def expire(self, *, now_ms: int, trusted_time: bool) -> bool:
        journal = self.store.journal
        if journal is None or journal.phase >= RotationPhase.COMMIT_INTENT_SECRET_ZEROIZED:
            return False
        if not trusted_time or now_ms <= journal.overlap_expires_ms:
            return False
        journal.candidate_secret = b""
        self.store.inactive_secret = None
        self.store.journal = None
        return True

    def resume(self, *, now_ms: int, trusted_time: bool) -> None:
        journal = self.store.journal
        if journal is None:
            return
        if journal.phase < RotationPhase.COMMIT_INTENT_SECRET_ZEROIZED:
            if self.expire(now_ms=now_ms, trusted_time=trusted_time):
                return
            if not trusted_time:
                return
        journal = self.store.journal
        if journal is None:
            return
        if journal.phase == RotationPhase.CANDIDATE_PERSISTED:
            self.store.inactive_secret = bytes(journal.candidate_secret)
            journal.phase = RotationPhase.CONFIG_STAGED
            self._boundary(RotationPhase.CONFIG_STAGED)
        if journal.phase == RotationPhase.CONFIG_STAGED:
            evidence = {
                "rotation_id": journal.rotation_id,
                "credential_fingerprint": journal.fingerprint,
                "ready": True,
            }
            self.store.results[journal.prepare_command_id] = evidence
            self.store.result_authentication[journal.prepare_command_id] = "old_device_to_server"
        if journal.phase == RotationPhase.COMMIT_INTENT_SECRET_ZEROIZED:
            if self.store.inactive_secret is None:
                raise AssertionError("durable staged candidate missing")
            self.store.active_secret = self.store.inactive_secret
            journal.phase = RotationPhase.CONFIG_ACTIVATED
            self._boundary(RotationPhase.CONFIG_ACTIVATED)
        if journal.phase == RotationPhase.CONFIG_ACTIVATED:
            evidence = {
                "rotation_id": journal.rotation_id,
                "credential_fingerprint": journal.fingerprint,
                "activated": True,
            }
            self.store.results[journal.commit_command_id] = evidence
            self.store.result_authentication[journal.commit_command_id] = "new_device_to_server"
            journal.phase = RotationPhase.RESULT_PERSISTED
            self._boundary(RotationPhase.RESULT_PERSISTED)

    def acknowledge_result(self, *, command_id: str, authenticated: bool) -> None:
        journal = self.store.journal
        if (
            journal is None
            or journal.phase != RotationPhase.RESULT_PERSISTED
            or command_id != journal.commit_command_id
            or not authenticated
        ):
            raise PermissionError("result acknowledgement rejected")
        journal.phase = RotationPhase.RESULT_ACKNOWLEDGED
        self._boundary(RotationPhase.RESULT_ACKNOWLEDGED)
        self.store.inactive_secret = None
        self.store.journal = None
        self.store.phase_log.append("CLEANUP_COMPLETE")
