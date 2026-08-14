from __future__ import annotations

import hashlib
import unittest

from credential_rotation_model import (
    CredentialRotationDevice,
    PowerLoss,
    RotationPhase,
    RotationStore,
)

OLD_SECRET = bytes(reversed(range(32)))
NEW_SECRET = bytes(range(32))
FINGERPRINT = hashlib.sha256(NEW_SECRET).hexdigest()
ROTATION_ID = "e23e4567-e89b-42d3-a456-426614174013"
PREPARE_ID = "b23e4567-e89b-42d3-a456-426614174010"
COMMIT_ID = "c23e4567-e89b-42d3-a456-426614174011"
NOW = 1_786_651_620_000
EXPIRES = NOW + 600_000


class CredentialRotationRecoveryTests(unittest.TestCase):
    def prepare(self, store: RotationStore, crash_after: set[RotationPhase] | None = None) -> None:
        CredentialRotationDevice(store, crash_after).prepare(
            prepare_command_id=PREPARE_ID,
            rotation_id=ROTATION_ID,
            candidate_secret=NEW_SECRET,
            fingerprint=FINGERPRINT,
            overlap_expires_ms=EXPIRES,
            now_ms=NOW,
        )

    def commit(self, store: RotationStore, crash_after: set[RotationPhase] | None = None) -> None:
        CredentialRotationDevice(store, crash_after).commit(
            commit_command_id=COMMIT_ID,
            rotation_id=ROTATION_ID,
            fingerprint=FINGERPRINT,
            now_ms=NOW + 60_000,
            authenticated_with="old_server_to_device",
        )

    def test_prepare_recovers_after_every_durable_boundary(self) -> None:
        for phase in (RotationPhase.CANDIDATE_PERSISTED, RotationPhase.CONFIG_STAGED):
            with self.subTest(phase=phase.name):
                store = RotationStore(active_secret=OLD_SECRET)
                with self.assertRaises(PowerLoss):
                    self.prepare(store, {phase})
                CredentialRotationDevice(store).resume(now_ms=NOW + 1, trusted_time=True)
                self.assertEqual(OLD_SECRET, store.active_secret)
                self.assertEqual(NEW_SECRET, store.inactive_secret)
                self.assertEqual(
                    {
                        "rotation_id": ROTATION_ID,
                        "credential_fingerprint": FINGERPRINT,
                        "ready": True,
                    },
                    store.results[PREPARE_ID],
                )
                self.assertEqual("old_device_to_server", store.result_authentication[PREPARE_ID])

    def test_commit_recovers_after_every_durable_boundary(self) -> None:
        for phase in (
            RotationPhase.COMMIT_INTENT_SECRET_ZEROIZED,
            RotationPhase.CONFIG_ACTIVATED,
            RotationPhase.RESULT_PERSISTED,
        ):
            with self.subTest(phase=phase.name):
                store = RotationStore(active_secret=OLD_SECRET)
                self.prepare(store)
                with self.assertRaises(PowerLoss):
                    self.commit(store, {phase})
                self.assertEqual(b"", store.journal.candidate_secret)
                CredentialRotationDevice(store).resume(now_ms=NOW + 60_001, trusted_time=True)
                self.assertEqual(NEW_SECRET, store.active_secret)
                self.assertEqual(
                    {
                        "rotation_id": ROTATION_ID,
                        "credential_fingerprint": FINGERPRINT,
                        "activated": True,
                    },
                    store.results[COMMIT_ID],
                )
                self.assertEqual("new_device_to_server", store.result_authentication[COMMIT_ID])

    def test_result_is_byte_stable_until_authenticated_acknowledgement(self) -> None:
        store = RotationStore(active_secret=OLD_SECRET)
        self.prepare(store)
        self.commit(store)
        first = dict(store.results[COMMIT_ID])
        for _ in range(3):
            CredentialRotationDevice(store).resume(now_ms=NOW + 90_000, trusted_time=True)
            self.assertEqual(first, store.results[COMMIT_ID])
        with self.assertRaises(PermissionError):
            CredentialRotationDevice(store).acknowledge_result(
                command_id=COMMIT_ID, authenticated=False
            )
        CredentialRotationDevice(store).acknowledge_result(command_id=COMMIT_ID, authenticated=True)
        self.assertIsNone(store.journal)
        self.assertIsNone(store.inactive_secret)
        self.assertEqual("CLEANUP_COMPLETE", store.phase_log[-1])

    def test_mismatched_cancel_cannot_clear_candidate(self) -> None:
        store = RotationStore(active_secret=OLD_SECRET)
        self.prepare(store)
        with self.assertRaises(PermissionError):
            CredentialRotationDevice(store).cancel(
                rotation_id="f23e4567-e89b-42d3-a456-426614174014"
            )
        self.assertIsNotNone(store.journal)
        self.assertEqual(NEW_SECRET, store.inactive_secret)
        self.assertEqual(
            {"rotation_id": ROTATION_ID, "cancelled": True},
            CredentialRotationDevice(store).cancel(rotation_id=ROTATION_ID),
        )
        self.assertIsNone(store.journal)
        self.assertIsNone(store.inactive_secret)

    def test_untrusted_time_is_dormant_and_trusted_expiry_zeroizes(self) -> None:
        store = RotationStore(active_secret=OLD_SECRET)
        self.prepare(store)
        device = CredentialRotationDevice(store)
        self.assertFalse(device.expire(now_ms=EXPIRES + 1, trusted_time=False))
        self.assertIsNotNone(store.journal)
        self.assertTrue(device.expire(now_ms=EXPIRES + 1, trusted_time=True))
        self.assertIsNone(store.journal)
        self.assertIsNone(store.inactive_secret)

    def test_wrong_fingerprint_and_wrong_commit_key_fail_closed(self) -> None:
        store = RotationStore(active_secret=OLD_SECRET)
        with self.assertRaises(ValueError):
            CredentialRotationDevice(store).prepare(
                prepare_command_id=PREPARE_ID,
                rotation_id=ROTATION_ID,
                candidate_secret=NEW_SECRET,
                fingerprint="00" * 32,
                overlap_expires_ms=EXPIRES,
                now_ms=NOW,
            )
        self.prepare(store)
        with self.assertRaises(PermissionError):
            CredentialRotationDevice(store).commit(
                commit_command_id=COMMIT_ID,
                rotation_id=ROTATION_ID,
                fingerprint=FINGERPRINT,
                now_ms=NOW + 1,
                authenticated_with="new_server_to_device",
            )
        self.assertEqual(OLD_SECRET, store.active_secret)


if __name__ == "__main__":
    unittest.main()
