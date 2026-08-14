from __future__ import annotations

import unittest

from durable_destructive_model import (
    CrashPlan,
    DestructiveKind,
    DurableDestructiveDevice,
    DurableDestructiveStore,
    DurablePhase,
    SimulatedPowerLoss,
    recovery_phases,
)

FORMAT_PREPARE_ID = "523e4567-e89b-42d3-a456-426614174004"
FORMAT_COMMIT_ID = "623e4567-e89b-42d3-a456-426614174005"
FORMAT_CONFIRMATION = "00112233445566778899aabbccddeeff"
RESET_PREPARE_ID = "723e4567-e89b-42d3-a456-426614174006"
RESET_COMMIT_ID = "823e4567-e89b-42d3-a456-426614174007"
RESET_CONFIRMATION = "102132435465768798a9bacbdcedfe0f"
RESET_GENERATION = 4
SERVER_SEQUENCE_FLOOR = 42


class RecoveryScenario:
    def __init__(self, kind: DestructiveKind, crash_plan: CrashPlan):
        self.kind = kind
        self.plan = crash_plan
        self.store = DurableDestructiveStore()
        self.device = DurableDestructiveDevice(self.store)
        if kind is DestructiveKind.FORMAT_STORAGE:
            self.prepare_id = FORMAT_PREPARE_ID
            self.commit_id = FORMAT_COMMIT_ID
            self.token_hex = FORMAT_CONFIRMATION
        else:
            self.prepare_id = RESET_PREPARE_ID
            self.commit_id = RESET_COMMIT_ID
            self.token_hex = RESET_CONFIRMATION
        self.commit_token: bytearray | None = None
        self.result_before_ack: bytes | None = None

    def _survive(self, operation) -> None:
        try:
            operation()
        except SimulatedPowerLoss:
            self.device = self.device.reboot()
        self.device.assert_safety_invariants()

    def prepare(self) -> None:
        self._survive(
            lambda: self.device.persist_prepare(
                kind=self.kind,
                prepare_command_id=self.prepare_id,
                confirmation_token_hex=self.token_hex,
                origin="server",
                reset_generation=(
                    RESET_GENERATION
                    if self.kind is DestructiveKind.DATA_RESET
                    else 0
                ),
                server_sequence_floor=(
                    SERVER_SEQUENCE_FLOOR
                    if self.kind is DestructiveKind.DATA_RESET
                    else 0
                ),
                crash_plan=self.plan,
            )
        )

    def commit(self) -> None:
        self.commit_token = bytearray.fromhex(self.token_hex)
        durable_token_reference = (
            self.store.prepare.confirmation_token
            if self.store.prepare is not None
            else None
        )
        self._survive(
            lambda: self.device.persist_commit_intent(
                kind=self.kind,
                prepare_command_id=self.prepare_id,
                commit_command_id=self.commit_id,
                supplied_token=self.commit_token,
                reset_generation=(
                    RESET_GENERATION
                    if self.kind is DestructiveKind.DATA_RESET
                    else 0
                ),
                server_sequence_floor=(
                    SERVER_SEQUENCE_FLOOR
                    if self.kind is DestructiveKind.DATA_RESET
                    else 0
                ),
                crash_plan=self.plan,
            )
        )
        if self.store.intent is not None:
            if self.commit_token != bytearray(16):
                raise AssertionError("boot-local commit token was not zeroized")
            if durable_token_reference != bytearray(16):
                raise AssertionError("durable prepare token was not zeroized")

    def reach_result(self) -> bytes:
        while self.store.retained_result is None:
            old_phase_count = len(self.store.phase_log)
            self._survive(lambda: self.device.advance(self.plan))
            if (
                len(self.store.phase_log) == old_phase_count
                and self.store.retained_result is None
            ):
                raise AssertionError("recovery made no progress before result")

        first = self.device.result_bytes(self.commit_id)
        if first is None:
            raise AssertionError("durable result is not replayable")
        # Rebooting any number of times before a signed response must retain the
        # byte-identical result and must not repeat the destructive effects.
        for _ in range(3):
            self.device = self.device.reboot()
            if self.device.result_bytes(self.commit_id) != first:
                raise AssertionError("result changed across reboot")
            if self.device.advance(self.plan):
                raise AssertionError("cleanup occurred before result acknowledgement")
        self.result_before_ack = first
        return first

    def acknowledge_and_cleanup(self) -> None:
        if self.result_before_ack is None:
            raise AssertionError("result has not been retained")

        # Neither an unauthenticated response nor a response for different
        # bytes satisfies the cleanup policy.
        with unittest.TestCase().assertRaises(ValueError):
            self.device.acknowledge_result(
                command_id=self.commit_id,
                submitted_result=self.result_before_ack,
                authenticated_server_response=False,
                crash_plan=self.plan,
            )
        with unittest.TestCase().assertRaises(ValueError):
            self.device.acknowledge_result(
                command_id=self.commit_id,
                submitted_result=self.result_before_ack + b"x",
                authenticated_server_response=True,
                crash_plan=self.plan,
            )

        if self.store.intent is not None and (
            self.store.intent.phase is DurablePhase.RESULT_PERSISTED
        ):
            self._survive(
                lambda: self.device.acknowledge_result(
                    command_id=self.commit_id,
                    submitted_result=self.result_before_ack,
                    authenticated_server_response=True,
                    crash_plan=self.plan,
                )
            )

        while self.store.intent is not None:
            old_phase_count = len(self.store.phase_log)
            self._survive(lambda: self.device.advance(self.plan))
            if len(self.store.phase_log) == old_phase_count and self.store.intent is not None:
                raise AssertionError("recovery made no progress during cleanup")

    def run(self) -> bytes:
        self.prepare()
        self.commit()
        result = self.reach_result()
        self.acknowledge_and_cleanup()
        return result


class DurableDestructiveRecoveryTests(unittest.TestCase):
    def assert_final_state(self, scenario: RecoveryScenario, result: bytes) -> None:
        scenario.device.assert_safety_invariants()
        store = scenario.store
        self.assertIsNone(store.prepare)
        self.assertIsNone(store.intent)
        self.assertIsNone(store.retained_result)
        self.assertFalse(store.result_acknowledged)
        self.assertTrue(store.credentials_present)
        self.assertEqual(store.storage_records, ())
        self.assertEqual(store.zeroized_token_count, 1)
        self.assertEqual(store.format_effects, {scenario.commit_id})
        self.assertEqual(scenario.device.result_bytes(scenario.commit_id), result)
        self.assertNotIn(scenario.token_hex, repr(store).lower())
        self.assertEqual(
            [phase for _command_id, phase in store.phase_log],
            list(recovery_phases(scenario.kind)),
        )
        self.assertEqual(store.phase_log[0][0], scenario.prepare_id)
        self.assertTrue(
            all(
                command_id == scenario.commit_id
                for command_id, _phase in store.phase_log[1:]
            )
        )

        completed = store.completed_results[scenario.commit_id]
        self.assertEqual(completed.command_id, scenario.commit_id)
        self.assertEqual(completed.state, "succeeded")
        self.assertEqual(completed.progress_percent, 100)
        self.assertEqual(completed.result_code, "ok")
        evidence = completed.evidence
        self.assertNotIn("confirmation_token", evidence)
        self.assertNotIn("token", completed.evidence_json.lower())
        self.assertEqual(evidence["prepare_command_id"], scenario.prepare_id)

        if scenario.kind is DestructiveKind.FORMAT_STORAGE:
            self.assertEqual(store.sequence_floor_effects, set())
            self.assertEqual(store.reset_config_effects, set())
            self.assertEqual(
                evidence,
                {
                    "prepare_command_id": FORMAT_PREPARE_ID,
                    "acknowledged_records_lost": 42,
                    "unacknowledged_records_lost": 5,
                    "formatted": True,
                },
            )
        else:
            self.assertEqual(store.sequence_floor_effects, {scenario.commit_id})
            self.assertEqual(store.reset_config_effects, {scenario.commit_id})
            self.assertEqual(store.reset_generation, RESET_GENERATION)
            self.assertEqual(store.sequence_floor, 47)
            self.assertEqual(store.maximum_sequence, 47)
            self.assertEqual(store.acknowledged_sequence, 47)
            self.assertEqual(store.reset_config, (RESET_GENERATION, 47))
            self.assertEqual(
                evidence,
                {
                    "prepare_command_id": RESET_PREPARE_ID,
                    "reset_generation": RESET_GENERATION,
                    "sequence_floor": 47,
                },
            )

    def test_format_recovers_after_power_loss_at_every_phase_boundary(self):
        for phase in recovery_phases(DestructiveKind.FORMAT_STORAGE):
            with self.subTest(phase=phase.value):
                plan = CrashPlan.after(phase)
                scenario = RecoveryScenario(DestructiveKind.FORMAT_STORAGE, plan)
                result = scenario.run()
                self.assertEqual(plan.triggered, {phase})
                self.assert_final_state(scenario, result)

    def test_reset_recovers_after_power_loss_at_every_phase_boundary(self):
        for phase in recovery_phases(DestructiveKind.DATA_RESET):
            with self.subTest(phase=phase.value):
                plan = CrashPlan.after(phase)
                scenario = RecoveryScenario(DestructiveKind.DATA_RESET, plan)
                result = scenario.run()
                self.assertEqual(plan.triggered, {phase})
                self.assert_final_state(scenario, result)

    def test_format_recovers_when_every_boundary_loses_power_once(self):
        phases = recovery_phases(DestructiveKind.FORMAT_STORAGE)
        plan = CrashPlan.after(*phases)
        scenario = RecoveryScenario(DestructiveKind.FORMAT_STORAGE, plan)
        result = scenario.run()
        self.assertEqual(plan.triggered, set(phases))
        self.assertGreaterEqual(scenario.store.boot_count, len(phases) + 1)
        self.assert_final_state(scenario, result)

    def test_reset_recovers_when_every_boundary_loses_power_once(self):
        phases = recovery_phases(DestructiveKind.DATA_RESET)
        plan = CrashPlan.after(*phases)
        scenario = RecoveryScenario(DestructiveKind.DATA_RESET, plan)
        result = scenario.run()
        self.assertEqual(plan.triggered, set(phases))
        self.assertGreaterEqual(scenario.store.boot_count, len(phases) + 1)
        self.assert_final_state(scenario, result)

    def test_prepare_rejects_non_server_or_noncanonical_token(self):
        device = DurableDestructiveDevice(DurableDestructiveStore())
        with self.assertRaisesRegex(ValueError, "server-generated"):
            device.persist_prepare(
                kind=DestructiveKind.FORMAT_STORAGE,
                prepare_command_id=FORMAT_PREPARE_ID,
                confirmation_token_hex=FORMAT_CONFIRMATION,
                origin="device",
            )
        with self.assertRaisesRegex(ValueError, "lowercase"):
            device.persist_prepare(
                kind=DestructiveKind.FORMAT_STORAGE,
                prepare_command_id=FORMAT_PREPARE_ID,
                confirmation_token_hex=FORMAT_CONFIRMATION.upper(),
                origin="server",
            )

    def test_wrong_commit_token_is_zeroized_without_persisting_intent(self):
        store = DurableDestructiveStore()
        device = DurableDestructiveDevice(store)
        device.persist_prepare(
            kind=DestructiveKind.FORMAT_STORAGE,
            prepare_command_id=FORMAT_PREPARE_ID,
            confirmation_token_hex=FORMAT_CONFIRMATION,
            origin="server",
        )
        wrong = bytearray.fromhex("ff" * 16)
        with self.assertRaisesRegex(ValueError, "validation failed"):
            device.persist_commit_intent(
                kind=DestructiveKind.FORMAT_STORAGE,
                prepare_command_id=FORMAT_PREPARE_ID,
                commit_command_id=FORMAT_COMMIT_ID,
                supplied_token=wrong,
            )
        self.assertEqual(wrong, bytearray(16))
        self.assertIsNone(store.intent)
        self.assertEqual(
            store.prepare.confirmation_token.hex(), FORMAT_CONFIRMATION
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
