from __future__ import annotations

import importlib.util
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "verify_firmware_profile", ROOT / "tools" / "verify_firmware_profile.py"
)
assert SPEC is not None and SPEC.loader is not None
PROFILE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PROFILE)


def base_values() -> dict[str, str]:
    return {
        "CONFIG_PM_METER_VARIANT_PZEM004T_V4_CLASSIC": "1",
        "CONFIG_PM_METER_SAMPLE_MS": "1000",
        "CONFIG_PM_TELEMETRY_INTERVAL_SECONDS": "5",
    }


class FirmwareProfileTests(unittest.TestCase):
    def test_release_candidate_polls_real_pzem_without_claiming_certification(self):
        values = base_values() | {
            "CONFIG_PM_PZEM_LIVE_VALIDATION": "1",
            "CONFIG_PM_RELEASE_CANDIDATE": "1",
        }
        errors, mode = PROFILE.validate_profile(values, "release-candidate")
        self.assertEqual([], errors)
        self.assertEqual("candidate-live-validation", mode)

    def test_release_candidate_rejects_false_hardware_certification(self):
        values = base_values() | {
            "CONFIG_PM_PZEM_LIVE_VALIDATION": "1",
            "CONFIG_PM_HARDWARE_IDENTITY_VERIFIED": "1",
            "CONFIG_PM_RELEASE_CANDIDATE": "1",
        }
        errors, _ = PROFILE.validate_profile(values, "release-candidate")
        self.assertIn(
            "CONFIG_PM_HARDWARE_IDENTITY_VERIFIED must be disabled for release-candidate",
            errors,
        )

    def test_stable_profile_requires_certification_and_disables_validation_mode(self):
        values = base_values() | {
            "CONFIG_PM_HARDWARE_IDENTITY_VERIFIED": "1",
            "CONFIG_PM_PRODUCTION_RELEASE": "1",
            "CONFIG_NVS_ENCRYPTION": "1",
            "CONFIG_NVS_SEC_KEY_PROTECT_USING_HMAC": "1",
        }
        errors, mode = PROFILE.validate_profile(values, "release")
        self.assertEqual([], errors)
        self.assertEqual("certified-production", mode)

    def test_sample_cadence_change_fails_profile_verification(self):
        values = base_values() | {
            "CONFIG_PM_PZEM_LIVE_VALIDATION": "1",
            "CONFIG_PM_RELEASE_CANDIDATE": "1",
        }
        values["CONFIG_PM_METER_SAMPLE_MS"] = "2000"
        errors, _ = PROFILE.validate_profile(values, "release-candidate")
        self.assertIn("CONFIG_PM_METER_SAMPLE_MS must remain 1000; found 2000", errors)

    def test_repository_overlays_encode_distinct_validation_and_certification_modes(self):
        candidate = (ROOT / "sdkconfig.release-candidate").read_text(encoding="utf-8")
        release = (ROOT / "sdkconfig.release").read_text(encoding="utf-8")
        self.assertIn("CONFIG_PM_PZEM_LIVE_VALIDATION=y", candidate)
        self.assertIn("CONFIG_PM_HARDWARE_IDENTITY_VERIFIED=n", candidate)
        self.assertIn("CONFIG_PM_PZEM_LIVE_VALIDATION=n", release)
        self.assertIn("CONFIG_PM_HARDWARE_IDENTITY_VERIFIED=y", release)

    def test_meter_self_test_uses_the_existing_sample_and_cannot_add_uart_load(self):
        source = (ROOT / "main" / "app_main_stateless.c").read_text(encoding="utf-8")
        self.assertEqual(1, source.count("pm_meter_read(&s_meter"))
        self_test = source.split("case PM_COMMAND_METER_SELF_TEST:", 1)[1].split(
            "case PM_COMMAND_OTA_INSTALL:", 1
        )[0]
        self.assertIn("pm_network_copy_live(&sample, &present)", self_test)
        self.assertNotIn("pm_meter_read", self_test)


if __name__ == "__main__":
    unittest.main(verbosity=2)
