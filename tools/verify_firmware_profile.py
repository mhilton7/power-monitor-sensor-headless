from __future__ import annotations

import argparse
import json
from pathlib import Path
import re


DEFINE = re.compile(r"^#define (CONFIG_[A-Z0-9_]+)(?:\s+(.+))?$")


def parse_sdkconfig_header(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        match = DEFINE.match(line.strip())
        if match:
            values[match.group(1)] = match.group(2) or "1"
    return values


def validate_profile(values: dict[str, str], profile: str) -> tuple[list[str], str]:
    expected_common = {
        "CONFIG_PM_METER_VARIANT_PZEM004T_V4_CLASSIC": True,
        "CONFIG_PM_SIMULATED_METER": False,
    }
    expected_by_profile = {
        "release-candidate": {
            "CONFIG_PM_PZEM_LIVE_VALIDATION": True,
            "CONFIG_PM_HARDWARE_IDENTITY_VERIFIED": False,
            "CONFIG_PM_RELEASE_CANDIDATE": True,
            "CONFIG_PM_PRODUCTION_RELEASE": False,
        },
        "release": {
            "CONFIG_PM_PZEM_LIVE_VALIDATION": False,
            "CONFIG_PM_HARDWARE_IDENTITY_VERIFIED": True,
            "CONFIG_PM_RELEASE_CANDIDATE": False,
            "CONFIG_PM_PRODUCTION_RELEASE": True,
            "CONFIG_NVS_ENCRYPTION": True,
            "CONFIG_NVS_SEC_KEY_PROTECT_USING_HMAC": True,
        },
    }
    expected_timing = {
        "CONFIG_PM_HEARTBEAT_SECONDS": "15",
        "CONFIG_PM_METER_SAMPLE_MS": "1000",
        "CONFIG_PM_DURABLE_INTERVAL_SECONDS": "60",
    }
    errors: list[str] = []
    expected = expected_common | expected_by_profile[profile]
    for name, enabled in expected.items():
        actual = values.get(name) == "1"
        if actual != enabled:
            errors.append(f"{name} must be {'enabled' if enabled else 'disabled'} for {profile}")
    for name, expected_value in expected_timing.items():
        if values.get(name) != expected_value:
            errors.append(f"{name} must remain {expected_value}; found {values.get(name, 'unset')}")
    mode = "candidate-live-validation" if profile == "release-candidate" else "certified-production"
    return errors, mode


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--sdkconfig-header", type=Path, required=True)
    parser.add_argument("--profile", choices=("release-candidate", "release"), required=True)
    arguments = parser.parse_args()
    values = parse_sdkconfig_header(arguments.sdkconfig_header)
    errors, mode = validate_profile(values, arguments.profile)
    result = {
        "result": "fail" if errors else "pass",
        "profile": arguments.profile,
        "pzem_mode": mode,
        "timing": {
            "heartbeat_seconds": values.get("CONFIG_PM_HEARTBEAT_SECONDS"),
            "sample_ms": values.get("CONFIG_PM_METER_SAMPLE_MS"),
            "durable_interval_seconds": values.get("CONFIG_PM_DURABLE_INTERVAL_SECONDS"),
        },
        "errors": errors,
    }
    print(json.dumps(result, sort_keys=True))
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
