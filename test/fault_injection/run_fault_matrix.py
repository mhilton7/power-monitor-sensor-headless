from __future__ import annotations

import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "host"))
from pm_model import FAULTS, SimulatedDevice


def main() -> int:
    results = []
    for fault in FAULTS:
        device = SimulatedDevice()
        device.config.commit(b"known-good-config")
        before_ack = device.sequence.acknowledged
        before_measurements = device.measurement_count
        device.inject(fault)
        device.assert_invariants()
        passed = (
            device.sequence.acknowledged >= before_ack
            and device.measurement_count >= before_measurements
            and device.credentials_present
            and not device.sync_latched
        )
        results.append({
            "fault": fault,
            "passed": passed,
            "maximum_sequence": device.sequence.maximum_seen,
            "acknowledged": device.sequence.acknowledged,
            "unavailable_ranges": len(device.unavailable),
        })
    output = {"suite": "fault-injection", "cases": len(results), "passed": sum(item["passed"] for item in results),
              "failed": sum(not item["passed"] for item in results), "results": results}
    print(json.dumps(output, sort_keys=True))
    return 0 if output["failed"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())

