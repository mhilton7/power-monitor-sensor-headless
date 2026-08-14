from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import time
import unittest


ROOT = Path(__file__).resolve().parents[1]
HOST = ROOT / "test" / "host"
sys.path.insert(0, str(HOST))


def main() -> int:
    output = ROOT / "test-results" / "host"
    output.mkdir(parents=True, exist_ok=True)
    started = time.time()
    suite = unittest.defaultTestLoader.discover(str(HOST), pattern="test_*.py")
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    commands = [
        [sys.executable, str(ROOT / "test" / "fault_injection" / "run_fault_matrix.py")],
        [sys.executable, str(ROOT / "test" / "integration" / "run_simulation.py")],
    ]
    subresults = []
    for command in commands:
        process = subprocess.run(command, cwd=ROOT, text=True, capture_output=True, check=False)
        if process.stdout:
            print(process.stdout.strip())
        if process.stderr:
            print(process.stderr.strip(), file=sys.stderr)
        subresults.append({"command": command[-1], "returncode": process.returncode,
                           "result": json.loads(process.stdout) if process.stdout else {}})
    summary = {
        "suite": "firmware-host",
        "unit_tests": result.testsRun,
        "unit_failures": len(result.failures),
        "unit_errors": len(result.errors),
        "subprocess_failures": sum(item["returncode"] != 0 for item in subresults),
        "duration_seconds": round(time.time() - started, 3),
        "subresults": subresults,
    }
    (output / "results.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(summary, sort_keys=True))
    return 0 if result.wasSuccessful() and summary["subprocess_failures"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())

