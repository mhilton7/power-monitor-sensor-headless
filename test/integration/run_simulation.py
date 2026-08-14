from __future__ import annotations

import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "host"))
from pm_model import accelerated_simulation, protocol_vector


def main() -> int:
    result = accelerated_simulation(days=120)
    result["protocol_vector_signature_base64"] = protocol_vector()["signature_base64"]
    result["suite"] = "accelerated-120-day-simulation"
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
