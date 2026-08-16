from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import subprocess
import sys


FUNCTION_RE = re.compile(r"^[0-9a-fA-F]+ <([^>]+)>:$")
ENTRY_RE = re.compile(r"\bentry\s+a\d+,\s*(0x[0-9a-fA-F]+|\d+)\b")
MOVSP_RE = re.compile(r"\bmovsp\b")


def parse_disassembly(text: str) -> list[dict[str, object]]:
    functions: list[dict[str, object]] = []
    current: dict[str, object] | None = None
    for raw_line in text.splitlines():
        line = raw_line.strip()
        match = FUNCTION_RE.match(line)
        if match is not None:
            current = {"function": match.group(1), "frame_bytes": 0, "dynamic_frame": False}
            functions.append(current)
            continue
        if current is None:
            continue
        entry = ENTRY_RE.search(line)
        if entry is not None:
            current["frame_bytes"] = int(entry.group(1), 0)
        if MOVSP_RE.search(line) is not None:
            current["dynamic_frame"] = True
    return functions


def first_party_objects(project_root: Path, build_dir: Path) -> list[tuple[str, Path]]:
    components = ["main"]
    components.extend(sorted(path.name for path in (project_root / "components").iterdir() if path.is_dir()))
    objects: list[tuple[str, Path]] = []
    missing: list[str] = []
    for component in components:
        component_dir = build_dir / "esp-idf" / component
        component_objects = sorted(component_dir.rglob("*.obj")) if component_dir.is_dir() else []
        if not component_objects:
            missing.append(component)
        objects.extend((component, path) for path in component_objects)
    if missing:
        raise RuntimeError("missing first-party build objects for: " + ", ".join(missing))
    return objects


def audit(
    project_root: Path,
    build_dir: Path,
    objdump: str,
    threshold: int,
) -> dict[str, object]:
    records: list[dict[str, object]] = []
    for component, object_path in first_party_objects(project_root, build_dir):
        process = subprocess.run(
            [objdump, "-d", str(object_path)],
            cwd=project_root,
            text=True,
            capture_output=True,
            check=False,
        )
        if process.returncode != 0:
            raise RuntimeError(f"objdump failed for {object_path}: {process.stderr.strip()}")
        relative_object = object_path.relative_to(build_dir).as_posix()
        for function in parse_disassembly(process.stdout):
            records.append({"component": component, "object": relative_object, **function})
    records.sort(key=lambda item: (-int(item["frame_bytes"]), str(item["component"]), str(item["function"])))
    violations = [
        record for record in records
        if int(record["frame_bytes"]) > threshold or bool(record["dynamic_frame"])
    ]
    return {
        "schema": "pm-stack-frame-audit/1.0.0",
        "threshold_bytes": threshold,
        "object_count": len(first_party_objects(project_root, build_dir)),
        "function_count": len(records),
        "largest_frame_bytes": int(records[0]["frame_bytes"]) if records else 0,
        "violations": violations,
        "functions": records,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Audit every first-party ESP-IDF object for oversized or dynamic stack frames."
    )
    parser.add_argument("--build-dir", required=True, type=Path)
    parser.add_argument("--objdump", default="xtensa-esp32s3-elf-objdump")
    parser.add_argument("--threshold", type=int, default=3072)
    parser.add_argument("--json", type=Path, dest="json_path")
    args = parser.parse_args()
    if args.threshold <= 0:
        parser.error("--threshold must be positive")
    project_root = Path(__file__).resolve().parents[1]
    build_dir = args.build_dir.resolve()
    try:
        result = audit(project_root, build_dir, args.objdump, args.threshold)
    except (OSError, RuntimeError) as exc:
        print(f"stack frame audit failed: {exc}", file=sys.stderr)
        return 2
    if args.json_path is not None:
        args.json_path.parent.mkdir(parents=True, exist_ok=True)
        args.json_path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    for violation in result["violations"]:
        detail = "dynamic movsp frame" if violation["dynamic_frame"] else f"{violation['frame_bytes']} bytes"
        print(f"FAIL {violation['component']}:{violation['function']}: {detail}", file=sys.stderr)
    if result["violations"]:
        return 1
    print(
        f"stack frame audit passed: {result['function_count']} functions in "
        f"{result['object_count']} first-party objects; largest frame "
        f"{result['largest_frame_bytes']} bytes (limit {args.threshold})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
