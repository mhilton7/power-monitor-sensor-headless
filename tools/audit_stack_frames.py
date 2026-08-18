from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

FUNCTION_RE = re.compile(r"^[0-9a-fA-F]+ <([^>]+)>:$")
ENTRY_RE = re.compile(r"\bentry\s+a\d+,\s*(0x[0-9a-fA-F]+|\d+)\b")
MOVSP_RE = re.compile(r"\bmovsp\b")
COMPILER_RE = re.compile(r"(?:gcc|g\+\+)(\.exe)?$", re.IGNORECASE)


def _command_executable(entry: object) -> str | None:
    if not isinstance(entry, dict):
        return None
    arguments = entry.get("arguments")
    if isinstance(arguments, list) and arguments and isinstance(arguments[0], str):
        return arguments[0]
    command = entry.get("command")
    if not isinstance(command, str):
        return None
    match = re.match(r'^\s*(?:"([^"]+)"|(\S+))', command)
    if match is None:
        return None
    return match.group(1) or match.group(2)


def resolve_objdump(build_dir: Path, requested: str | None) -> str:
    if requested:
        return requested
    for command in ("xtensa-esp32s3-elf-objdump", "xtensa-esp-elf-objdump"):
        resolved = shutil.which(command)
        if resolved is not None:
            return resolved
    compile_commands = build_dir / "compile_commands.json"
    if not compile_commands.is_file():
        raise RuntimeError(f"missing compiler inventory: {compile_commands}")
    try:
        entries = json.loads(compile_commands.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"invalid compiler inventory {compile_commands}: {exc}") from exc
    if not isinstance(entries, list):
        raise RuntimeError(f"invalid compiler inventory shape: {compile_commands}")
    for entry in entries:
        compiler = _command_executable(entry)
        if compiler is None:
            continue
        compiler_path = Path(compiler)
        objdump_name = COMPILER_RE.sub(r"objdump\1", compiler_path.name)
        if objdump_name == compiler_path.name:
            continue
        candidate = compiler_path.with_name(objdump_name)
        if candidate.is_file():
            return str(candidate)
    raise RuntimeError(
        "could not locate the Xtensa objdump on PATH or beside the compiler recorded in "
        f"{compile_commands}"
    )


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


def active_first_party_components(project_root: Path, build_dir: Path) -> list[str]:
    description_path = build_dir / "project_description.json"
    if not description_path.is_file():
        raise RuntimeError(f"missing build component inventory: {description_path}")
    try:
        description = json.loads(description_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"invalid build component inventory {description_path}: {exc}") from exc
    names = description.get("build_components")
    paths = description.get("build_component_paths")
    if not isinstance(names, list) or not isinstance(paths, list) or len(names) != len(paths):
        raise RuntimeError(f"invalid build component inventory shape: {description_path}")
    project_root = project_root.resolve()
    component_root = (project_root / "components").resolve()
    first_party: list[str] = []
    for name, source in zip(names, paths, strict=True):
        if not isinstance(name, str) or not name or not isinstance(source, str) or not source:
            continue
        source_path = Path(source).resolve()
        if source_path == (project_root / "main").resolve() or source_path.parent == component_root:
            first_party.append(name)
    if "main" not in first_party:
        raise RuntimeError("active first-party component inventory does not contain main")
    return sorted(set(first_party))


def first_party_objects(project_root: Path, build_dir: Path) -> list[tuple[str, Path]]:
    components = active_first_party_components(project_root, build_dir)
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
        # The executable is explicit or resolved beside CMake's recorded pinned compiler.
        process = subprocess.run(  # noqa: S603
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
    records.sort(
        key=lambda item: (-int(item["frame_bytes"]), str(item["component"]), str(item["function"]))
    )
    violations = [
        record
        for record in records
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
    parser.add_argument(
        "--objdump",
        help="explicit objdump path; otherwise discover it on PATH or beside the recorded compiler",
    )
    parser.add_argument("--threshold", type=int, default=3072)
    parser.add_argument("--json", type=Path, dest="json_path")
    args = parser.parse_args()
    if args.threshold <= 0:
        parser.error("--threshold must be positive")
    project_root = Path(__file__).resolve().parents[1]
    build_dir = args.build_dir.resolve()
    try:
        objdump = resolve_objdump(build_dir, args.objdump)
        result = audit(project_root, build_dir, objdump, args.threshold)
    except (OSError, RuntimeError) as exc:
        print(f"stack frame audit failed: {exc}", file=sys.stderr)
        return 2
    if args.json_path is not None:
        args.json_path.parent.mkdir(parents=True, exist_ok=True)
        args.json_path.write_text(
            json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
    for violation in result["violations"]:
        detail = (
            "dynamic movsp frame"
            if violation["dynamic_frame"]
            else f"{violation['frame_bytes']} bytes"
        )
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
