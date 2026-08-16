from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))

from audit_stack_frames import parse_disassembly, resolve_objdump  # noqa: E402


class StackFrameAuditTests(unittest.TestCase):
    def test_parses_decimal_and_hex_entry_frames(self) -> None:
        functions = parse_disassembly(
            """
00000000 <small>:
   0: 004136 entry a1, 32
00000010 <large>:
  10: 0c4136 entry a1, 0x620
"""
        )
        self.assertEqual(
            [(item["function"], item["frame_bytes"]) for item in functions],
            [("small", 32), ("large", 1568)],
        )

    def test_marks_dynamic_stack_adjustment(self) -> None:
        functions = parse_disassembly(
            """
00000000 <variable_length_array>:
   0: 004136 entry a1, 32
   3: 0060c0 movsp a1, a6
"""
        )
        self.assertTrue(functions[0]["dynamic_frame"])

    def test_discovers_objdump_beside_recorded_compiler_when_path_is_empty(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            build_dir = root / "build"
            toolchain = root / "toolchain"
            build_dir.mkdir()
            toolchain.mkdir()
            compiler = toolchain / "xtensa-esp32s3-elf-gcc"
            objdump = toolchain / "xtensa-esp32s3-elf-objdump"
            objdump.touch()
            (build_dir / "compile_commands.json").write_text(
                json.dumps([{"command": f'"{compiler}" -c input.c -o input.o'}]),
                encoding="utf-8",
            )
            with mock.patch("audit_stack_frames.shutil.which", return_value=None):
                self.assertEqual(resolve_objdump(build_dir, None), str(objdump))

    def test_explicit_objdump_path_takes_precedence(self) -> None:
        self.assertEqual(resolve_objdump(Path("unused"), "custom-objdump"), "custom-objdump")


if __name__ == "__main__":
    unittest.main()
