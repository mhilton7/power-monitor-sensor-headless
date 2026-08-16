from __future__ import annotations

from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))

from audit_stack_frames import parse_disassembly  # noqa: E402


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

if __name__ == "__main__":
    unittest.main()
