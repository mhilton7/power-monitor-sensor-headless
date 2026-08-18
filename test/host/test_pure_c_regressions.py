from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]


def host_compiler() -> str | None:
    configured = os.environ.get("CC")
    candidates = ([configured] if configured else []) + ["cc", "gcc", "clang", "cl"]
    for candidate in candidates:
        if candidate and shutil.which(candidate):
            return candidate
    return None


class PureCRegressionTests(unittest.TestCase):
    def compile_and_run(
        self, name: str, *, sources: list[str], include_directories: list[str]
    ) -> None:
        compiler = host_compiler()
        if compiler is None:
            self.skipTest("no native host C compiler is available")
        with tempfile.TemporaryDirectory(prefix="pm-host-c-") as temporary:
            executable = Path(temporary) / (name + (".exe" if os.name == "nt" else ""))
            if Path(compiler).name.lower() in {"cl", "cl.exe"}:
                object_directory = str(Path(temporary)) + os.sep
                command = [
                    compiler,
                    "/nologo",
                    "/std:c11",
                    "/W4",
                    "/WX",
                    *[f"/I{ROOT / directory}" for directory in include_directories],
                    *[str(ROOT / source) for source in sources],
                    f"/Fo{object_directory}",
                    f"/Fe:{executable}",
                ]
            else:
                command = [
                    compiler,
                    "-std=c11",
                    "-Wall",
                    "-Wextra",
                    "-Werror",
                    *[f"-I{ROOT / directory}" for directory in include_directories],
                    *[str(ROOT / source) for source in sources],
                    "-o",
                    str(executable),
                ]
            compiled = subprocess.run(command, cwd=ROOT, text=True, capture_output=True, check=False)
            self.assertEqual(0, compiled.returncode, compiled.stdout + compiled.stderr)
            executed = subprocess.run(
                [str(executable)], cwd=ROOT, text=True, capture_output=True, check=False
            )
            self.assertEqual(0, executed.returncode, executed.stdout + executed.stderr)
            self.assertIn('"failures":0', executed.stdout)

    def test_bounded_response_header_capture(self) -> None:
        self.compile_and_run(
            "test_pm_http_response",
            sources=[
                "test/host/test_pm_http_response.c",
                "components/pm_protocol/pm_http_response.c",
            ],
            include_directories=["test/host/stubs", "components/pm_protocol/include"],
        )

    def test_ota_version_and_stale_attempt_policy(self) -> None:
        self.compile_and_run(
            "test_pm_ota_policy",
            sources=[
                "test/host/test_pm_ota_policy.c",
                "components/pm_ota/pm_ota_version.c",
                "components/pm_network/pm_command_envelope.c",
            ],
            include_directories=[
                "test/host/stubs",
                "components/pm_ota/include",
                "components/pm_network/include",
            ],
        )

    def test_stateless_latest_value_and_backoff_policy(self) -> None:
        self.compile_and_run(
            "test_pm_telemetry",
            sources=[
                "test/host/test_pm_telemetry.c",
                "components/pm_telemetry/pm_telemetry.c",
            ],
            include_directories=[
                "test/host/stubs",
                "components/pm_config/include",
                "components/pm_meter/include",
                "components/pm_telemetry/include",
            ],
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
