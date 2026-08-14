[CmdletBinding()]
param(
    [string]$OutputDirectory = "test-results/host"
)

$ErrorActionPreference = "Stop"
$repo = Split-Path -Parent $PSScriptRoot
$pythonCandidates = @(
    "C:\Espressif\tools\python\v6.0.2\venv\Scripts\python.exe",
    (Get-Command python -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source -ErrorAction SilentlyContinue)
)
$python = $pythonCandidates | Where-Object { $_ -and (Test-Path -LiteralPath $_) } | Select-Object -First 1
if (-not $python) { throw "A Python 3.11 runtime was not found." }
& $python (Join-Path $repo "tools/run_host_tests.py")
if ($LASTEXITCODE -ne 0) { throw "Firmware host tests failed with exit code $LASTEXITCODE" }
