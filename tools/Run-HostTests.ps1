[CmdletBinding()]
param(
    [string]$OutputDirectory = "test-results/host",
    [string]$PythonPath
)

$ErrorActionPreference = "Stop"
$repo = Split-Path -Parent $PSScriptRoot
$workspace = Split-Path -Parent $repo
$pythonCandidates = @(
    $PythonPath,
    (Join-Path $workspace ".venv\Scripts\python.exe"),
    "C:\Espressif\tools\python\v6.0.2\venv\Scripts\python.exe",
    (Get-Command python -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source -ErrorAction SilentlyContinue)
)
$python = $pythonCandidates | Where-Object { $_ -and (Test-Path -LiteralPath $_) } | Select-Object -First 1
if (-not $python) { throw "A Python 3.11 runtime was not found." }
& $python -c "import jsonschema"
if ($LASTEXITCODE -ne 0) {
    throw "Host-test dependencies are missing from '$python'. Install the exact hashes from test/host/requirements.txt into that interpreter, or pass -PythonPath for an existing environment that contains them."
}
& (Join-Path $repo "test/powershell/ProvisioningUx.Tests.ps1")
& $python (Join-Path $repo "tools/run_host_tests.py")
if ($LASTEXITCODE -ne 0) { throw "Firmware host tests failed with exit code $LASTEXITCODE" }
