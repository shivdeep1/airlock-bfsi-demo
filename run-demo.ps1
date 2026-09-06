$ErrorActionPreference = 'Stop'
Push-Location $PSScriptRoot
try {
    if (Test-Path -LiteralPath '.venv\Scripts\python.exe') {
        & '.\.venv\Scripts\python.exe' -m airlock_checkpoint.submission @args
    } else {
        if (-not (Get-Command uv -ErrorAction SilentlyContinue)) {
            throw 'uv is required for first-time setup. See README.md.'
        }
        & uv sync --frozen --extra dev
        if ($LASTEXITCODE -ne 0) { throw 'Dependency setup failed.' }
        & uv run --frozen --no-sync python -m airlock_checkpoint.submission @args
    }
    if ($LASTEXITCODE -ne 0) { throw 'The demo exited with an error. Read the terminal output above.' }
} finally {
    Pop-Location
}
