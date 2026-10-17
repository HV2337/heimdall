param(
    [Parameter(Position = 0)]
    [ValidateSet("test", "run", "eval")]
    [string]$Task = "test"
)

$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent $PSScriptRoot
Push-Location $RepoRoot
try {
    switch ($Task) {
        "test" {
            & python -m unittest discover -s tests -v
        }
        "run" {
            & python -m uvicorn gateway.main:app --host 0.0.0.0 --port 8000
        }
        "eval" {
            & python -m unittest discover -s tests -v
        }
    }
    if ($LASTEXITCODE -ne 0) {
        exit $LASTEXITCODE
    }
}
finally {
    Pop-Location
}
