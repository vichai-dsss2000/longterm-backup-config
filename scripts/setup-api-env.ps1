<#
Setup script for the API Python virtual environment (Windows PowerShell)

This script attempts to:
- Locate a suitable Python executable (prefers Python 3.11 when available)
- Create a venv at ./api/.venv
- Upgrade pip/setuptools/wheel and install dependencies from api/requirements.txt

Usage:
  Open PowerShell as your normal user (not necessarily admin) and run:
    .\scripts\setup-api-env.ps1

If you need to force a specific Python executable, run:
    .\scripts\setup-api-env.ps1 -PythonExe 'C:\Path\To\python.exe'

Notes:
- pydantic-core may try to build from source on unsupported Python versions (3.13+).
  If you see build errors for pydantic-core, create the venv with Python 3.11 and rerun.
#>

param(
    [string]$PythonExe
)

function Write-Status($msg){ Write-Host "[setup-api-env] $msg" -ForegroundColor Cyan }

Write-Status "Starting setup script..."

if (-not $PythonExe) {
    # Prefer py launcher for specific version if available
    try {
        $py311 = & py -3.11 -c "import sys; print(sys.executable)" 2>$null
        if ($LASTEXITCODE -eq 0 -and $py311) {
            $PythonExe = $py311.Trim()
            Write-Status "Found Python 3.11 via py launcher: $PythonExe"
        }
    } catch {}
}

if (-not $PythonExe) {
    try {
        $verOut = & python -c "import sys, json; print(json.dumps({'ver': sys.version_info[:], 'exe': sys.executable}))" 2>$null
        if ($LASTEXITCODE -eq 0 -and $verOut) {
            $info = ConvertFrom-Json $verOut
            $PythonExe = $info.exe
            Write-Status "Using python: $PythonExe (version $($info.ver[0]).$($info.ver[1]))"
        }
    } catch {
        # nothing
    }
}

if (-not $PythonExe) {
    Write-Host "ERROR: No suitable Python executable found. Install Python 3.11 and ensure 'py' or 'python' is in PATH." -ForegroundColor Red
    exit 1
}

# Check Python major/minor
$pyVer = & "$PythonExe" -c "import sys; print('.'.join(map(str, sys.version_info[:3])))"
Write-Status "Detected Python version: $pyVer"

# Create venv in api/.venv
Push-Location -Path "$PSScriptRoot\..\api"
try {
    Write-Status "Creating virtual environment at ./api/.venv using $PythonExe"
    & "$PythonExe" -m venv .venv
} catch {
    Write-Host "ERROR: Failed to create venv: $_" -ForegroundColor Red
    Pop-Location
    exit 1
}

Write-Status "Upgrading pip, setuptools and wheel in the new venv"
& ".\.venv\Scripts\python.exe" -m pip install --upgrade pip setuptools wheel | Write-Host

Write-Status "Installing dependencies from requirements.txt (prefer binary wheels)"
& ".\.venv\Scripts\python.exe" -m pip install --prefer-binary -r requirements.txt
$installExit = $LASTEXITCODE

if ($installExit -ne 0) {
    Write-Host "\nInstallation finished with errors (exit code $installExit)." -ForegroundColor Yellow
    Write-Host "Common causes: building pydantic-core from source on unsupported Python versions (3.13+), missing build tools (Visual C++), or missing Rust toolchain. Recommended fixes:" -ForegroundColor Cyan
    Write-Host " - Use Python 3.11 to create the venv (install from python.org), or run this script with -PythonExe specifying a Python 3.11 executable." -ForegroundColor Cyan
    Write-Host " - If you must build from source, install Visual C++ Build Tools and Rust (https://www.rust-lang.org/tools/install)." -ForegroundColor Cyan
    Write-Host "Please re-run the script after addressing the above, or send the full pip output to the maintainer for help." -ForegroundColor Cyan
    Pop-Location
    exit $installExit
}

Write-Status "Dependencies installed successfully. Activate the venv with:`n  . .\.venv\Scripts\Activate.ps1` and then run the API." 
Pop-Location
exit 0
