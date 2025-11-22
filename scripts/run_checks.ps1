$ErrorActionPreference = "Continue"

Write-Host "Starting code quality checks..." -ForegroundColor Cyan

# Create reports directory
New-Item -ItemType Directory -Force -Path reports | Out-Null

# 1. Black
Write-Host "Running Black (code formatter)..." -ForegroundColor Yellow
black --line-length 100 --check app/ tests/
if ($LASTEXITCODE -ne 0) {
    Write-Host "Formatting needed. Running Black to fix..." -ForegroundColor Yellow
    black --line-length 100 app/ tests/
}

# 2. isort
Write-Host "Running isort (import sorting)..." -ForegroundColor Yellow
isort --check-only --profile black app/ tests/
if ($LASTEXITCODE -ne 0) {
    Write-Host "Import sorting needed. Running isort to fix..." -ForegroundColor Yellow
    isort --profile black app/ tests/
}

# 3. Flake8
Write-Host "Running Flake8 (linting)..." -ForegroundColor Yellow
flake8 app/ tests/ --max-line-length=100 --exclude=migrations --output-file=reports/flake8.txt
if ($LASTEXITCODE -ne 0) { Write-Host "Flake8 found issues. Check reports/flake8.txt" -ForegroundColor Red }

# 4. Pylint
Write-Host "Running Pylint (deep analysis)..." -ForegroundColor Yellow
Get-ChildItem -Path app, tests -Recurse -Filter *.py | ForEach-Object { pylint --max-line-length=100 $_.FullName } | Out-File -FilePath reports/pylint.txt -Encoding utf8
Write-Host "Pylint report saved to reports/pylint.txt"

# 5. MyPy
Write-Host "Running MyPy (type checking)..." -ForegroundColor Yellow
mypy app/ --ignore-missing-imports --no-strict-optional | Out-File -FilePath reports/mypy.txt -Encoding utf8
Write-Host "MyPy report saved to reports/mypy.txt"

# 6. Bandit
Write-Host "Running Bandit (security audit)..." -ForegroundColor Yellow
bandit -r app/ -f json -o reports/bandit.json -ll
bandit -r app/ -ll

# 7. Safety
Write-Host "Running Safety (dependencies check)..." -ForegroundColor Yellow
safety check --json | Out-File -FilePath reports/safety.json -Encoding utf8
Write-Host "Safety report saved to reports/safety.json"

Write-Host "All checks completed! Reports saved in reports/" -ForegroundColor Green
