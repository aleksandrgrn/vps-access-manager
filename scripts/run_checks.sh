#!/bin/bash
set -e

echo "🔍 Starting code quality checks..."

# Создать директорию для отчетов
mkdir -p reports

# 1. Black - форматирование
echo "\n📝 Running Black (code formatter)..."
black --line-length 100 --check app/ tests/ || black --line-length 100 app/ tests/

# 2. isort - сортировка импортов
echo "\n📦 Running isort (import sorting)..."
isort --check-only --profile black app/ tests/ || isort --profile black app/ tests/

# 3. Flake8 - линтинг
echo "\n🔎 Running Flake8 (linting)..."
flake8 app/ tests/ --max-line-length=100 --exclude=migrations --output-file=reports/flake8.txt

# 4. Pylint - глубокий анализ
echo "\n🔬 Running Pylint (deep analysis)..."
find app tests -type f -name "*.py" | xargs pylint --max-line-length=100 > reports/pylint.txt || true

# 5. MyPy - type checking
echo "\n🎯 Running MyPy (type checking)..."
mypy app/ --ignore-missing-imports --no-strict-optional > reports/mypy.txt || true

# 6. Bandit - security check
echo "\n🛡️  Running Bandit (security audit)..."
bandit -r app/ -f json -o reports/bandit.json -ll
bandit -r app/ -ll

# 7. Safety - dependency vulnerability check
echo "\n🔐 Running Safety (dependencies check)..."
safety check --json > reports/safety.json || true

echo "\n✅ All checks completed! Reports saved in reports/"
