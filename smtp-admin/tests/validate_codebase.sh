
#!/usr/bin/env bash

# ============================================================
# MuktoPay SMTP Admin Portal - Codebase Validation
# Uses existing Python environment
# No virtual environment creation
# ============================================================

set -uo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
REPORT_DIR="${PROJECT_DIR}/validation_reports/${TIMESTAMP}"

mkdir -p "$REPORT_DIR"

REPORT="${REPORT_DIR}/validation_report.txt"
SUMMARY="${REPORT_DIR}/summary.txt"

PASS=0
FAIL=0
WARN=0

# ------------------------------------------------------------
# Logging
# ------------------------------------------------------------

log() {
    echo "[$(date '+%F %T')] $*" | tee -a "$REPORT"
}

run_check() {
    local name="$1"
    shift

    local output="${REPORT_DIR}/${name}.log"

    log "START: ${name}"

    if "$@" > "$output" 2>&1; then
        echo "PASS: ${name}" | tee -a "$REPORT"
        PASS=$((PASS + 1))
    else
        local rc=$?
        echo "FAIL: ${name} (exit ${rc})" | tee -a "$REPORT"
        FAIL=$((FAIL + 1))
    fi

    cat "$output" >> "$REPORT"
    echo "" >> "$REPORT"
}

skip_check() {
    log "SKIP: $1"
    WARN=$((WARN + 1))
}

# ------------------------------------------------------------
# Project validation
# ------------------------------------------------------------

cd "$PROJECT_DIR" || exit 1

{
    echo "=================================================="
    echo "MuktoPay Codebase Validation Report"
    echo "Project: $PROJECT_DIR"
    echo "Date: $(date)"
    echo "=================================================="
} | tee "$REPORT"

if [[ ! -d app ]]; then
    log "ERROR: app directory not found"
    exit 1
fi

# ------------------------------------------------------------
# Python environment
# ------------------------------------------------------------

PYTHON_BIN="${PYTHON_BIN:-python3.9}"

if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
    log "ERROR: Python executable not found: $PYTHON_BIN"
    exit 1
fi

"$PYTHON_BIN" --version | tee -a "$REPORT"

# ------------------------------------------------------------
# Tool availability
# ------------------------------------------------------------

check_tool() {
    local tool="$1"

    if command -v "$tool" >/dev/null 2>&1; then
        return 0
    fi

    log "WARNING: Tool not installed: $tool"
    WARN=$((WARN + 1))
    return 1
}

# ------------------------------------------------------------
# Git validation
# ------------------------------------------------------------

if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then

    git status --short \
        > "${REPORT_DIR}/git_status.log"

    if git diff --check \
        > "${REPORT_DIR}/git_diff_check.log" 2>&1; then
        log "PASS: Git diff check"
        PASS=$((PASS + 1))
    else
        log "FAIL: Git diff check"
        FAIL=$((FAIL + 1))
    fi

else
    skip_check "Git repository not detected"
fi

# ------------------------------------------------------------
# Python syntax
# ------------------------------------------------------------

run_check python_syntax \
    "$PYTHON_BIN" -m compileall -q app

# ------------------------------------------------------------
# Ruff lint
# ------------------------------------------------------------

if check_tool ruff; then
    run_check ruff_lint ruff check app
else
    skip_check "Ruff lint skipped"
fi

# ------------------------------------------------------------
# Ruff formatting
# ------------------------------------------------------------

if check_tool ruff; then
    run_check ruff_format ruff format --check app
else
    skip_check "Ruff format skipped"
fi

# ------------------------------------------------------------
# Mypy
# ------------------------------------------------------------

if check_tool mypy; then
    run_check mypy_type_check mypy app
else
    skip_check "Mypy skipped"
fi

# ------------------------------------------------------------
# Bandit security scan
# ------------------------------------------------------------

if check_tool bandit; then
    run_check bandit_security_scan bandit -r app -ll
else
    skip_check "Bandit skipped"
fi

# ------------------------------------------------------------
# Dependency security scan
# ------------------------------------------------------------

if check_tool pip-audit; then
    run_check dependency_security_scan pip-audit
else
    skip_check "pip-audit skipped"
fi

# ------------------------------------------------------------
# Pytest
# ------------------------------------------------------------

if [[ -d tests ]] && check_tool pytest; then

    run_check pytest_tests \
        pytest -v --tb=short \
        --junitxml="${REPORT_DIR}/pytest_results.xml"

    if pytest --help 2>&1 | grep -q -- '--cov'; then

        run_check pytest_coverage \
            pytest --cov=app \
            --cov-report=term-missing \
            --cov-report="xml:${REPORT_DIR}/coverage.xml"

    else
        skip_check "pytest-cov plugin not installed"
    fi

else
    skip_check "Tests directory or pytest unavailable"
fi

# ------------------------------------------------------------
# Final summary
# ------------------------------------------------------------

{
    echo "=================================================="
    echo "VALIDATION SUMMARY"
    echo "=================================================="
    echo "Project: $PROJECT_DIR"
    echo "Date: $(date)"
    echo "Passed checks: $PASS"
    echo "Failed checks: $FAIL"
    echo "Skipped checks: $WARN"
    echo "Report directory: $REPORT_DIR"
    echo "=================================================="

    if [[ "$FAIL" -eq 0 ]]; then
        echo "RESULT: No check failures detected."
        echo "Manual review and UAT are still required."
    else
        echo "RESULT: Validation findings require review."
    fi
} | tee "$SUMMARY"

cat "$SUMMARY" >> "$REPORT"

echo ""
echo "Validation completed."
echo "Summary: $SUMMARY"
echo "Full report: $REPORT"

if [[ "$FAIL" -gt 0 ]]; then
    exit 1
fi

exit 0