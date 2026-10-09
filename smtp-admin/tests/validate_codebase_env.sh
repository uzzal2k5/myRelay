
#!/usr/bin/env bash

# ============================================================
# MuktoPay SMTP Admin Portal - Automated Codebase Validation
# Platform: Oracle Linux 9.7
# Python: 3.9+
# ============================================================

set -uo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
REPORT_DIR="${PROJECT_DIR}/validation_reports/${TIMESTAMP}"
VENV_DIR="${PROJECT_DIR}/.venv-review"

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
# Pre-checks
# ------------------------------------------------------------

cd "$PROJECT_DIR" || exit 1

echo "==================================================" | tee "$REPORT"
echo "MuktoPay Codebase Validation Report" | tee -a "$REPORT"
echo "Project: $PROJECT_DIR" | tee -a "$REPORT"
echo "Date: $(date)" | tee -a "$REPORT"
echo "==================================================" | tee -a "$REPORT"

if [[ ! -d app ]]; then
    log "ERROR: app directory not found"
    exit 1
fi

if [[ ! -f requirements.txt ]]; then
    log "WARNING: requirements.txt not found"
    WARN=$((WARN + 1))
fi

# ------------------------------------------------------------
# Git status
# ------------------------------------------------------------

log "Checking Git status"

if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    git status --short > "${REPORT_DIR}/git_status.log"
    git diff --check > "${REPORT_DIR}/git_diff_check.log" 2>&1

    cat "${REPORT_DIR}/git_status.log" >> "$REPORT"
    cat "${REPORT_DIR}/git_diff_check.log" >> "$REPORT"

    if [[ -s "${REPORT_DIR}/git_diff_check.log" ]]; then
        FAIL=$((FAIL + 1))
        log "FAIL: Git whitespace/error check"
    else
        PASS=$((PASS + 1))
        log "PASS: Git whitespace/error check"
    fi
else
    skip_check "Git repository not detected"
fi

# ------------------------------------------------------------
# Python environment
# ------------------------------------------------------------

if [[ ! -d "$VENV_DIR" ]]; then
    log "Creating isolated validation environment"

    python3.9 -m venv "$VENV_DIR" || {
        log "ERROR: Unable to create virtual environment"
        exit 1
    }
fi

# shellcheck disable=SC1091
source "${VENV_DIR}/bin/activate"

python --version | tee -a "$REPORT"

# ------------------------------------------------------------
# Install dependencies and validation tools
# ------------------------------------------------------------

if [[ -f requirements.txt ]]; then
    run_check install_project_dependencies \
        python -m pip install -r requirements.txt
fi

run_check install_validation_tools \
    python -m pip install \
        ruff \
        mypy \
        pytest \
        pytest-cov \
        bandit \
        pip-audit

# ------------------------------------------------------------
# Python syntax validation
# ------------------------------------------------------------

run_check python_syntax \
    python -m compileall -q app

# ------------------------------------------------------------
# Code quality / linting
# ------------------------------------------------------------

run_check ruff_lint \
    ruff check app

run_check ruff_format \
    ruff format --check app

# ------------------------------------------------------------
# Type checking
# ------------------------------------------------------------

run_check mypy_type_check \
    mypy app

# ------------------------------------------------------------
# Security scanning
# ------------------------------------------------------------

run_check bandit_security_scan \
    bandit -r app -ll

# ------------------------------------------------------------
# Dependency vulnerability scan
# ------------------------------------------------------------

run_check dependency_security_scan \
    pip-audit

# ------------------------------------------------------------
# Automated tests
# ------------------------------------------------------------

if [[ -d tests ]]; then
    run_check pytest_tests \
        pytest -v --tb=short \
        --junitxml="${REPORT_DIR}/pytest_results.xml"
else
    skip_check "No tests directory found"
fi

# ------------------------------------------------------------
# Test coverage
# ------------------------------------------------------------

if [[ -d tests ]]; then
    run_check pytest_coverage \
        pytest --cov=app \
        --cov-report=term-missing \
        --cov-report="xml:${REPORT_DIR}/coverage.xml"
else
    skip_check "Coverage skipped: no tests directory"
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