#!/usr/bin/env bash
# Doc drift check — run locally or in CI to catch documentation lagging code.
#
# Checks:
#   1. Test count in README.md / README.ko.md matches `pytest --collect-only`
#   2. terraform.tfvars.example contains only variables declared in variables.tf
#      (also runs `terraform validate` to catch other config drift)
#   3. IAM tables in README.md and docs/ANALYSIS_AGENT_REQUIREMENTS.md agree
#      row-by-row (Supervisor, Sub-agent, Tools Lambda, Gateway, Trigger,
#      Runner, Healthcheck)
#
# Exit code: 0 = all checks passed, non-zero = drift detected.
#
# Usage:
#   scripts/check_doc_drift.sh                # run all checks
#   scripts/check_doc_drift.sh --tests-only   # only check 1
#   scripts/check_doc_drift.sh --tfvars-only  # only check 2
#   scripts/check_doc_drift.sh --iam-only     # only check 3
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"

RUN_TESTS=true
RUN_TFVARS=true
RUN_IAM=true
for arg in "$@"; do
  case "$arg" in
    --tests-only)   RUN_TFVARS=false; RUN_IAM=false ;;
    --tfvars-only)  RUN_TESTS=false;  RUN_IAM=false ;;
    --iam-only)     RUN_TESTS=false;  RUN_TFVARS=false ;;
    -h|--help)
      grep -E '^#( |$)' "$0" | sed 's/^# \{0,1\}//'
      exit 0
      ;;
    *) echo "unknown flag: $arg" >&2; exit 2 ;;
  esac
done

FAILURES=0
pass() { printf '  \033[32m✓\033[0m %s\n' "$*"; }
fail() { printf '  \033[31m✗\033[0m %s\n' "$*"; FAILURES=$((FAILURES + 1)); }
info() { printf '\n\033[1m%s\033[0m\n' "$*"; }

# ─────────────────────────────────────────────────────────────
# Check 1 — test count in READMEs matches pytest
# ─────────────────────────────────────────────────────────────
if $RUN_TESTS; then
  info "[1/3] Test count in README vs pytest --collect-only"

  cd "$ROOT_DIR"
  if [ ! -d ".venv" ]; then
    fail "no .venv/ found — cannot invoke pytest. Run 'python -m venv .venv && .venv/bin/pip install pytest'"
  else
    # shellcheck disable=SC1091
    source .venv/bin/activate

    ACTUAL=$(pytest tests/test_tools.py --collect-only -q 2>/dev/null \
             | grep -oE '[0-9]+ tests? collected' \
             | grep -oE '^[0-9]+')

    if [ -z "$ACTUAL" ]; then
      fail "could not parse pytest test count"
    else
      pass "pytest reports $ACTUAL tests"

      # README.md: expect "Unit tests ($ACTUAL," AND "# $ACTUAL tests"
      for pattern in "Unit tests ($ACTUAL," "# $ACTUAL tests"; do
        if grep -qF "$pattern" README.md; then
          pass "README.md contains \"$pattern\""
        else
          fail "README.md missing \"$pattern\" — did test count change without doc update?"
        fi
      done

      # README.ko.md: expect "단위 테스트 (${ACTUAL}개" AND "# ${ACTUAL}개 테스트"
      for pattern in "단위 테스트 (${ACTUAL}개" "# ${ACTUAL}개 테스트"; do
        if grep -qF "$pattern" README.ko.md; then
          pass "README.ko.md contains \"$pattern\""
        else
          fail "README.ko.md missing \"$pattern\" — did test count change without doc update?"
        fi
      done
    fi
  fi
fi

# ─────────────────────────────────────────────────────────────
# Check 2 — tfvars.example vs variables.tf + terraform validate
# ─────────────────────────────────────────────────────────────
if $RUN_TFVARS; then
  info "[2/3] terraform.tfvars.example vs variables.tf + terraform validate"

  INFRA_DIR="$ROOT_DIR/infra"
  VARS_TF="$INFRA_DIR/variables.tf"
  TFVARS_EXAMPLE="$INFRA_DIR/terraform.tfvars.example"

  if [ ! -f "$VARS_TF" ] || [ ! -f "$TFVARS_EXAMPLE" ]; then
    fail "expected $VARS_TF and $TFVARS_EXAMPLE to exist"
  else
    # Extract declared variable names (lines like: variable "foo" {)
    DECLARED=$(grep -oE '^variable "[a-zA-Z_][a-zA-Z0-9_]*"' "$VARS_TF" \
               | sed 's/^variable "//; s/"$//' \
               | sort -u)

    # Extract used variable names from tfvars.example (lines like: name = value)
    USED=$(grep -oE '^[a-zA-Z_][a-zA-Z0-9_]*[[:space:]]*=' "$TFVARS_EXAMPLE" \
           | sed 's/[[:space:]]*=$//' \
           | sort -u)

    UNDECLARED=$(comm -23 <(printf '%s\n' "$USED") <(printf '%s\n' "$DECLARED"))
    if [ -z "$UNDECLARED" ]; then
      pass "tfvars.example references only declared variables"
    else
      while IFS= read -r var; do
        [ -n "$var" ] && fail "tfvars.example uses undeclared variable: $var"
      done <<< "$UNDECLARED"
    fi

    # Run terraform validate — catches other config drift (syntax, refs)
    if command -v terraform >/dev/null 2>&1; then
      cd "$INFRA_DIR"
      if [ ! -d ".terraform" ]; then
        info "  (running 'terraform init -backend=false' for validate…)"
        if ! terraform init -backend=false -input=false >/dev/null 2>&1; then
          fail "terraform init failed"
        fi
      fi
      if terraform validate >/dev/null 2>&1; then
        pass "terraform validate passed"
      else
        fail "terraform validate failed — run 'cd infra && terraform validate' for details"
      fi
    else
      fail "terraform CLI not found in PATH — cannot run 'terraform validate'"
    fi
  fi
fi

# ─────────────────────────────────────────────────────────────
# Check 3 — IAM tables in README vs spec doc agree
# ─────────────────────────────────────────────────────────────
if $RUN_IAM; then
  info "[3/3] IAM tables in README.md vs docs/ANALYSIS_AGENT_REQUIREMENTS.md"

  README_FILE="$ROOT_DIR/README.md"
  SPEC_FILE="$ROOT_DIR/docs/ANALYSIS_AGENT_REQUIREMENTS.md"

  if [ ! -f "$README_FILE" ] || [ ! -f "$SPEC_FILE" ]; then
    fail "expected $README_FILE and $SPEC_FILE to exist"
  else
    ROLES=(
      "Supervisor Runtime"
      "Sub-agent Runtimes"
      "Tools Lambda"
      "Gateway"
      "Trigger Lambda"
      "Runner Lambda"
      "Healthcheck Lambda"
    )
    for role in "${ROLES[@]}"; do
      # Extract the row starting with "| $role |" from each file
      # Use fixed-string grep + head -n1 (first hit only)
      readme_row=$(grep -F "| $role |" "$README_FILE" | head -n1 || true)
      spec_row=$(grep -F "| $role |" "$SPEC_FILE" | head -n1 || true)

      if [ -z "$readme_row" ]; then
        fail "README.md missing IAM row for \"$role\""
      elif [ -z "$spec_row" ]; then
        fail "spec doc missing IAM row for \"$role\""
      elif [ "$readme_row" = "$spec_row" ]; then
        pass "IAM row \"$role\" matches"
      else
        fail "IAM row \"$role\" differs between README.md and spec doc"
        echo "  README: ${readme_row:0:120}…" >&2
        echo "  Spec  : ${spec_row:0:120}…" >&2
      fi
    done
  fi
fi

# ─────────────────────────────────────────────────────────────
info "Result"
if [ "$FAILURES" -eq 0 ]; then
  pass "all doc-drift checks passed"
  exit 0
else
  fail "$FAILURES drift issue(s) found"
  exit 1
fi
