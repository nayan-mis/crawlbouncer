#!/bin/bash
# ─────────────────────────────────────────────────────────────────
# CrawlBouncer — Test Runner
# Run from the backend/ directory:
#   bash tests/run_tests.sh
# ─────────────────────────────────────────────────────────────────

set -e
cd "$(dirname "$0")/.."

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  CrawlBouncer Test Suite"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Check dependencies
echo "→ Checking dependencies..."
pip install -q -r requirements-dev.txt

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Running all tests"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# Run with verbose output and coverage summary
python -m pytest tests/ \
  --tb=short \
  --no-header \
  -v \
  --color=yes \
  -p no:warnings \
  "$@"

EXIT_CODE=$?

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

if [ $EXIT_CODE -eq 0 ]; then
  echo "  ✅  All tests passed"
else
  echo "  ❌  Some tests failed — see output above"
fi

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Clean up test database
rm -f test_crawlbouncer.db

exit $EXIT_CODE
