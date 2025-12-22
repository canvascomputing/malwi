#!/bin/bash
set -e

echo "=========================================="
echo "Testing malwi Python integration"
echo "Python version: $(python3 --version)"
echo "=========================================="

# Test 1: Basic audit hook functionality
echo ""
echo "Test 1: Audit hook captures events"
echo "---"
OUTPUT=$(timeout 10 ./malwi x python3 -c "print('hello')" 2>&1 || true)

if echo "$OUTPUT" | grep -q "\[AUDIT\]"; then
    echo "PASS: Audit hook events captured"
else
    echo "FAIL: No audit events found"
    echo "$OUTPUT"
    exit 1
fi

# Test 2: py: filter syntax
echo ""
echo "Test 2: py: filter syntax parses correctly"
echo "---"
OUTPUT=$(timeout 10 ./malwi x -c py:exec python3 -c "exec('1+1')" 2>&1 || true)

if echo "$OUTPUT" | grep -q "Added filter for: exec"; then
    echo "PASS: Filter added for exec"
else
    echo "FAIL: Filter not added"
    echo "$OUTPUT"
    exit 1
fi

# Test 3: Native hook still works
echo ""
echo "Test 3: Native hooks work"
echo "---"
OUTPUT=$(timeout 10 ./malwi x -c malloc python3 -c "x = [1,2,3]" 2>&1 || true)

if echo "$OUTPUT" | grep -q "Hooked malloc"; then
    echo "PASS: Native malloc hook added"
else
    echo "FAIL: Native hook not added"
    echo "$OUTPUT"
    exit 1
fi

echo ""
echo "=========================================="
echo "All tests passed!"
echo "=========================================="
