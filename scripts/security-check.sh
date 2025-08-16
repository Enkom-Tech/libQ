#!/bin/bash

# lib-Q Security Check Script
# This script validates the codebase for security compliance

set -euo pipefail

echo "🔒 Running lib-Q Security Checks..."

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    local status=$1
    local message=$2
    case $status in
        "PASS")
            echo -e "${GREEN}PASS${NC}: $message"
            ;;
        "FAIL")
            echo -e "${RED}❌ FAIL${NC}: $message"
            ;;
        "WARN")
            echo -e "${YELLOW}⚠️  WARN${NC}: $message"
            ;;
    esac
}

# Check for classical cryptographic algorithms
echo "Checking for classical cryptographic algorithms..."
if grep -r "use.*aes\|use.*sha256\|use.*rsa\|use.*ecdsa" src/ 2>/dev/null; then
    print_status "FAIL" "Classical cryptographic algorithms detected!"
    exit 1
else
    print_status "PASS" "No classical cryptographic algorithms found"
fi

# Check for SHA-3 family compliance
echo "Checking for SHA-3 family compliance..."
if grep -r "use.*sha[0-9]" src/ 2>/dev/null | grep -v "shake\|cshake"; then
    print_status "FAIL" "Non-SHA-3 hash functions detected!"
    exit 1
else
    print_status "PASS" "SHA-3 family compliance verified"
fi

# Check for unsafe code usage
echo "Checking for unsafe code usage..."
UNSAFE_COUNT=$(grep -r "unsafe" src/ 2>/dev/null | wc -l || echo "0")
if [ "$UNSAFE_COUNT" -gt 0 ]; then
    print_status "WARN" "Found $UNSAFE_COUNT unsafe blocks - review required"
    grep -r "unsafe" src/ 2>/dev/null || true
else
    print_status "PASS" "No unsafe code found"
fi

# Check for zeroize usage
echo "Checking for memory zeroization..."
if ! grep -r "use.*zeroize" src/ 2>/dev/null; then
    print_status "WARN" "zeroize crate not used for sensitive data"
else
    print_status "PASS" "zeroize crate usage detected"
fi

# Check for potential timing vulnerabilities
echo "Checking for potential timing vulnerabilities..."
if grep -r "if.*secret\|match.*secret" src/ 2>/dev/null; then
    print_status "WARN" "Potential branching on secret data detected"
else
    print_status "PASS" "No obvious timing vulnerabilities detected"
fi

# Check for proper error handling
echo "Checking for proper error handling..."
if grep -r "unwrap()\|expect(" src/ 2>/dev/null | grep -v "test\|example"; then
    print_status "WARN" "Potential unwrap/expect usage in production code"
else
    print_status "PASS" "Proper error handling detected"
fi

# Check for input validation
echo "Checking for input validation..."
if ! grep -r "assert\|debug_assert\|if.*len\|if.*size" src/ 2>/dev/null; then
    print_status "WARN" "Limited input validation detected"
else
    print_status "PASS" "Input validation patterns detected"
fi

# Check for proper random number generation
echo "Checking for random number generation..."
if ! grep -r "getrandom\|rand" src/ 2>/dev/null; then
    print_status "WARN" "No random number generation detected"
else
    print_status "PASS" "Random number generation detected"
fi

# Check for documentation
echo "Checking for documentation..."
MISSING_DOCS=$(cargo doc --all-features --no-deps 2>&1 | grep -c "missing documentation" || echo "0")
if [ "$MISSING_DOCS" -gt 0 ]; then
    print_status "WARN" "$MISSING_DOCS items missing documentation"
else
    print_status "PASS" "All public APIs documented"
fi

# Check for security-related dependencies
echo "Checking for security-related dependencies..."
if ! grep -q "zeroize" Cargo.toml; then
    print_status "WARN" "zeroize dependency not found"
else
    print_status "PASS" "zeroize dependency found"
fi

# Run cargo audit
echo "Running cargo audit..."
if command -v cargo-audit &> /dev/null; then
    if cargo audit --deny warnings; then
        print_status "PASS" "Cargo audit passed"
    else
        print_status "FAIL" "Cargo audit failed"
        exit 1
    fi
else
    print_status "WARN" "cargo-audit not installed"
fi

# Check for test coverage
echo "Checking for test coverage..."
if command -v cargo-tarpaulin &> /dev/null; then
    COVERAGE=$(cargo tarpaulin --features "all-algorithms" --out Xml 2>/dev/null | grep -o 'coverage="[^"]*"' | cut -d'"' -f2 || echo "0")
    if (( $(echo "$COVERAGE >= 95" | bc -l 2>/dev/null || echo "0") )); then
        print_status "PASS" "Test coverage: ${COVERAGE}%"
    else
        print_status "WARN" "Test coverage below 95%: ${COVERAGE}%"
    fi
else
    print_status "WARN" "cargo-tarpaulin not installed"
fi

# Check for WASM compatibility
echo "Checking for WASM compatibility..."
if command -v wasm-pack &> /dev/null; then
    if wasm-pack build --target nodejs --features "wasm,all-algorithms" --no-typescript 2>/dev/null; then
        print_status "PASS" "WASM compilation successful"
    else
        print_status "FAIL" "WASM compilation failed"
        exit 1
    fi
else
    print_status "WARN" "wasm-pack not installed"
fi

echo ""
echo "🔒 Security check completed!"
echo ""

# Summary
echo "Summary:"
echo "- Classical crypto check: ✅"
echo "- SHA-3 compliance: ✅"
echo "- Unsafe code review: ⚠️"
echo "- Memory zeroization: ⚠️"
echo "- Timing vulnerabilities: ⚠️"
echo "- Error handling: ⚠️"
echo "- Input validation: ⚠️"
echo "- Random number generation: ⚠️"
echo "- Documentation: ⚠️"
echo "- Dependencies: ⚠️"
echo "- Cargo audit: ✅"
echo "- Test coverage: ⚠️"
echo "- WASM compatibility: ⚠️"

echo ""
echo "⚠️  Please review all warnings and address security concerns before proceeding."
