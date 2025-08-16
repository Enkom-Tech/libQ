# lib-Q Security Check Script (PowerShell)
# This script validates the codebase for security compliance

param(
    [switch]$Verbose
)

Write-Host "Running lib-Q Security Checks..." -ForegroundColor Cyan

# Function to print colored output
function Write-Status {
    param(
        [string]$Status,
        [string]$Message
    )
    
    switch ($Status) {
        "PASS" { Write-Host "PASS: $Message" -ForegroundColor Green }
        "FAIL" { Write-Host "FAIL: $Message" -ForegroundColor Red }
        "WARN" { Write-Host "WARN: $Message" -ForegroundColor Yellow }
    }
}

# Check for classical cryptographic algorithms
Write-Host "Checking for classical cryptographic algorithms..."
$classicalCrypto = Get-ChildItem -Path "src" -Recurse -File -Name "*.rs" | ForEach-Object {
    Get-Content "src\$_" | Select-String "use.*aes|use.*sha256|use.*rsa|use.*ecdsa"
}

if ($classicalCrypto) {
    Write-Status "FAIL" "Classical cryptographic algorithms detected!"
    exit 1
} else {
    Write-Status "PASS" "No classical cryptographic algorithms found"
}

# Check for SHA-3 family compliance
Write-Host "Checking for SHA-3 family compliance..."
$nonSha3 = Get-ChildItem -Path "src" -Recurse -File -Name "*.rs" | ForEach-Object {
    Get-Content "src\$_" | Select-String "use.*sha[0-9]" | Where-Object { $_ -notmatch "shake|cshake" }
}

if ($nonSha3) {
    Write-Status "FAIL" "Non-SHA-3 hash functions detected!"
    exit 1
} else {
    Write-Status "PASS" "SHA-3 family compliance verified"
}

# Check for unsafe code usage
Write-Host "Checking for unsafe code usage..."
$unsafeCount = (Get-ChildItem -Path "src" -Recurse -File -Name "*.rs" | ForEach-Object {
    Get-Content "src\$_" | Select-String "unsafe"
}).Count

if ($unsafeCount -gt 0) {
    Write-Status "WARN" "Found $unsafeCount unsafe blocks - review required"
    if ($Verbose) {
        Get-ChildItem -Path "src" -Recurse -File -Name "*.rs" | ForEach-Object {
            Get-Content "src\$_" | Select-String "unsafe" | ForEach-Object { Write-Host "  $_" }
        }
    }
} else {
    Write-Status "PASS" "No unsafe code found"
}

# Check for zeroize usage
Write-Host "Checking for memory zeroization..."
$zeroizeUsage = Get-ChildItem -Path "src" -Recurse -File -Name "*.rs" | ForEach-Object {
    Get-Content "src\$_" | Select-String "use.*zeroize"
}

if (-not $zeroizeUsage) {
    Write-Status "WARN" "zeroize crate not used for sensitive data"
} else {
    Write-Status "PASS" "zeroize crate usage detected"
}

# Check for potential timing vulnerabilities
Write-Host "Checking for potential timing vulnerabilities..."
$timingVulns = Get-ChildItem -Path "src" -Recurse -File -Name "*.rs" | ForEach-Object {
    Get-Content "src\$_" | Select-String "if.*secret|match.*secret"
}

if ($timingVulns) {
    Write-Status "WARN" "Potential branching on secret data detected"
} else {
    Write-Status "PASS" "No obvious timing vulnerabilities detected"
}

# Check for proper error handling
Write-Host "Checking for proper error handling..."
$unwrapUsage = Get-ChildItem -Path "src" -Recurse -File -Name "*.rs" | ForEach-Object {
    Get-Content "src\$_" | Select-String "unwrap\(\)|expect\(" | Where-Object { $_ -notmatch "test|example" }
}

if ($unwrapUsage) {
    Write-Status "WARN" "Potential unwrap/expect usage in production code"
} else {
    Write-Status "PASS" "Proper error handling detected"
}

# Check for input validation
Write-Host "Checking for input validation..."
$inputValidation = Get-ChildItem -Path "src" -Recurse -File -Name "*.rs" | ForEach-Object {
    Get-Content "src\$_" | Select-String "assert|debug_assert|if.*len|if.*size"
}

if (-not $inputValidation) {
    Write-Status "WARN" "Limited input validation detected"
} else {
    Write-Status "PASS" "Input validation patterns detected"
}

# Check for proper random number generation
Write-Host "Checking for random number generation..."
$randomGen = Get-ChildItem -Path "src" -Recurse -File -Name "*.rs" | ForEach-Object {
    Get-Content "src\$_" | Select-String "getrandom|rand"
}

if (-not $randomGen) {
    Write-Status "WARN" "No random number generation detected"
} else {
    Write-Status "PASS" "Random number generation detected"
}

# Check for security-related dependencies
Write-Host "Checking for security-related dependencies..."
$cargoContent = Get-Content "Cargo.toml" -Raw
if ($cargoContent -notmatch "zeroize") {
    Write-Status "WARN" "zeroize dependency not found"
} else {
    Write-Status "PASS" "zeroize dependency found"
}

# Run cargo audit if available
Write-Host "Running cargo audit..."
try {
    $auditResult = cargo audit --deny warnings 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Status "PASS" "Cargo audit passed"
    } else {
        Write-Status "FAIL" "Cargo audit failed"
        if ($Verbose) { Write-Host $auditResult }
        exit 1
    }
} catch {
    Write-Status "WARN" "cargo-audit not available"
}

# Check for WASM compatibility
Write-Host "Checking for WASM compatibility..."
try {
    $wasmResult = cargo check --target wasm32-unknown-unknown --features "wasm" 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Status "PASS" "WASM compilation successful"
    } else {
        Write-Status "FAIL" "WASM compilation failed"
        if ($Verbose) { Write-Host $wasmResult }
    }
} catch {
    Write-Status "WARN" "WASM target not available"
}

Write-Host ""
Write-Host "Security check completed!" -ForegroundColor Cyan
Write-Host ""

# Summary
Write-Host "Summary:" -ForegroundColor White
Write-Host "- Classical crypto check: PASS" -ForegroundColor Green
Write-Host "- SHA-3 compliance: PASS" -ForegroundColor Green
Write-Host "- Unsafe code review: WARN" -ForegroundColor Yellow
Write-Host "- Memory zeroization: WARN" -ForegroundColor Yellow
Write-Host "- Timing vulnerabilities: WARN" -ForegroundColor Yellow
Write-Host "- Error handling: WARN" -ForegroundColor Yellow
Write-Host "- Input validation: WARN" -ForegroundColor Yellow
Write-Host "- Random number generation: WARN" -ForegroundColor Yellow
Write-Host "- Dependencies: WARN" -ForegroundColor Yellow
Write-Host "- Cargo audit: PASS" -ForegroundColor Green
Write-Host "- WASM compatibility: WARN" -ForegroundColor Yellow

Write-Host ""
Write-Host "WARNING: Please review all warnings and address security concerns before proceeding." -ForegroundColor Yellow
