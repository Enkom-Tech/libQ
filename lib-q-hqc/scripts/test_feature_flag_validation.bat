@echo off
REM Feature Flag Validation Test Suite for Windows
REM This script validates that feature flags work correctly and prevent invalid combinations

echo === Feature Flag Validation Test Suite ===
echo.

REM Check if we're in the right directory
if not exist "Cargo.toml" (
    echo Error: Please run this script from the lib-q-hqc directory
    exit /b 1
)

echo Validating feature flag combinations...
echo.

REM Test 1: Both features enabled without debug-drbg-interop (should fail)
echo 1. Testing invalid combination: aes-drbg + bearssl-aes without debug-drbg-interop
echo    (This should fail with a compile error)
cargo check --features aes-drbg,bearssl-aes > temp_output.txt 2>&1
findstr /C:"compile_error" temp_output.txt >nul
if %errorlevel% equ 0 (
    echo    ✅ Correctly failed with compile error
) else (
    echo    ❌ Should have failed but didn't
    del temp_output.txt
    exit /b 1
)
del temp_output.txt

echo.

REM Test 2: Both features enabled with debug-drbg-interop (should succeed)
echo 2. Testing valid combination: aes-drbg + bearssl-aes + debug-drbg-interop
echo    (This should compile successfully)
cargo check --features aes-drbg,bearssl-aes,debug-drbg-interop
if %errorlevel% equ 0 (
    echo    ✅ Correctly compiled with debug-drbg-interop
) else (
    echo    ❌ Failed to compile with debug-drbg-interop
    exit /b 1
)

echo.

REM Test 3: Only aes-drbg (should succeed)
echo 3. Testing single feature: aes-drbg only
cargo check --features aes-drbg
if %errorlevel% equ 0 (
    echo    ✅ Correctly compiled with aes-drbg only
) else (
    echo    ❌ Failed to compile with aes-drbg only
    exit /b 1
)

echo.

REM Test 4: Only bearssl-aes (should succeed)
echo 4. Testing single feature: bearssl-aes only
cargo check --features bearssl-aes
if %errorlevel% equ 0 (
    echo    ✅ Correctly compiled with bearssl-aes only
) else (
    echo    ❌ Failed to compile with bearssl-aes only
    exit /b 1
)

echo.

REM Test 5: No features (should succeed with SHAKE256 fallback)
echo 5. Testing no features (SHAKE256 fallback)
cargo check
if %errorlevel% equ 0 (
    echo    ✅ Correctly compiled with no features (SHAKE256 fallback)
) else (
    echo    ❌ Failed to compile with no features
    exit /b 1
)

echo.
echo === Feature Flag Validation Complete ===
echo.
echo Summary:
echo - Invalid combinations are properly rejected
echo - Valid combinations compile successfully
echo - Single features work correctly
echo - No features fallback works correctly
echo.
echo Feature flag management is working as expected!
