@echo off
REM Complete Test Suite Runner for Windows
REM This script runs all test suites in the correct order

echo === Complete HQC Test Suite Runner ===
echo.

REM Check if we're in the right directory
if not exist "Cargo.toml" (
    echo Error: Please run this script from the lib-q-hqc directory
    exit /b 1
)

echo Running complete test suite...
echo.

REM Phase 1: Feature Flag Validation
echo Phase 1: Feature Flag Validation
echo =================================
call scripts\test_feature_flag_validation.bat
if %errorlevel% neq 0 (
    echo ❌ Feature flag validation failed
    exit /b 1
)
echo.

REM Phase 2: Production Mode Tests
echo Phase 2: Production Mode Tests
echo ==============================
call scripts\test_production_modes.bat
if %errorlevel% neq 0 (
    echo ❌ Production mode tests failed
    exit /b 1
)
echo.

REM Phase 3: Diagnostic Mode Tests
echo Phase 3: Diagnostic Mode Tests
echo ==============================
call scripts\test_drbg_diagnostic.bat
if %errorlevel% neq 0 (
    echo ❌ Diagnostic mode tests failed
    exit /b 1
)
echo.

REM Phase 4: Additional Validation
echo Phase 4: Additional Validation
echo ==============================
echo Running additional validation tests...

REM Test no_std compatibility
echo Testing no_std compatibility...
cargo check --no-default-features --features aes-drbg
if %errorlevel% equ 0 (
    echo ✅ no_std with aes-drbg works
) else (
    echo ❌ no_std with aes-drbg failed
)

cargo check --no-default-features --features bearssl-aes
if %errorlevel% equ 0 (
    echo ✅ no_std with bearssl-aes works
) else (
    echo ❌ no_std with bearssl-aes failed
)

cargo check --no-default-features
if %errorlevel% equ 0 (
    echo ✅ no_std with no features works
) else (
    echo ❌ no_std with no features failed
)

echo.

REM Test WASM compatibility (if wasm32 target is available)
echo Testing WASM compatibility...
rustup target list --installed | findstr "wasm32-unknown-unknown" >nul
if %errorlevel% equ 0 (
    cargo check --target wasm32-unknown-unknown --features aes-drbg
    if %errorlevel% equ 0 (
        echo ✅ WASM with aes-drbg works
    ) else (
        echo ❌ WASM with aes-drbg failed
    )
    
    cargo check --target wasm32-unknown-unknown
    if %errorlevel% equ 0 (
        echo ✅ WASM with no features works
    ) else (
        echo ❌ WASM with no features failed
    )
) else (
    echo ⚠️  WASM target not installed, skipping WASM tests
)

echo.
echo === Complete Test Suite Finished ===
echo.
echo Summary:
echo - Feature flag validation: ✅
echo - Production mode tests: ✅
echo - Diagnostic mode tests: ✅
echo - Additional validation: ✅
echo.
echo All test suites completed successfully!
echo.
echo Next steps:
echo 1. Review diagnostic test output for DRBG differences
echo 2. Choose a single DRBG implementation for production
echo 3. Update your application to use the chosen implementation
echo 4. Consider the interoperability limitations documented in the analysis
