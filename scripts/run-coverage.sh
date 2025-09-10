#!/bin/bash
# Bash script for running targeted test coverage analysis

CRATE=""
NO_REFERENCE=true
SHOW_REPORT=true
OUTPUT_DIR="coverage"
OUTPUT_FORMAT="Html"
IGNORE_TESTS=true
IGNORE_PANICS=true
LINE_THRESHOLD="95"
TOOLCHAIN="stable"

# Parse arguments
while [[ $# -gt 0 ]]; do
  case $1 in
    --crate)
      CRATE="$2"
      shift 2
      ;;
    --no-reference)
      NO_REFERENCE=true
      shift
      ;;
    --with-reference)
      NO_REFERENCE=false
      shift
      ;;
    --no-report)
      SHOW_REPORT=false
      shift
      ;;
    --output-dir)
      OUTPUT_DIR="$2"
      shift 2
      ;;
    --format)
      OUTPUT_FORMAT="$2"
      shift 2
      ;;
    --with-tests)
      IGNORE_TESTS=false
      shift
      ;;
    --with-panics)
      IGNORE_PANICS=false
      shift
      ;;
    --threshold)
      LINE_THRESHOLD="$2"
      shift 2
      ;;
    --toolchain)
      TOOLCHAIN="$2"
      shift 2
      ;;
    *)
      echo "Unknown option: $1"
      echo "Usage: $0 [--crate CRATE] [--no-reference|--with-reference] [--no-report] [--output-dir DIR] [--format FORMAT] [--with-tests] [--with-panics] [--threshold THRESHOLD] [--toolchain TOOLCHAIN]"
      exit 1
      ;;
  esac
done

# Create directory for coverage reports if it doesn't exist
mkdir -p "$OUTPUT_DIR"

# Build the tarpaulin command
if [[ "$TOOLCHAIN" == "stable" ]]; then
  CMD="cargo tarpaulin"
else
  CMD="cargo +$TOOLCHAIN tarpaulin"
fi

# Add package filter if specified
if [[ -n "$CRATE" ]]; then
  CMD="$CMD --packages $CRATE"
  
  # Use crate-specific tarpaulin config if it exists
  if [[ -f "$CRATE/.tarpaulin.toml" ]]; then
    CMD="$CMD --config $CRATE/.tarpaulin.toml"
  fi
  
  # Add crate-specific features if needed
  if [[ "$CRATE" == "lib-q-core" ]]; then
    CMD="$CMD --features std,rand"
  elif [[ "$CRATE" == "lib-q" ]]; then
    CMD="$CMD --features all-algorithms"
  fi
fi

# Add common flags
if [[ "$IGNORE_TESTS" == true ]]; then
  CMD="$CMD --ignore-tests"
fi

if [[ "$IGNORE_PANICS" == true ]]; then
  CMD="$CMD --ignore-panics"
fi

# Always exclude reference implementations and build artifacts
CMD="$CMD --exclude-files 'reference/*' --exclude-files 'target/*' --exclude-files 'benches/*' --exclude-files 'examples/*'"

# For specific packages, exclude all other crates to focus coverage calculation
if [[ "$CRATE" == "lib-q-core" ]]; then
  CMD="$CMD --exclude-files 'lib-q-ascon/*' --exclude-files 'lib-q-hash/*' --exclude-files 'lib-q-hpke/*' --exclude-files 'lib-q-intrinsics/*' --exclude-files 'lib-q-k12/*' --exclude-files 'lib-q-keccak/*' --exclude-files 'lib-q-kem/*' --exclude-files 'lib-q-ml-dsa/*' --exclude-files 'lib-q-ml-kem/*' --exclude-files 'lib-q-sha3/*' --exclude-files 'lib-q-sig/*' --exclude-files 'lib-q-aead/*' --exclude-files 'lib-q-platform/*' --exclude-files 'lib-q-utils/*' --exclude-files 'lib-q-zkp/*' --exclude-files 'lib-q-sponge/*'"
elif [[ "$CRATE" == "lib-q" ]]; then
  # For the root lib-q package, we need to be more selective about what to include
  # Only include the main lib.rs and core functionality, exclude most implementation details
  CMD="$CMD --exclude-files 'lib-q-ml-dsa/*' --exclude-files 'lib-q-ml-kem/*' --exclude-files 'lib-q-kem/*' --exclude-files 'lib-q-sig/*' --exclude-files 'lib-q-aead/*' --exclude-files 'lib-q-hpke/*' --exclude-files 'lib-q-zkp/*' --exclude-files 'lib-q-platform/*' --exclude-files 'lib-q-intrinsics/*' --exclude-files 'lib-q-utils/*'"
fi

# Add output format
CMD="$CMD --out $OUTPUT_FORMAT --output-dir $OUTPUT_DIR"

# Add line coverage threshold (removed as not supported by current tarpaulin version)
# We'll check the threshold manually after running

# Show the command
echo "Running: $CMD"

# Execute the command
eval "$CMD"
RESULT=$?

# Show the report if requested
if [[ "$SHOW_REPORT" == true && -f "$OUTPUT_DIR/index.html" ]]; then
  echo "Opening coverage report..."
  if command -v xdg-open &> /dev/null; then
    xdg-open "$OUTPUT_DIR/index.html"
  elif command -v open &> /dev/null; then
    open "$OUTPUT_DIR/index.html"
  else
    echo "Cannot open report automatically. Please open $OUTPUT_DIR/index.html manually."
  fi
fi

# Check if we met the threshold
COVERAGE_FILE="$OUTPUT_DIR/tarpaulin-report.html"
if [[ -f "$COVERAGE_FILE" ]]; then
  COVERAGE=$(grep -o '[0-9]\+\.[0-9]\+%' "$COVERAGE_FILE" | head -1 | tr -d '%')
  
  # Make sure we have a valid coverage number
  if [[ -n "$COVERAGE" && "$COVERAGE" =~ ^[0-9]+(\.[0-9]+)?$ ]]; then
    # Export the coverage for CI environments
    if [[ -n "$GITHUB_ENV" ]]; then
      echo "COVERAGE_PERCENT=$COVERAGE" >> $GITHUB_ENV
    fi
    
    if (( $(echo "$COVERAGE < $LINE_THRESHOLD" | bc -l) )); then
      echo -e "\e[31m❌ Coverage is $COVERAGE%, which is below the $LINE_THRESHOLD% threshold.\e[0m"
      exit 1
    else
      echo -e "\e[32m✅ Coverage is $COVERAGE%, which meets or exceeds the $LINE_THRESHOLD% threshold.\e[0m"
    fi
  else
    echo -e "\e[31m❌ Could not determine coverage percentage.\e[0m"
    exit 1
  fi
else
  echo -e "\e[31m❌ Coverage report file not found at $COVERAGE_FILE\e[0m"
  exit 1
fi

exit $RESULT
