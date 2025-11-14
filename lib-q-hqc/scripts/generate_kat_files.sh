#!/bin/bash

# Script to generate KAT files from HQC reference implementation
# This script compiles and runs the KAT generator from the C reference

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}Generating HQC KAT files from reference implementation...${NC}"

# Base directory for reference implementation
REF_DIR="../../reference/hqc-avx2/Reference_Implementation 2"
KAT_DIR="tests/kat_data"

# Create KAT data directory
mkdir -p "$KAT_DIR"

# Function to generate KAT files for a parameter set
generate_kat_for_params() {
    local params=$1
    local param_dir="$REF_DIR/$params"
    
    echo -e "${YELLOW}Generating KAT files for $params...${NC}"
    
    if [ ! -d "$param_dir" ]; then
        echo -e "${RED}Error: Parameter directory $param_dir not found${NC}"
        return 1
    fi
    
    cd "$param_dir"
    
    # Clean previous builds
    make clean 2>/dev/null || true
    
    # Compile KAT generator
    echo "Compiling KAT generator for $params..."
    if ! make "${params}-kat" 2>/dev/null; then
        echo -e "${RED}Warning: Could not compile KAT generator for $params${NC}"
        echo "This might be due to missing dependencies (NTL, gf2x, OpenSSL)"
        echo "Skipping $params..."
        cd - > /dev/null
        return 0
    fi
    
    # Run KAT generator
    echo "Running KAT generator for $params..."
    if [ -f "bin/${params}-kat" ]; then
        ./bin/${params}-kat
        echo -e "${GREEN}KAT files generated for $params${NC}"
    else
        echo -e "${RED}Error: KAT generator binary not found for $params${NC}"
        cd - > /dev/null
        return 1
    fi
    
    # Copy KAT files to our test directory
    if [ -f "PQCkemKAT_*.req" ] && [ -f "PQCkemKAT_*.rsp" ]; then
        cp PQCkemKAT_*.req "../../../lib-q-hqc/$KAT_DIR/"
        cp PQCkemKAT_*.rsp "../../../lib-q-hqc/$KAT_DIR/"
        echo -e "${GREEN}KAT files copied for $params${NC}"
    else
        echo -e "${RED}Warning: KAT files not found for $params${NC}"
    fi
    
    cd - > /dev/null
}

# Generate KAT files for all parameter sets
generate_kat_for_params "hqc-128-1"
generate_kat_for_params "hqc-192-1"
generate_kat_for_params "hqc-192-2"
generate_kat_for_params "hqc-256-1"
generate_kat_for_params "hqc-256-2"
generate_kat_for_params "hqc-256-3"

echo -e "${GREEN}KAT file generation complete!${NC}"
echo "KAT files are available in: $KAT_DIR"

# List generated files
if [ -d "$KAT_DIR" ]; then
    echo -e "${YELLOW}Generated KAT files:${NC}"
    ls -la "$KAT_DIR"
fi
