#!/usr/bin/env bash
OUTPUT_FORMAT="Html,Xml"
IFS=',' read -ra FORMAT_PARTS <<< "$OUTPUT_FORMAT"
echo "count=${#FORMAT_PARTS[@]}"
printf 'part=%s\n' "${FORMAT_PARTS[@]}"
