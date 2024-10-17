#!/bin/bash

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if file argument is provided
if [ $# -eq 0 ]; then
    echo -e "${RED}Error: No JSON file specified${NC}"
    echo "Usage: $0 <path-to-json-file>"
    exit 1
fi

file="$1"
errors=0
warnings=0

# Check if file exists and is readable
if [[ ! -r "$file" ]]; then
    echo -e "${RED}Error: Cannot read file $file${NC}"
    exit 1
fi

echo "Validating $file..."

# Validate JSON syntax
if ! jq empty "$file" 2>/dev/null; then
    echo -e "${RED}Error: Invalid JSON syntax in $file${NC}"
    exit 1
fi

# Validate structure and required fields
jq -r '.vulnerabilities[] | 
    select(
        (.id | type != "string") or
        (.nvd_link | type != "string") or
        (.description | type != "string") or
        (.known_exploited | type != "boolean") or
        (.dependencies | type != "object") or
        (.resources | type != "object") or
        (.metadata | type != "object") or
        (.dependencies.features | type != "array") or
        (.dependencies.conditions | type != "array") or
        (.dependencies.configuration | type != "array") or
        (.dependencies.notes | type != "string") or
        (.metadata.date_added | type != "string") or
        (.metadata.last_updated | type != "string") or
        (.metadata.contributor | type != "string")
    ) | 
    "Error: Invalid structure or missing required field in \(.id // "UNKNOWN CVE")"
' "$file" | while read -r line; do
    echo -e "${RED}$line${NC}"
    ((errors++))
done

# Check for empty dependencies
jq -r '.vulnerabilities[] | 
    select((.dependencies.features | length == 0) and 
           (.dependencies.conditions | length == 0) and 
           (.dependencies.configuration | length == 0)) |
    "Warning: No dependencies specified for \(.id)"
' "$file" | while read -r line; do
    echo -e "${YELLOW}$line${NC}"
    ((warnings++))
done

# Check for empty notes
jq -r '.vulnerabilities[] | 
    select(.dependencies.notes == "") | 
    "Warning: Empty notes for \(.id)"
' "$file" | while read -r line; do
    echo -e "${YELLOW}$line${NC}"
    ((warnings++))
done

echo "----------------------------------------"
if [[ $errors -eq 0 ]]; then
    echo -e "${GREEN}✓ Validation passed for $file${NC}"
    if [[ $warnings -gt 0 ]]; then
        echo -e "${YELLOW}⚠ Found $warnings warning(s)${NC}"
    fi
    exit 0
else
    echo -e "${RED}✗ Found $errors error(s)${NC}"
    exit 1
fi
