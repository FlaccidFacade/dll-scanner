#!/bin/bash
# Format Check Script for DLL Scanner
# This script ensures code is properly formatted before commits

set -e

echo "🔍 Checking code formatting with Black..."

# Check if black is installed
if ! command -v black &> /dev/null; then
    echo "❌ Black is not installed. Install with: pip install black"
    exit 1
fi

# Check formatting
if black --check src/ tests/; then
    echo "✅ All code is properly formatted!"
    exit 0
else
    echo ""
    echo "❌ Code formatting issues detected!"
    echo ""
    echo "🔧 To fix formatting issues, run:"
    echo "   black src/ tests/"
    echo ""
    echo "💡 Tip: Install pre-commit hooks to automatically format code:"
    echo "   pre-commit install"
    exit 1
fi