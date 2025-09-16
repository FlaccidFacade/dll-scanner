#!/bin/bash
# Example usage of DLL Scanner

# Creating a simple test with fake DLL file
mkdir -p /tmp/test_with_dll /tmp/test_source

# Create a fake DLL file for testing (note: real usage requires actual DLL files)
echo "fake dll content" > /tmp/test_with_dll/test.dll

# Create sample source code files
cat > /tmp/test_source/main.cpp << 'EOF'
#include <windows.h>

int main() {
    HMODULE handle = LoadLibrary("test.dll");
    if (handle) {
        // Use the DLL
        FreeLibrary(handle);
    }
    return 0;
}
EOF

cat > /tmp/test_source/program.cs << 'EOF'
using System.Runtime.InteropServices;

class Program {
    [DllImport("test.dll")]
    static extern void SomeFunction();
    
    static void Main() {
        SomeFunction();
    }
}
EOF

# Test the scanner
dll-scanner scan /tmp/test_with_dll

# Test dependency analysis (will work but won't extract much without real DLL)
dll-scanner scan /tmp/test_with_dll --analyze-dependencies --source-dir /tmp/test_source