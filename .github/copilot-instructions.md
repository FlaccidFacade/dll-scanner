# DLL Scanner - GitHub Copilot Instructions

Always reference these instructions first and fallback to search or bash commands only when you encounter unexpected information that does not match the info here.

DLL Scanner is a powerful Python tool for scanning directories to find DLL files, extracting comprehensive metadata, and performing static code analysis to confirm dependencies. The tool supports Windows DLL scanning functionality but maintains cross-platform compatibility for development and testing.

## Working Effectively

### Bootstrap, Build, and Test the Repository

**NEVER CANCEL any of these commands - builds and tests may take several minutes:**

- Set up development environment: `pip install -e ".[dev]"` -- takes 1-2 minutes to install all dependencies
- Run tests: `pytest tests/ -v` -- takes ~5 seconds. NEVER CANCEL - set timeout to 30+ seconds for safety
- Run tests with coverage: `pytest tests/ -v --cov=dll_scanner --cov-report=term-missing` -- takes ~5 seconds
- Format code: `black src/ tests/` -- takes <1 second
- Check formatting: `black --check src/ tests/` -- takes <1 second 
- Lint code: `flake8 src/ tests/ --max-line-length=88 --extend-ignore=E203,W503` -- takes <1 second
- Type checking: `mypy src/dll_scanner --ignore-missing-imports` -- takes ~4 seconds
- Build package: `python -m build` -- **WARNING: May fail due to network timeouts in CI environments. This is normal.**

### Run the Application

**CLI Commands:**
- Help: `dll-scanner --help`
- Version: `dll-scanner --version`
- Scan directory: `dll-scanner scan /path/to/directory`
- Scan with output: `dll-scanner scan /path/to/directory --output results.json`
- Scan with CycloneDX SBOM: `dll-scanner scan /path/to/directory --cyclonedx --output sbom.json`
- Inspect single DLL: `dll-scanner inspect path/to/file.dll`
- Inspect with output: `dll-scanner inspect path/to/file.dll --output metadata.json`
- Analyze dependencies: `dll-scanner scan /path/to/dlls --analyze-dependencies --source-dir /path/to/source`
- Standalone dependency analysis: `dll-scanner analyze /path/to/source library1.dll library2.dll`
- Command help: `dll-scanner COMMAND --help` (for any command)

**Python API:**
```python
from dll_scanner import DLLScanner, DependencyAnalyzer
from pathlib import Path

# Basic scanning
scanner = DLLScanner()
result = scanner.scan_directory(Path("/path/to/directory"))

# Dependency analysis  
analyzer = DependencyAnalyzer()
analysis_results = analyzer.analyze_dependencies(
    Path("/path/to/source"), 
    ["library.dll"]
)
```

## Validation

**ALWAYS run these quality checks before committing:**
- `black src/ tests/` -- format code
- `flake8 src/ tests/ --max-line-length=88 --extend-ignore=E203,W503` -- lint code
- `mypy src/dll_scanner --ignore-missing-imports` -- type checking
- `pytest tests/ -v --cov=dll_scanner` -- run tests with coverage

**Manual Testing Scenarios:**
After making changes, ALWAYS test at least one complete end-to-end scenario:

1. **Basic Scanning Test:**
   ```bash
   mkdir -p /tmp/test_dll_dir
   echo "fake dll content" > /tmp/test_dll_dir/test.dll
   dll-scanner scan /tmp/test_dll_dir
   # Expected: Shows table with 1 DLL file found, architecture "Unknown"
   ```

2. **Dependency Analysis Test:**
   ```bash
   mkdir -p /tmp/test_source
   cat > /tmp/test_source/main.cpp << 'EOF'
   #include <windows.h>
   int main() {
       HMODULE handle = LoadLibrary("test.dll");
       return 0;
   }
   EOF
   dll-scanner scan /tmp/test_dll_dir --analyze-dependencies --source-dir /tmp/test_source
   # Expected: Shows dependency analysis with 1 confirmed dependency found
   ```

3. **JSON Output Test:**
   ```bash
   dll-scanner scan /tmp/test_dll_dir --output /tmp/results.json
   cat /tmp/results.json  # Verify JSON is valid and contains expected fields
   # Expected: Valid JSON with scan_path, total_dlls_found, dll_files array
   ```

4. **CycloneDX SBOM Test:**
   ```bash
   dll-scanner scan /tmp/test_dll_dir --cyclonedx --output /tmp/sbom.json
   head -20 /tmp/sbom.json  # Verify SBOM format
   # Expected: Valid CycloneDX JSON with components and metadata
   ```

5. **Inspect Command Test:**
   ```bash
   dll-scanner inspect /tmp/test_dll_dir/test.dll
   # Expected: Shows detailed metadata panel for the DLL file
   ```

6. **Python API Test:**
   ```bash
   python3 -c "
   from dll_scanner import DLLScanner, DependencyAnalyzer
   from pathlib import Path
   scanner = DLLScanner()
   result = scanner.scan_directory(Path('/tmp/test_dll_dir'))
   print(f'Found {len(result.dll_files)} DLL files')
   "
   # Expected: Prints "Found 1 DLL files"
   ```

## Common Tasks

### Repository Structure
```
dll-scanner/
├── .github/                 # GitHub workflows and configuration
│   └── workflows/
│       ├── ci.yml          # CI/CD pipeline (tests, linting, building)
│       └── publish.yml     # PyPI publishing workflow
├── src/dll_scanner/        # Main source code
│   ├── __init__.py         # Package initialization and exports
│   ├── cli.py              # Command-line interface implementation
│   ├── scanner.py          # Core DLL scanning functionality
│   ├── metadata.py         # DLL metadata extraction and representation
│   ├── analyzer.py         # Dependency analysis and static code scanning
│   └── cyclonedx_exporter.py # CycloneDX SBOM export functionality
├── tests/                  # Test suite
│   ├── __init__.py
│   └── test_dll_scanner.py # Comprehensive test coverage
├── examples/               # Usage examples and test scripts
│   └── test_usage.sh       # Example script demonstrating CLI usage
├── pyproject.toml          # Project configuration, dependencies, build settings
├── README.md               # User documentation and usage examples
├── CONTRIBUTING.md         # Developer guidelines and setup instructions
├── CHANGELOG.md            # Version history and release notes
└── LICENSE                 # MIT license
```

### Key Features and Commands
- **Directory Scanning:** Recursively scan directories for DLL files
- **Metadata Extraction:** Extract PE metadata including architecture, version info, imports/exports
- **Dependency Analysis:** Static code analysis to confirm DLL usage in source code
- **Multiple Output Formats:** JSON output and CycloneDX SBOM format
- **Cross-Platform Development:** Tests run on Windows, Ubuntu, and Debian
- **Rich CLI Interface:** Progress bars, tables, and colored output using Rich library

### Dependencies and Requirements
- **Python 3.9+** (supports 3.9, 3.10, 3.11, 3.12)
- **Runtime:** pefile, click, rich, pathlib-mate, cyclonedx-bom
- **Development:** pytest, pytest-cov, black, flake8, mypy, twine, build
- **Platform Notes:** Primary DLL functionality requires Windows, but development and testing work cross-platform

### CI/CD Pipeline
The repository uses GitHub Actions with the following workflows:
- **ci.yml:** Runs tests on multiple Python versions and platforms (Windows, Ubuntu, Debian)
- **publish.yml:** Automated PyPI publishing using OIDC trusted publishing
- **Quality Checks:** Formatting (Black), linting (flake8), type checking (mypy), testing (pytest)
- **Security:** Bandit security analysis and Safety dependency checking

### Common Issues and Solutions
- **Build fails with network timeouts (HTTPSConnectionPool timeout):** This is common in CI environments due to PyPI network issues. The build will work locally or when network is stable. Do not rely on `python -m build` for validation - use the installed package instead.
- **"pefile library is required" errors:** Install with `pip install pefile` (should be automatic with dev install)
- **Permission denied errors:** Run as administrator or ensure read permissions for target directory
- **ImportError with optional dependencies:** Install dev dependencies with `pip install -e ".[dev]"`
- **Analysis errors with fake DLL files:** This is expected - fake DLL files will show "PE analysis failed" but the tool will still process them
- **flake8 linting errors:** The codebase has some existing linting issues in cli.py and cyclonedx_exporter.py - these are known issues and do not prevent functionality

### Performance Tips
- Use `--max-workers` to control memory usage vs. speed trade-off
- Disable `--parallel` for very large numbers of small files
- Use `--no-recursive` when only scanning the target directory (not subdirectories)

### Testing Notes
- Tests are designed to work without real DLL files using mocking
- One integration test is skipped that requires actual DLL files
- Full test suite runs in ~5 seconds
- Test coverage is maintained at high levels across all modules