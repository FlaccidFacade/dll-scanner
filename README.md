# DLL Scanner

A powerful Python tool for scanning directories to find DLL files, extracting comprehensive metadata, and performing static code analysis to confirm dependencies.

https://app.codecov.io/gh/FlaccidFacade/dll-scanner

## Features

- 🔍 **Recursive Directory Scanning**: Scan entire directory trees for DLL files
- 📊 **Comprehensive Metadata Extraction**: Extract detailed information from PE headers including:
  - Architecture and machine type
  - Version information (product, file, company)
  - Import/export tables
  - Security characteristics
  - Digital signature status
- 🧠 **Static Code Analysis**: Analyze source code to confirm DLL dependencies with:
  - Support for multiple programming languages (C/C++, C#, Python, Java, etc.)
  - Pattern matching for LoadLibrary calls, DllImport attributes, and function references
  - Confidence scoring for dependency matches
- ⚡ **Parallel Processing**: Multi-threaded scanning for improved performance
- 🎨 **Rich CLI Interface**: Beautiful command-line interface with progress bars and formatted output
- 📄 **Multiple Output Formats**: JSON export and CycloneDX SBOM format for integration with other tools
- 🔒 **Security & Compliance**: CycloneDX SBOM generation for supply chain security analysis
- 🐍 **Python API**: Use as a library in your own projects

## Installation

### From PyPI (when available)

```bash
pip install dll-scanner
```

### From Source

```bash
git clone https://github.com/FlaccidFacade/dll-scanner.git
cd dll-scanner
pip install -e .
```

## Quick Start

### Scan a Directory

```bash
# Basic directory scan
dll-scanner scan /path/to/project

# Recursive scan with dependency analysis
dll-scanner scan /path/to/project --analyze-dependencies --source-dir /path/to/source

# Save results to JSON
dll-scanner scan /path/to/project --output results.json
```

### Inspect a Single DLL

```bash
dll-scanner inspect path/to/file.dll
```

### Analyze Dependencies

```bash
dll-scanner analyze /path/to/source file1.dll file2.dll --output analysis.json
```

## Usage Examples

### Command Line Interface

#### Basic Directory Scan

```bash
# Scan current directory recursively
dll-scanner scan .

# Scan specific directory without recursion
dll-scanner scan /path/to/dlls --no-recursive

# Use custom number of worker threads
dll-scanner scan /path/to/dlls --max-workers 8
```

#### Dependency Analysis

```bash
# Analyze DLL dependencies in source code
dll-scanner scan /path/to/project \
    --analyze-dependencies \
    --source-dir /path/to/source \
    --output full_analysis.json
```

#### CycloneDX SBOM Export

```bash
# Export scan results as CycloneDX SBOM
dll-scanner scan /path/to/project \
    --cyclonedx \
    --project-name "MyProject" \
    --project-version "2.1.0" \
    --output project_sbom.json

# Combine with dependency analysis
dll-scanner scan /path/to/project \
    --analyze-dependencies \
    --source-dir /path/to/source \
    --cyclonedx \
    --project-name "MyProject" \
    --project-version "2.1.0" \
    --output project_sbom.json

# Export single DLL as CycloneDX SBOM
dll-scanner inspect mylib.dll --cyclonedx --output mylib_sbom.json
```
```

#### Single File Inspection

```bash
# Inspect a specific DLL file
dll-scanner inspect kernel32.dll --output kernel32_metadata.json
```

### Python API

```python
from dll_scanner import DLLScanner, DependencyAnalyzer
from pathlib import Path

# Initialize scanner
scanner = DLLScanner(max_workers=4)

# Scan directory
result = scanner.scan_directory(Path("/path/to/project"))

print(f"Found {result.total_dlls_found} DLL files")
for dll in result.dll_files:
    print(f"- {dll.file_name}: {dll.architecture}, {dll.company_name}")

# Analyze dependencies
analyzer = DependencyAnalyzer()
for dll_metadata in result.dll_files:
    analysis = analyzer.analyze_dll_dependencies(
        dll_metadata, 
        Path("/path/to/source")
    )
    print(f"{dll_metadata.file_name}: {len(analysis.confirmed_dependencies)} confirmed")
```

#### CycloneDX SBOM Export

```python
from dll_scanner import DLLScanner, CycloneDXExporter
from pathlib import Path

# Scan directory
scanner = DLLScanner()
result = scanner.scan_directory(Path("/path/to/project"))

# Export to CycloneDX SBOM
exporter = CycloneDXExporter()
cyclonedx_json = exporter.export_to_json(
    result,
    project_name="MyProject",
    project_version="1.0.0",
    output_file=Path("project_sbom.json")
)

# Get SBOM summary
bom = exporter.export_to_cyclonedx(result, project_name="MyProject")
summary = exporter.get_component_summary(bom)
print(f"SBOM contains {summary['total_components']} components")
```

### Advanced Usage

#### Custom Progress Callback

```python
from rich.console import Console

console = Console()

def progress_callback(message):
    console.print(f"[dim]{message}[/dim]")

scanner = DLLScanner(progress_callback=progress_callback)
result = scanner.scan_directory(Path("/path/to/project"))
```

#### Filtering and Analysis

```python
# Get summary statistics
stats = scanner.get_summary_stats(result)
print(f"Architectures found: {stats['architectures']}")
print(f"Most common imports: {stats['most_common_imports']}")

# Filter DLLs by criteria
x64_dlls = [dll for dll in result.dll_files if dll.architecture == 'x64']
unsigned_dlls = [dll for dll in result.dll_files if not dll.is_signed]
```

## Output Format

### Scan Results (JSON)

```json
{
  "scan_path": "/path/to/project",
  "recursive": true,
  "total_files_scanned": 42,
  "total_dlls_found": 15,
  "scan_duration_seconds": 2.34,
  "errors": [],
  "dll_files": [
    {
      "file_name": "example.dll",
      "file_path": "/path/to/example.dll",
      "file_size": 65536,
      "architecture": "x64",
      "machine_type": "amd64",
      "company_name": "Microsoft Corporation",
      "product_version": "10.0.19041.1",
      "imported_dlls": ["kernel32.dll", "user32.dll"],
      "exported_functions": ["ExampleFunction", "AnotherFunction"],
      "is_signed": true
    }
  ]
}
```

### Dependency Analysis

```json
{
  "summary": {
    "total_dlls_analyzed": 15,
    "dlls_with_confirmed_usage": 12,
    "dlls_potentially_unused": 3,
    "total_confirmed_dependencies": 28,
    "total_potential_dependencies": 5
  },
  "confirmed_dlls": [
    {
      "dll_name": "custom.dll",
      "confirmed_references": 3,
      "analysis_confidence": 0.95
    }
  ],
  "potentially_unused_dlls": [
    {
      "dll_name": "unused.dll",
      "file_size": 32768,
      "company": "Unknown"
    }
  ]
}
```

## Supported Languages for Dependency Analysis

The static code analyzer can detect DLL dependencies in the following languages:

- **C/C++**: LoadLibrary calls, #pragma lib comments, function references
- **C#**: DllImport attributes, P/Invoke declarations
- **Python**: ctypes library usage, LoadLibrary calls
- **Java**: JNI library loading
- **JavaScript/TypeScript**: Node.js native module references
- **Go**: CGO library references
- **Rust**: FFI declarations
- **PHP**: dl() function calls
- **Ruby**: DL library usage

## Requirements

### Runtime Requirements
- **Windows operating system** (for DLL scanning functionality)
- Python 3.9+
- pefile >= 2023.2.7
- click >= 8.0.0
- rich >= 13.0.0
- pathlib-mate >= 1.0.0
- cyclonedx-bom >= 4.0.0 (for CycloneDX SBOM export)

### Development and Testing
- **Cross-platform support**: Tests run on Windows, Ubuntu, and Debian
- While the primary functionality requires Windows DLLs, the codebase is designed to be maintainable across platforms
- Static code analysis features work on any platform

## Development

### Setting up Development Environment

```bash
git clone https://github.com/FlaccidFacade/dll-scanner.git
cd dll-scanner

# Install in development mode with dev dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Run tests with coverage
pytest --cov=dll_scanner

# Format code
black src/ tests/

# Type checking
mypy src/

# Linting
flake8 src/
```

### Cross-Platform Testing

This project uses GitHub Actions to test on multiple platforms:
- **Windows**: Full functionality testing with actual DLL files
- **Ubuntu**: Core functionality and code quality testing
- **Debian**: Additional Linux distribution testing using Docker containers

While the primary DLL scanning functionality requires Windows, the test suite ensures code quality and maintainability across platforms.

### Building and Publishing

#### Automated Publishing (Recommended)

The project uses GitHub Actions for automated publishing to PyPI with OIDC trusted publishing:

- **Automatic**: Publishing happens automatically when a new release is created on GitHub
- **Manual**: You can manually trigger publishing using the "Publish to PyPI" workflow in the Actions tab

The workflow file `.github/workflows/publish.yml` handles:
- Building the package
- Running quality checks
- OIDC token minting for secure authentication
- Publishing to PyPI or Test PyPI with proper audience configuration
- Environment protection with `pypi` and `test-pypi` environments

**Security**: Uses OIDC trusted publishing - no API tokens required!

#### Manual Publishing

```bash
# Build package
python -m build

# Check package quality
twine check dist/*

# Upload to PyPI
twine upload dist/*
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Troubleshooting

### Common Issues

**"pefile library is required"**
```bash
pip install pefile
```

**Permission denied errors**
- Run as administrator or ensure you have read permissions for the target directory

**ImportError with optional dependencies**
```bash
pip install dll-scanner[dev]
```

### Performance Tips

- Use `--max-workers` to control memory usage vs. speed
- Disable `--parallel` for very large numbers of small files
- Use `--no-recursive` when you only need files in the target directory

## Changelog

### v0.1.0
- Initial release
- Directory scanning functionality
- PE metadata extraction
- Static code dependency analysis
- CLI interface with rich formatting
- Python API
