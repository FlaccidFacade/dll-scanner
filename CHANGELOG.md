# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.5.0] - 2025-01-XX

### Added
- Enhanced Microsoft DLL version extraction with VarFileInfo translation support
- Support for language-specific string tables in Microsoft system DLLs
- Automatic enumeration of available translations from VarFileInfo\Translation entries
- Robust fallback mechanism for third-party DLLs without translation information
- Comprehensive test coverage for Microsoft DLL version extraction scenarios

### Changed
- Improved version information extraction for Microsoft-signed DLLs (kernel32.dll, ntdll.dll, etc.)
- Enhanced metadata extraction now properly handles translation keys (e.g., "040904b0" for US English/Unicode)
- Better error handling for malformed or missing version resources

### Fixed
- Microsoft DLL version extraction now correctly reads FileVersion, ProductVersion, CompanyName, FileDescription, OriginalFilename from translated string tables
- Type annotations added for all new helper methods to satisfy mypy requirements

## [0.3.0] - 2025-01-XX

### Added
- Version information is fully extracted and included in CycloneDX SBOM exports
- Version data (file_version, product_version, legal_copyright) is included in component properties
- Version information is used in component version field and PURL attributes
- Enhanced SBOM export with comprehensive version metadata

### Changed
- Project version bumped to 0.3.0 for PyPI release

## [0.1.0] - 2024-01-XX

### Added
- Initial release of DLL Scanner
- **Core Features:**
  - Recursive directory scanning for DLL files
  - Comprehensive PE metadata extraction including:
    - Architecture and machine type detection
    - Version information (product, file, company)
    - Import/export table analysis
    - Security characteristics
    - Digital signature status
  - Static code analysis for dependency confirmation
  - Support for multiple programming languages (C/C++, C#, Python, Java, etc.)
  
- **Command Line Interface:**
  - `dll-scanner scan` - Scan directories for DLL files
  - `dll-scanner inspect` - Inspect single DLL files
  - `dll-scanner analyze` - Analyze source code dependencies
  - Rich formatted output with progress bars
  - JSON export functionality
  
- **Python API:**
  - `DLLScanner` class for directory scanning
  - `DLLMetadata` class for metadata representation
  - `DependencyAnalyzer` class for static code analysis
  - Parallel processing support
  - Comprehensive error handling
  
- **Development Infrastructure:**
  - GitHub Actions CI/CD pipeline
  - Automated testing with pytest
  - Code formatting with Black
  - Linting with flake8
  - Type checking with mypy
  - PyPI publishing automation
  
- **Documentation:**
  - Comprehensive README with usage examples
  - API documentation with docstrings
  - Contributing guidelines
  - Example scripts for common use cases

### Dependencies
- pefile >= 2023.2.7 (PE file parsing)
- click >= 8.0.0 (CLI framework)
- rich >= 13.0.0 (Rich console output)
- pathlib-mate >= 1.0.0 (Path utilities)

### Requirements
- Python 3.8+
- Compatible with Windows, Linux, and macOS

### Security
- Input validation for file paths
- Safe handling of PE file parsing errors
- No execution of analyzed code