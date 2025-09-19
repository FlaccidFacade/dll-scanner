# Contributing to DLL Scanner

Thank you for your interest in contributing to DLL Scanner! This document provides guidelines for contributing to the project.

## Development Setup

1. **Clone the repository:**
   ```bash
   git clone https://github.com/FlaccidFacade/dll-scanner.git
   cd dll-scanner
   ```

2. **Create a virtual environment:**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install in development mode:**
   ```bash
   pip install -e ".[dev]"
   ```

4. **Install pre-commit hooks:**
   ```bash
   pip install pre-commit
   pre-commit install
   ```

   This will automatically run Black and other checks before each commit.

## Code Quality

This project maintains high code quality standards:

- **Formatting:** Code is formatted with [Black](https://black.readthedocs.io/)
- **Linting:** Code is linted with [flake8](https://flake8.pycqa.org/)
- **Type Checking:** Type hints are checked with [mypy](https://mypy.readthedocs.io/)
- **Testing:** Tests are written with [pytest](https://pytest.org/)

## GitHub Copilot Configuration

This project is configured to use GitHub Copilot with the `#codebase` semantic search tool by default. This ensures consistent code assistance throughout the project:

- The configuration is stored in `.github/copilot.yml`
- The CI pipeline validates this configuration
- When using Copilot, always reference the existing codebase for patterns and styles
- Customized Copilot instructions are available in `.github/copilot-instructions.md`

This configuration helps maintain code consistency and leverages project-specific knowledge during development.

### Running Quality Checks

**⚠️ MANDATORY: Always format before committing:**
```bash
# Format code (REQUIRED before every commit)
black src/ tests/
```

```bash
# Run all pre-commit hooks on all files
pre-commit run --all-files

# Run a specific hook
pre-commit run black --all-files

# Manual quality checks
# Format code (MANDATORY)
black src/ tests/

# Check formatting
black --check src/ tests/

# Lint code
flake8 src/ tests/ --max-line-length=88 --extend-ignore=E203,W503

# Type checking
mypy src/dll_scanner --ignore-missing-imports

# Run tests
pytest tests/ -v --cov=dll_scanner
```

> Note: If you've installed the pre-commit hooks, Black will automatically run before each commit.

## Testing

- Write tests for all new functionality
- Maintain or improve test coverage
- Use descriptive test names
- Mock external dependencies in tests

Example test structure:
```python
def test_function_name_should_do_something():
    # Arrange
    input_data = create_test_data()
    
    # Act
    result = function_under_test(input_data)
    
    # Assert
    assert result.expected_property == expected_value
```

## Pull Request Process

1. **Fork the repository** and create a feature branch
2. **Make your changes** following the coding standards
3. **Add tests** for new functionality
4. **Run all quality checks** and ensure they pass
5. **Update documentation** if needed
6. **Create a pull request** with a clear description

### Pull Request Checklist

- [ ] Tests pass locally
- [ ] Pre-commit hooks pass (`pre-commit run --all-files`)
- [ ] Code is formatted with Black
- [ ] Code passes flake8 linting
- [ ] Type hints are added and mypy passes
- [ ] Documentation is updated (if applicable)
- [ ] CHANGELOG.md is updated (if applicable)

## Coding Guidelines

### Python Style

- Follow [PEP 8](https://pep8.org/) with line length of 88 characters
- Use type hints for all function signatures
- Use descriptive variable and function names
- Add docstrings for all public functions and classes

### Documentation

- Use Google-style docstrings
- Include examples in docstrings when helpful
- Keep README.md up to date
- Document breaking changes

Example docstring:
```python
def extract_metadata(self, dll_path: Path) -> DLLMetadata:
    """
    Extract comprehensive metadata from a DLL file.
    
    Args:
        dll_path: Path to the DLL file to analyze
        
    Returns:
        DLLMetadata object containing extracted information
        
    Raises:
        FileNotFoundError: If the DLL file doesn't exist
        ValueError: If the file is not a valid DLL
        
    Example:
        >>> extractor = DLLMetadataExtractor()
        >>> metadata = extractor.extract_metadata(Path("example.dll"))
        >>> print(metadata.file_name)
        example.dll
    """
```

## Reporting Issues

When reporting issues, please include:

1. **Environment information:** OS, Python version, package version
2. **Steps to reproduce:** Clear, minimal example
3. **Expected behavior:** What should happen
4. **Actual behavior:** What actually happens
5. **Error messages:** Full traceback if applicable

## Feature Requests

For feature requests, please:

1. **Check existing issues** to avoid duplicates
2. **Describe the use case** clearly
3. **Provide examples** of how the feature would be used
4. **Consider implementation** if you have ideas

## Security

If you discover a security vulnerability, please email the maintainers directly rather than opening a public issue.

## License

By contributing to this project, you agree that your contributions will be licensed under the MIT License.