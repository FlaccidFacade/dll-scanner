# Automatic Semantic Versioning

DLL Scanner includes automated semantic versioning functionality that creates Git tags based on the project version defined in `pyproject.toml`.

## Overview

The project version is defined in two places that must be kept in sync:
- `pyproject.toml` - The authoritative source for the project version
- `src/dll_scanner/__init__.py` - The Python package version (must match pyproject.toml)

The automatic semantic versioning system:
1. Extracts the version from `pyproject.toml`
2. Verifies consistency with `__init__.py`
3. Creates a Git tag in the format `v{version}` (e.g., `v0.2.0`)
4. Pushes the tag to the remote repository

## GitHub Actions Workflow

The `.github/workflows/semantic-versioning.yml` workflow automatically creates semantic version tags:

### Triggers
- **Manual trigger**: Use the "Actions" tab to manually run the workflow
- **Automatic trigger**: Runs when `pyproject.toml` or `src/dll_scanner/__init__.py` are changed on the main branch

### Features
- **Version extraction**: Automatically reads version from `pyproject.toml`
- **Version consistency check**: Ensures `pyproject.toml` and `__init__.py` versions match
- **Duplicate prevention**: Skips tag creation if the tag already exists
- **Force option**: Manual runs can force tag creation even if it exists
- **Release notes**: Automatically generates basic release notes
- **Comprehensive logging**: Detailed step-by-step output

### Workflow Inputs (Manual Trigger)
- **force**: Force tag creation even if it already exists (default: false)

## CLI Command

You can also create version tags manually using the CLI:

```bash
# Create a semantic version tag
dll-scanner create-version-tag

# Preview what would be done
dll-scanner create-version-tag --dry-run

# Force creation even if tag exists
dll-scanner create-version-tag --force
```

### CLI Features
- **Dry run mode**: Preview actions without making changes
- **Version consistency check**: Validates version synchronization
- **Git integration**: Uses local Git configuration
- **Error handling**: Graceful handling of authentication and network issues

## Version Format

The system follows [Semantic Versioning](https://semver.org/) standards:

- **Format**: `MAJOR.MINOR.PATCH`
- **Examples**: `1.0.0`, `0.2.0`, `2.1.3`
- **Pre-release**: `1.0.0-beta`, `1.0.0-rc.1`
- **Build metadata**: `1.0.0+build.123`

Git tags are created with the `v` prefix: `v1.0.0`, `v0.2.0`, etc.

## Integration with Release Process

The semantic versioning system integrates with the existing release workflow:

1. **Version Update**: Update version in `pyproject.toml` and `__init__.py`
2. **Commit Changes**: Push changes to main branch
3. **Automatic Tagging**: Workflow creates the semantic version tag
4. **Release Creation**: Use the tag to create a GitHub release
5. **Package Publishing**: The `publish.yml` workflow publishes to PyPI

## Error Handling

The system includes comprehensive error handling:

- **Version mismatch**: Fails if `pyproject.toml` and `__init__.py` versions don't match
- **Duplicate tags**: Skips creation if tag already exists (unless forced)
- **Authentication errors**: Gracefully handles Git authentication issues
- **Network issues**: Provides clear error messages for push failures

## Best Practices

1. **Always update both files**: When changing the version, update both `pyproject.toml` and `__init__.py`
2. **Use the dry-run option**: Test CLI commands with `--dry-run` first
3. **Follow semantic versioning**: Use appropriate version increments for changes
4. **Review tags before releases**: Verify tags are created correctly before publishing
5. **Use force sparingly**: Only use `--force` when you need to recreate an existing tag

## Examples

### Version Update Workflow
```bash
# 1. Update version in both files
# Edit pyproject.toml: version = "0.3.0"
# Edit src/dll_scanner/__init__.py: __version__ = "0.3.0"

# 2. Commit and push changes
git add pyproject.toml src/dll_scanner/__init__.py
git commit -m "Bump version to 0.3.0"
git push origin main

# 3. The workflow will automatically create tag v0.3.0

# 4. Or create manually
dll-scanner create-version-tag
```

### Manual Tag Creation
```bash
# Check what would happen
dll-scanner create-version-tag --dry-run

# Create the tag
dll-scanner create-version-tag

# Force recreation of existing tag
dll-scanner create-version-tag --force
```

## Troubleshooting

### Common Issues

**Version Mismatch Error**:
```
ERROR: Version mismatch between pyproject.toml (0.3.0) and __init__.py (0.2.0)
```
Solution: Update both files to have the same version.

**Tag Already Exists**:
```
Tag v0.2.0 already exists. Use --force to recreate it.
```
Solution: Use `--force` flag if you need to recreate the tag.

**Authentication Failed**:
```
Tag created locally but failed to push to remote
```
Solution: The tag was created locally. Push manually or check Git credentials.

### Verification Commands

```bash
# Check current version
python -c "import tomllib; print(tomllib.load(open('pyproject.toml', 'rb'))['project']['version'])"

# Check version consistency
dll-scanner create-version-tag --dry-run

# List existing tags
git tag --list

# Show tag details
git show v0.2.0
```