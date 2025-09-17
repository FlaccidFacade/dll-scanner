# Publishing Workflow Documentation

This document describes the automated publishing workflow for the dll-scanner package to PyPI.

## Overview

The `publish.yml` workflow automates the process of building and publishing the dll-scanner package to PyPI. It replaces the manual publishing process and ensures consistent, secure releases.

## Workflow Details

- **File**: `.github/workflows/publish.yml`
- **Repository**: FlaccidFacade/dll-scanner
- **Package Name**: dll-scanner
- **Publisher**: GitHub Actions
- **Environment**: pypi

## Triggers

The workflow can be triggered in two ways:

1. **Automatic**: When a new release is published on GitHub
2. **Manual**: Using the workflow dispatch option with choice of environment (PyPI or Test PyPI)

## Requirements

### Secrets Required

The workflow requires the following secrets to be configured in the repository:

- `PYPI_API_TOKEN`: API token for publishing to PyPI
- `TEST_PYPI_API_TOKEN`: API token for publishing to Test PyPI (optional, for testing)

### Environment Protection

The workflow uses the `pypi` environment which should be configured with:
- Protection rules for production releases
- Required reviewers (if desired)
- Environment-specific secrets

## Security Features

- Uses trusted publishing with OpenID Connect (OIDC)
- Runs in an isolated environment
- Validates package before publishing
- Uses official PyPA publishing action

## Usage

### Creating a Release

1. Create a new tag: `git tag v0.1.1`
2. Push the tag: `git push origin v0.1.1`
3. Create a release on GitHub using the tag
4. The workflow will automatically trigger and publish to PyPI

### Manual Publishing

1. Go to the "Actions" tab in the repository
2. Select "Publish to PyPI" workflow
3. Click "Run workflow"
4. Choose the environment (pypi or test-pypi)
5. Click "Run workflow"

## Package Information

- **Name**: dll-scanner
- **Current Version**: 0.1.0
- **Description**: A Python tool to scan directories for DLL files and extract metadata
- **PyPI URL**: https://pypi.org/p/dll-scanner