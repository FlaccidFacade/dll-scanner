# Publishing Workflow Documentation

This document describes the automated publishing workflow for the dll-scanner package to PyPI.

## Overview

The `publish.yml` workflow automates the process of building and publishing the dll-scanner package to PyPI using OIDC trusted publishing. It replaces the manual publishing process and ensures consistent, secure releases.

## Workflow Details

- **File**: `.github/workflows/publish.yml`
- **Repository**: FlaccidFacade/dll-scanner
- **Package Name**: dll-scanner
- **Publisher**: GitHub Actions
- **Environment**: pypi / test-pypi

## Triggers

The workflow can be triggered in two ways:

1. **Automatic**: When a new release is published on GitHub (publishes to PyPI)
2. **Manual**: Using the workflow dispatch option with choice of environment (PyPI or Test PyPI)

## OIDC Trusted Publishing

The workflow uses OIDC (OpenID Connect) trusted publishing for enhanced security:

- **PyPI audience**: Uses `audience=pypi` for production PyPI
- **TestPyPI audience**: Uses `audience=testpypi` for Test PyPI
- **No long-lived tokens**: Eliminates the need for API token secrets
- **Automatic token minting**: Dynamically generates OIDC tokens for each publish

## Jobs

### test-pypi Job
- Runs when manually triggered with `test-pypi` environment
- Uses TestPyPI-specific OIDC audience (`testpypi`)
- **Version checking**: Automatically checks if the current version already exists on TestPyPI
- Skips upload if version already exists (prevents duplicate upload errors)
- Publishes to https://test.pypi.org/legacy/
- Uses `test-pypi` environment for protection

### pypi Job  
- Runs on releases or manual trigger with `pypi` environment
- Uses PyPI-specific OIDC audience (`pypi`)
- **Version checking**: Automatically checks if the current version already exists on PyPI
- Skips upload if version already exists (prevents duplicate upload errors)
- Publishes to production PyPI
- Uses `pypi` environment for protection

## Requirements

### OIDC Configuration

The workflow requires OIDC trusted publishing to be configured:

1. **PyPI Configuration**: Set up trusted publisher on PyPI for this repository
2. **TestPyPI Configuration**: Set up trusted publisher on TestPyPI for testing

### Environment Protection

The workflow uses GitHub environments which should be configured with:
- `pypi` environment for production releases
- `test-pypi` environment for testing
- Protection rules for production releases
- Required reviewers (if desired)

## Security Features

- Uses OIDC trusted publishing (no API tokens required)
- Runs in isolated environments 
- Validates package before publishing
- **Version checking**: Prevents duplicate uploads by checking if version already exists
- Uses official PyPA publishing action
- Proper audience configuration for each registry
- Environment-based access controls

## Usage

### Creating a Release

1. Create a new tag: `git tag v0.1.1`
2. Push the tag: `git push origin v0.1.1`
3. Create a release on GitHub using the tag
4. The workflow will automatically trigger and publish to PyPI

### Manual Publishing to TestPyPI

1. Go to the "Actions" tab in the repository
2. Select "Publish to PyPI" workflow
3. Click "Run workflow"
4. Choose `test-pypi` environment
5. Click "Run workflow"

### Manual Publishing to PyPI

1. Go to the "Actions" tab in the repository
2. Select "Publish to PyPI" workflow
3. Click "Run workflow"
4. Choose `pypi` environment
5. Click "Run workflow"

## Package Information

- **Name**: dll-scanner
- **Current Version**: 0.1.0
- **Description**: A Python tool to scan directories for DLL files and extract metadata
- **PyPI URL**: https://pypi.org/p/dll-scanner
- **TestPyPI URL**: https://test.pypi.org/p/dll-scanner