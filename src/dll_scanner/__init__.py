"""
DLL Scanner - A Python tool to scan directories for DLL files and extract metadata.

This package provides functionality to:
- Scan directories recursively for DLL files
- Extract metadata from DLL files using PE analysis
- Perform static code analysis to confirm dependencies
- Generate comprehensive reports
"""

__version__ = "0.1.0"
__author__ = "DLL Scanner Contributors"

from .scanner import DLLScanner
from .metadata import DLLMetadata
from .analyzer import DependencyAnalyzer
from .cyclonedx_exporter import CycloneDXExporter

__all__ = ["DLLScanner", "DLLMetadata", "DependencyAnalyzer", "CycloneDXExporter"]
