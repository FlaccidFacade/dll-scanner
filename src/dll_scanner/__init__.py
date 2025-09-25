"""
DLL Scanner - A Python tool to scan directories for DLL files and extract metadata.

This package provides functionality to:
- Scan directories recursively for DLL files
- Extract metadata from DLL files using PE analysis
- Perform static code analysis to confirm dependencies
- Generate comprehensive reports
"""

__version__ = "0.6.4"
__author__ = "DLL Scanner Contributors"

from dll_scanner.scanner import DLLScanner
from dll_scanner.metadata import DLLMetadata
from dll_scanner.analyzer import DependencyAnalyzer
from dll_scanner.cyclonedx_exporter import CycloneDXExporter
from dll_scanner.page_generator import PageGenerator
from dll_scanner.wix_integration import WiXIntegration

__all__ = [
    "DLLScanner",
    "DLLMetadata",
    "DependencyAnalyzer",
    "CycloneDXExporter",
    "PageGenerator",
    "WiXIntegration",
]
