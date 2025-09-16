"""
Test suite for DLL Scanner.
"""

import pytest
from pathlib import Path
import tempfile
from unittest.mock import Mock, patch

from dll_scanner import DLLScanner, DLLMetadata, DependencyAnalyzer
from dll_scanner.scanner import ScanResult
from dll_scanner.analyzer import DependencyMatch, AnalysisResult
from dll_scanner.cyclonedx_exporter import CycloneDXExporter


@pytest.fixture
def temp_directory():
    """Create a temporary directory for testing."""
    with tempfile.TemporaryDirectory() as temp_dir:
        yield Path(temp_dir)


@pytest.fixture
def sample_dll_metadata():
    """Create sample DLL metadata for testing."""
    return DLLMetadata(
        file_path="/test/sample.dll",
        file_name="sample.dll",
        file_size=65536,
        modification_time=None,
        architecture="x64",
        machine_type="amd64",
        company_name="Test Company",
        product_version="1.0.0",
        imported_dlls=["kernel32.dll", "user32.dll"],
        exported_functions=["TestFunction", "AnotherFunction"],
    )


class TestDLLMetadata:
    """Tests for DLLMetadata class."""

    def test_metadata_creation(self):
        """Test basic metadata creation."""
        metadata = DLLMetadata(
            file_path="/test/test.dll",
            file_name="test.dll",
            file_size=1024,
            modification_time=None,
        )

        assert metadata.file_name == "test.dll"
        assert metadata.file_size == 1024
        assert metadata.analysis_errors == []
        assert metadata.dll_characteristics == []

    def test_metadata_to_dict(self, sample_dll_metadata):
        """Test metadata serialization to dictionary."""
        data = sample_dll_metadata.to_dict()

        assert data["file_name"] == "sample.dll"
        assert data["architecture"] == "x64"
        assert data["imported_dlls"] == ["kernel32.dll", "user32.dll"]

    def test_metadata_to_json(self, sample_dll_metadata):
        """Test metadata serialization to JSON."""
        json_str = sample_dll_metadata.to_json()

        assert "sample.dll" in json_str
        assert "x64" in json_str
        assert "kernel32.dll" in json_str


class TestDLLScanner:
    """Tests for DLLScanner class."""

    def test_scanner_initialization(self):
        """Test scanner initialization."""
        scanner = DLLScanner(max_workers=2)

        assert scanner.max_workers == 2
        assert scanner.progress_callback is None

    def test_scan_nonexistent_directory(self):
        """Test scanning a non-existent directory raises error."""
        scanner = DLLScanner()

        with pytest.raises(FileNotFoundError):
            scanner.scan_directory(Path("/nonexistent/path"))

    def test_scan_empty_directory(self, temp_directory):
        """Test scanning an empty directory."""
        scanner = DLLScanner()
        result = scanner.scan_directory(temp_directory)

        assert isinstance(result, ScanResult)
        assert result.total_dlls_found == 0
        assert result.dll_files == []
        assert result.scan_path == str(temp_directory)

    @patch("dll_scanner.scanner.extract_dll_metadata")
    def test_scan_directory_with_dll(
        self, mock_extract, temp_directory, sample_dll_metadata
    ):
        """Test scanning directory with DLL files."""
        # Create a fake DLL file
        dll_file = temp_directory / "test.dll"
        dll_file.write_bytes(b"fake dll content")

        # Mock metadata extraction
        mock_extract.return_value = sample_dll_metadata

        scanner = DLLScanner()
        result = scanner.scan_directory(temp_directory)

        assert result.total_dlls_found == 1
        assert len(result.dll_files) == 1
        assert result.dll_files[0].file_name == "sample.dll"

    def test_get_summary_stats_empty(self):
        """Test summary stats with empty scan result."""
        scanner = DLLScanner()
        scan_result = ScanResult(
            scan_path="/test",
            recursive=True,
            dll_files=[],
            total_files_scanned=0,
            total_dlls_found=0,
            scan_duration_seconds=0.1,
            errors=[],
        )

        stats = scanner.get_summary_stats(scan_result)

        assert stats["total_dlls"] == 0
        assert stats["architectures"] == {}
        assert stats["signed_dlls"] == 0


class TestDependencyAnalyzer:
    """Tests for DependencyAnalyzer class."""

    def test_analyzer_initialization(self):
        """Test analyzer initialization."""
        analyzer = DependencyAnalyzer()

        assert analyzer.logger is not None

    def test_dll_names_match(self):
        """Test DLL name matching logic."""
        analyzer = DependencyAnalyzer()

        assert analyzer._dll_names_match("test.dll", "test.dll")
        assert analyzer._dll_names_match("test", "test.dll")
        assert analyzer._dll_names_match("TEST.DLL", "test.dll")
        assert not analyzer._dll_names_match("test.dll", "other.dll")
        assert not analyzer._dll_names_match("", "test.dll")

    def test_analyze_nonexistent_directory(self, sample_dll_metadata):
        """Test analyzing non-existent source directory."""
        analyzer = DependencyAnalyzer()

        with pytest.raises(FileNotFoundError):
            analyzer.analyze_dll_dependencies(
                sample_dll_metadata, Path("/nonexistent/source")
            )

    def test_analyze_empty_directory(self, temp_directory, sample_dll_metadata):
        """Test analyzing empty source directory."""
        analyzer = DependencyAnalyzer()
        result = analyzer.analyze_dll_dependencies(sample_dll_metadata, temp_directory)

        assert isinstance(result, AnalysisResult)
        assert result.confirmed_dependencies == []
        assert result.potential_dependencies == []
        assert result.source_files_analyzed == 0

    def test_analyze_source_file_with_loadlibrary(
        self, temp_directory, sample_dll_metadata
    ):
        """Test analyzing source file with LoadLibrary call."""
        # Create C++ source file with LoadLibrary call
        cpp_file = temp_directory / "test.cpp"
        cpp_file.write_text(
            """
#include <windows.h>

int main() {
    HMODULE handle = LoadLibrary("sample.dll");
    return 0;
}
        """
        )

        analyzer = DependencyAnalyzer()
        result = analyzer.analyze_dll_dependencies(sample_dll_metadata, temp_directory)

        assert result.source_files_analyzed == 1
        assert len(result.confirmed_dependencies) >= 1

        # Check for LoadLibrary match
        loadlib_matches = [
            dep
            for dep in result.confirmed_dependencies
            if dep.match_type == "loadlibrary"
        ]
        assert len(loadlib_matches) > 0
        assert loadlib_matches[0].dll_name == "sample.dll"

    def test_analyze_source_file_with_dllimport(
        self, temp_directory, sample_dll_metadata
    ):
        """Test analyzing C# source file with DllImport."""
        cs_file = temp_directory / "test.cs"
        cs_file.write_text(
            """
using System.Runtime.InteropServices;

class Program {
    [DllImport("sample.dll")]
    static extern void TestFunction();
}
        """
        )

        analyzer = DependencyAnalyzer()
        result = analyzer.analyze_dll_dependencies(sample_dll_metadata, temp_directory)

        assert result.source_files_analyzed == 1

        # Check for DllImport match
        dllimport_matches = [
            dep
            for dep in result.confirmed_dependencies
            if dep.match_type == "dllimport"
        ]
        assert len(dllimport_matches) > 0
        assert dllimport_matches[0].dll_name == "sample.dll"

    def test_generate_dependency_report(self, sample_dll_metadata):
        """Test dependency report generation."""
        analyzer = DependencyAnalyzer()

        # Create mock analysis results
        analysis_results = [
            AnalysisResult(
                dll_metadata=sample_dll_metadata,
                confirmed_dependencies=[
                    DependencyMatch(
                        file_path="/test/main.cpp",
                        line_number=5,
                        line_content='LoadLibrary("sample.dll")',
                        match_type="loadlibrary",
                        dll_name="sample.dll",
                        confidence=0.95,
                    )
                ],
                potential_dependencies=[],
                source_files_analyzed=1,
                analysis_confidence=0.95,
            )
        ]

        report = analyzer.generate_dependency_report(analysis_results)

        assert report["summary"]["total_dlls_analyzed"] == 1
        assert report["summary"]["dlls_with_confirmed_usage"] == 1
        assert report["summary"]["total_confirmed_dependencies"] == 1
        assert len(report["confirmed_dlls"]) == 1


class TestCLI:
    """Tests for CLI functionality."""

    @patch("dll_scanner.cli.DLLScanner")
    def test_scan_command_basic(self, mock_scanner_class, temp_directory):
        """Test basic scan command."""
        from dll_scanner.cli import cli
        from click.testing import CliRunner

        # Mock scanner instance and result
        mock_scanner = Mock()
        mock_result = ScanResult(
            scan_path=str(temp_directory),
            recursive=True,
            dll_files=[],
            total_files_scanned=0,
            total_dlls_found=0,
            scan_duration_seconds=0.1,
            errors=[],
        )
        mock_scanner.scan_directory.return_value = mock_result
        mock_scanner_class.return_value = mock_scanner

        runner = CliRunner()
        result = runner.invoke(cli, ["scan", str(temp_directory)])

        assert result.exit_code == 0
        assert "Scanning directory" in result.output

    def test_cli_version(self):
        """Test CLI version command."""
        from dll_scanner.cli import cli
        from click.testing import CliRunner

        runner = CliRunner()
        result = runner.invoke(cli, ["--version"])

        assert result.exit_code == 0
        assert "0.1.0" in result.output


class TestCycloneDXExporter:
    """Tests for CycloneDX SBOM export functionality."""

    def test_exporter_initialization(self):
        """Test CycloneDX exporter initialization."""
        exporter = CycloneDXExporter()
        assert exporter is not None

    def test_export_empty_scan_result(self):
        """Test exporting empty scan result to CycloneDX."""
        exporter = CycloneDXExporter()
        scan_result = ScanResult(
            scan_path="/test",
            recursive=True,
            dll_files=[],
            total_files_scanned=0,
            total_dlls_found=0,
            scan_duration_seconds=0.1,
            errors=[],
        )

        bom = exporter.export_to_cyclonedx(scan_result)
        
        assert bom is not None
        assert bom.metadata.component.name == "DLL Analysis Project"
        assert len(bom.components) == 0

    def test_export_with_dll_metadata(self, sample_dll_metadata):
        """Test exporting scan result with DLL metadata."""
        exporter = CycloneDXExporter()
        scan_result = ScanResult(
            scan_path="/test",
            recursive=True,
            dll_files=[sample_dll_metadata],
            total_files_scanned=1,
            total_dlls_found=1,
            scan_duration_seconds=0.5,
            errors=[],
        )

        bom = exporter.export_to_cyclonedx(scan_result)
        
        assert bom is not None
        assert len(bom.components) == 1
        
        component = list(bom.components)[0]
        assert component.name == "sample.dll"
        assert component.version == "1.0.0"

    def test_export_to_json(self, sample_dll_metadata):
        """Test exporting to JSON format."""
        exporter = CycloneDXExporter()
        scan_result = ScanResult(
            scan_path="/test",
            recursive=True,
            dll_files=[sample_dll_metadata],
            total_files_scanned=1,
            total_dlls_found=1,
            scan_duration_seconds=0.5,
            errors=[],
        )

        json_output = exporter.export_to_json(scan_result)
        
        assert json_output is not None
        assert "bomFormat" in json_output
        assert "CycloneDX" in json_output
        assert "sample.dll" in json_output

    def test_components_have_package_urls(self, sample_dll_metadata):
        """Test that all components in exported JSON have purl (package URL) attributes."""
        import json
        
        exporter = CycloneDXExporter()
        scan_result = ScanResult(
            scan_path="/test",
            recursive=True,
            dll_files=[sample_dll_metadata],
            total_files_scanned=1,
            total_dlls_found=1,
            scan_duration_seconds=0.5,
            errors=[],
        )

        json_output = exporter.export_to_json(scan_result)
        bom_data = json.loads(json_output)
        
        # Check that components exist
        assert "components" in bom_data
        assert len(bom_data["components"]) == 1
        
        # Check that each component has a purl attribute
        for component in bom_data["components"]:
            assert "purl" in component, f"Component {component.get('name', 'unknown')} missing purl attribute"
            assert component["purl"] is not None, f"Component {component.get('name', 'unknown')} has null purl"
            assert component["purl"].startswith("pkg:"), f"Component purl should start with 'pkg:': {component['purl']}"
        
        # Check that the main metadata component also has a purl
        assert "metadata" in bom_data
        assert "component" in bom_data["metadata"]
        metadata_component = bom_data["metadata"]["component"]
        assert "purl" in metadata_component, "Main component missing purl attribute"
        assert metadata_component["purl"] is not None, "Main component has null purl"
        assert metadata_component["purl"].startswith("pkg:"), f"Main component purl should start with 'pkg:': {metadata_component['purl']}"
        
        # Verify specific purl format for DLL component
        dll_component = bom_data["components"][0]
        expected_purl_start = "pkg:dll/test-company/sample.dll@1.0.0"
        assert dll_component["purl"].startswith(expected_purl_start), f"DLL component purl should start with '{expected_purl_start}': {dll_component['purl']}"

    def test_component_summary(self, sample_dll_metadata):
        """Test getting component summary from BOM."""
        exporter = CycloneDXExporter()
        scan_result = ScanResult(
            scan_path="/test",
            recursive=True,
            dll_files=[sample_dll_metadata],
            total_files_scanned=1,
            total_dlls_found=1,
            scan_duration_seconds=0.5,
            errors=[],
        )

        bom = exporter.export_to_cyclonedx(scan_result)
        summary = exporter.get_component_summary(bom)
        
        assert summary["total_components"] == 1
        assert "architectures" in summary
        assert "signed_dlls" in summary


# Integration tests
class TestIntegration:
    """Integration tests for the complete workflow."""

    @pytest.mark.skip(reason="Requires pefile and actual DLL files")
    def test_full_workflow_with_real_dll(self):
        """Test complete workflow with a real DLL file."""
        # This test would require a real DLL file and pefile library
        # Skip in CI/CD pipeline but useful for local testing
        pass


if __name__ == "__main__":
    pytest.main([__file__])
