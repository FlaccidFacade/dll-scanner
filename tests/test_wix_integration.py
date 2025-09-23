"""
Tests for WiX integration functionality.
"""

import json
import platform
import tempfile
import unittest.mock as mock
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock

import pytest

from dll_scanner.wix_integration import WiXIntegration, WiXResult
from dll_scanner.metadata import DLLMetadata
from dll_scanner.scanner import ScanResult


class TestWiXIntegration:
    """Tests for WiX integration functionality."""

    def test_wix_integration_initialization(self):
        """Test WiX integration initialization."""
        wix = WiXIntegration()

        assert wix.cache_dir.name == "wix-cache"
        assert wix.wix_dir.name == "wix311"
        assert wix.heat_exe.name == "heat.exe"

    def test_wix_integration_with_custom_cache(self):
        """Test WiX integration with custom cache directory."""
        with tempfile.TemporaryDirectory() as temp_dir:
            cache_dir = Path(temp_dir) / "custom_cache"
            wix = WiXIntegration(cache_dir=cache_dir)

            assert wix.cache_dir == cache_dir
            assert wix.wix_dir == cache_dir / "wix311"

    def test_is_windows_detection(self):
        """Test Windows platform detection."""
        wix = WiXIntegration()

        with patch("platform.system") as mock_system:
            mock_system.return_value = "Windows"
            assert wix.is_windows() is True

            mock_system.return_value = "Linux"
            assert wix.is_windows() is False

            mock_system.return_value = "Darwin"
            assert wix.is_windows() is False

    def test_is_available_false_when_not_windows(self):
        """Test is_available returns False on non-Windows."""
        wix = WiXIntegration()

        with patch.object(wix, "is_windows", return_value=False):
            assert wix.is_available() is False

    def test_is_available_true_when_heat_exists(self):
        """Test is_available returns True when heat.exe exists."""
        wix = WiXIntegration()

        with (
            patch.object(wix, "is_windows", return_value=True),
            patch("pathlib.Path.exists", return_value=True),
            patch("pathlib.Path.is_file", return_value=True),
        ):
            assert wix.is_available() is True

    def test_is_available_false_when_heat_missing(self):
        """Test is_available returns False when heat.exe missing."""
        wix = WiXIntegration()

        with (
            patch.object(wix, "is_windows", return_value=True),
            patch("pathlib.Path.exists", return_value=False),
        ):
            assert wix.is_available() is False

    @patch("urllib.request.urlopen")
    @patch("urllib.request.urlretrieve")
    @patch("zipfile.ZipFile")
    def test_download_wix_success(self, mock_zipfile, mock_urlretrieve, mock_urlopen):
        """Test successful WiX download."""
        wix = WiXIntegration()

        # Mock release API response
        release_data = {
            "assets": [
                {
                    "name": "wix311-binaries.zip",
                    "browser_download_url": "https://example.com/wix311-binaries.zip",
                }
            ]
        }

        mock_response = Mock()
        mock_response.read.return_value = json.dumps(release_data).encode()
        mock_urlopen.return_value.__enter__.return_value = mock_response

        # Mock zipfile extraction
        mock_zip = Mock()
        mock_zipfile.return_value.__enter__.return_value = mock_zip

        with (
            patch.object(wix, "is_windows", return_value=True),
            patch.object(wix, "is_available", side_effect=[False, True]),
            patch("pathlib.Path.unlink"),
        ):

            result = wix.download_wix()

            assert result is True
            mock_urlretrieve.assert_called_once()
            mock_zip.extractall.assert_called_once()

    def test_download_wix_fails_on_non_windows(self):
        """Test WiX download fails on non-Windows."""
        wix = WiXIntegration()

        with patch.object(wix, "is_windows", return_value=False):
            result = wix.download_wix()
            assert result is False

    def test_download_wix_skips_if_available(self):
        """Test WiX download skips if already available."""
        wix = WiXIntegration()

        with patch.object(wix, "is_available", return_value=True):
            result = wix.download_wix()
            assert result is True

    @patch("subprocess.run")
    def test_run_heat_success(self, mock_subprocess):
        """Test successful heat.exe execution."""
        wix = WiXIntegration()

        # Mock successful subprocess result
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "Heat output"
        mock_result.stderr = ""
        mock_subprocess.return_value = mock_result

        with tempfile.TemporaryDirectory() as temp_dir:
            dll_path = Path(temp_dir) / "test.dll"
            dll_path.write_text("fake dll")

            wxs_content = """<?xml version="1.0" encoding="UTF-8"?>
            <Wix xmlns="http://schemas.microsoft.com/wix/2006/wi">
                <Fragment>
                    <Component Id="test_dll" Guid="12345678-1234-1234-1234-123456789012">
                        <File Id="test.dll" Name="test.dll" Source="$(var.SourceDir)/test.dll" KeyPath="yes" />
                    </Component>
                </Fragment>
            </Wix>"""

            with (
                patch.object(wix, "is_available", return_value=True),
                patch.object(
                    wix, "_parse_wxs_output", return_value={"wix_file_id": "test.dll"}
                ),
            ):

                result = wix.run_heat(dll_path)

                assert result.success is True
                assert result.dll_path == dll_path
                assert "wix_file_id" in result.wix_metadata
                assert result.heat_output == "Heat output"

    def test_run_heat_fails_when_not_available(self):
        """Test heat.exe execution fails when WiX not available."""
        wix = WiXIntegration()

        with tempfile.TemporaryDirectory() as temp_dir:
            dll_path = Path(temp_dir) / "test.dll"

            with patch.object(wix, "is_available", return_value=False):
                result = wix.run_heat(dll_path)

                assert result.success is False
                assert "not available" in result.error_message

    def test_run_heat_fails_with_missing_dll(self):
        """Test heat.exe execution fails with missing DLL."""
        wix = WiXIntegration()

        dll_path = Path("/nonexistent/test.dll")

        with patch.object(wix, "is_available", return_value=True):
            result = wix.run_heat(dll_path)

            assert result.success is False
            assert "not found" in result.error_message

    @patch("subprocess.run")
    def test_run_heat_subprocess_failure(self, mock_subprocess):
        """Test heat.exe execution with subprocess failure."""
        wix = WiXIntegration()

        # Mock failed subprocess result
        mock_result = Mock()
        mock_result.returncode = 1
        mock_result.stdout = ""
        mock_result.stderr = "Heat failed"
        mock_subprocess.return_value = mock_result

        with tempfile.TemporaryDirectory() as temp_dir:
            dll_path = Path(temp_dir) / "test.dll"
            dll_path.write_text("fake dll")

            with patch.object(wix, "is_available", return_value=True):
                result = wix.run_heat(dll_path)

                assert result.success is False
                assert "Heat failed" in result.error_message

    def test_parse_wxs_output_success(self):
        """Test successful WXS file parsing."""
        wix = WiXIntegration()

        wxs_content = """<?xml version="1.0" encoding="UTF-8"?>
        <Wix xmlns="http://schemas.microsoft.com/wix/2006/wi">
            <Fragment>
                <Directory Id="TARGETDIR" Name="SourceDir">
                    <Component Id="TestComponent" Guid="12345678-1234-1234-1234-123456789012">
                        <File Id="test.dll" Name="test.dll" Source="$(var.SourceDir)/test.dll" KeyPath="yes" />
                    </Component>
                </Directory>
            </Fragment>
        </Wix>"""

        with tempfile.TemporaryDirectory() as temp_dir:
            wxs_file = Path(temp_dir) / "test.wxs"
            wxs_file.write_text(wxs_content)

            metadata = wix._parse_wxs_output(wxs_file)

            assert "wix_file_id" in metadata
            assert metadata["wix_file_id"] == "test.dll"
            assert "wix_component_id" in metadata
            assert metadata["wix_component_id"] == "TestComponent"
            assert "wix_component_guid" in metadata

    def test_parse_wxs_output_with_missing_file(self):
        """Test WXS parsing with missing file."""
        wix = WiXIntegration()

        non_existent_file = Path("/nonexistent/test.wxs")
        metadata = wix._parse_wxs_output(non_existent_file)

        assert metadata == {}

    def test_analyze_dll_with_wix_non_windows(self):
        """Test DLL analysis on non-Windows platform."""
        wix = WiXIntegration()

        with tempfile.TemporaryDirectory() as temp_dir:
            dll_path = Path(temp_dir) / "test.dll"

            with patch.object(wix, "is_windows", return_value=False):
                result = wix.analyze_dll_with_wix(dll_path)

                assert result["wix_available"] is False
                assert "only available on Windows" in result["wix_error"]

    def test_analyze_dll_with_wix_success(self):
        """Test successful DLL analysis with WiX."""
        wix = WiXIntegration()

        with tempfile.TemporaryDirectory() as temp_dir:
            dll_path = Path(temp_dir) / "test.dll"

            mock_wix_result = WiXResult(
                dll_path=dll_path,
                wix_metadata={"wix_file_id": "test.dll"},
                heat_output="Success",
                success=True,
            )

            with (
                patch.object(wix, "is_windows", return_value=True),
                patch.object(wix, "is_available", return_value=True),
                patch.object(wix, "run_heat", return_value=mock_wix_result),
            ):

                result = wix.analyze_dll_with_wix(dll_path)

                assert result["wix_available"] is True
                assert result["wix_success"] is True
                assert result["wix_metadata"]["wix_file_id"] == "test.dll"
                assert result["wix_heat_output"] == "Success"

    def test_enhance_scan_result_non_windows(self):
        """Test scan result enhancement on non-Windows."""
        from datetime import datetime

        wix = WiXIntegration()

        # Create mock scan result
        dll_metadata = DLLMetadata(
            file_path="/test/test.dll",
            file_name="test.dll",
            file_size=1024,
            modification_time=datetime.now(),
            architecture="x64",
        )

        scan_result = ScanResult(
            scan_path="/test",
            recursive=True,
            dll_files=[dll_metadata],
            total_files_scanned=1,
            total_dlls_found=1,
            scan_duration_seconds=1.0,
            errors=[],
        )

        with patch.object(wix, "is_windows", return_value=False):
            enhanced_result = wix.enhance_scan_result(scan_result)

            # Should return original result unchanged on non-Windows
            assert enhanced_result.scan_path == scan_result.scan_path
            assert len(enhanced_result.dll_files) == 1
            assert enhanced_result.dll_files[0].file_name == "test.dll"

    def test_enhance_scan_result_windows_success(self):
        """Test successful scan result enhancement on Windows."""
        from datetime import datetime

        wix = WiXIntegration()

        # Create mock scan result
        dll_metadata = DLLMetadata(
            file_path="/test/test.dll",
            file_name="test.dll",
            file_size=1024,
            modification_time=datetime.now(),
            architecture="x64",
        )

        scan_result = ScanResult(
            scan_path="/test",
            recursive=True,
            dll_files=[dll_metadata],
            total_files_scanned=1,
            total_dlls_found=1,
            scan_duration_seconds=1.0,
            errors=[],
        )

        mock_wix_data = {
            "wix_available": True,
            "wix_success": True,
            "wix_metadata": {"wix_file_id": "test.dll"},
        }

        with (
            patch.object(wix, "is_windows", return_value=True),
            patch.object(wix, "analyze_dll_with_wix", return_value=mock_wix_data),
        ):

            enhanced_result = wix.enhance_scan_result(scan_result)

            assert enhanced_result.scan_path == scan_result.scan_path
            assert len(enhanced_result.dll_files) == 1

            enhanced_dll = enhanced_result.dll_files[0]
            assert enhanced_dll.file_name == "test.dll"
            # Check if additional_metadata was created or updated with WiX data
            assert enhanced_dll.additional_metadata is not None
            assert enhanced_dll.additional_metadata["wix_available"] is True
            assert enhanced_dll.additional_metadata["wix_success"] is True
            assert "wix_metadata" in enhanced_dll.additional_metadata


class TestWiXResult:
    """Tests for WiXResult dataclass."""

    def test_wix_result_creation(self):
        """Test WiXResult creation."""
        dll_path = Path("/test/test.dll")
        metadata = {"wix_file_id": "test.dll"}

        result = WiXResult(
            dll_path=dll_path,
            wix_metadata=metadata,
            heat_output="Success",
            success=True,
        )

        assert result.dll_path == dll_path
        assert result.wix_metadata == metadata
        assert result.heat_output == "Success"
        assert result.success is True
        assert result.error_message is None

    def test_wix_result_with_error(self):
        """Test WiXResult creation with error."""
        dll_path = Path("/test/test.dll")

        result = WiXResult(
            dll_path=dll_path,
            wix_metadata={},
            heat_output="",
            success=False,
            error_message="Test error",
        )

        assert result.dll_path == dll_path
        assert result.wix_metadata == {}
        assert result.heat_output == ""
        assert result.success is False
        assert result.error_message == "Test error"
