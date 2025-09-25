"""
WiX Toolset integration for enhanced Windows DLL analysis.

This module provides functionality to download, cache, and use WiX Toolset
for analyzing DLL files with Windows-specific metadata extraction capabilities.
"""

import json
import logging
import platform
import shutil
import subprocess
import tempfile
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Optional, Any
import urllib.request
import urllib.error

from dll_scanner.metadata import DLLMetadata
from dll_scanner.scanner import ScanResult


@dataclass
class WiXResult:
    """Result from WiX tool analysis."""

    dll_path: Path
    wix_metadata: Dict[str, Any]
    heat_output: str
    success: bool
    error_message: Optional[str] = None


class WiXIntegration:
    """
    Integrates WiX Toolset for enhanced DLL analysis on Windows.

    Downloads WiX Toolset from GitHub releases, caches it locally,
    and uses heat.exe to harvest DLL metadata.
    """

    GITHUB_RELEASE_URL = (
        "https://api.github.com/repos/wixtoolset/wix3/releases/tags/wix3112rtm"
    )
    BINARIES_ASSET_NAME = "wix311-binaries.zip"

    def __init__(
        self, cache_dir: Optional[Path] = None, logger: Optional[logging.Logger] = None
    ):
        """
        Initialize WiX integration.

        Args:
            cache_dir: Directory to cache WiX binaries (defaults to system temp)
            logger: Logger instance for debug/info messages
        """
        self.logger = logger or logging.getLogger(__name__)
        self.cache_dir = cache_dir or Path.home() / ".dll-scanner" / "wix-cache"
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.wix_dir = self.cache_dir / "wix311"
        self.heat_exe = self.wix_dir / "heat.exe"

    def is_windows(self) -> bool:
        """Check if running on Windows platform."""
        return platform.system().lower() == "windows"

    def is_available(self) -> bool:
        """
        Check if WiX tools are available.

        Returns:
            True if WiX is installed and heat.exe is available
        """
        if not self.is_windows():
            self.logger.warning("WiX Toolset is only available on Windows")
            return False

        return self.heat_exe.exists() and self.heat_exe.is_file()

    def download_wix(self) -> bool:
        """
        Download and extract WiX Toolset from GitHub releases.

        Returns:
            True if download and extraction successful
        """
        if self.is_available():
            self.logger.info("WiX Toolset already available")
            return True

        if not self.is_windows():
            self.logger.error("WiX Toolset can only be downloaded on Windows")
            return False

        try:
            self.logger.info("Fetching WiX release information from GitHub...")

            # Get release information
            with urllib.request.urlopen(self.GITHUB_RELEASE_URL) as response:
                release_data = json.loads(response.read().decode())

            # Find binaries asset
            binaries_asset = None
            for asset in release_data.get("assets", []):
                if asset["name"] == self.BINARIES_ASSET_NAME:
                    binaries_asset = asset
                    break

            if not binaries_asset:
                self.logger.error(
                    f"Could not find {self.BINARIES_ASSET_NAME} in release assets"
                )
                return False

            download_url = binaries_asset["browser_download_url"]
            self.logger.info(f"Downloading WiX binaries from {download_url}")

            # Download to temporary file
            with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as temp_file:
                temp_path = Path(temp_file.name)

            urllib.request.urlretrieve(download_url, temp_path)

            # Extract binaries
            self.logger.info(f"Extracting WiX binaries to {self.wix_dir}")
            self.wix_dir.mkdir(parents=True, exist_ok=True)

            with zipfile.ZipFile(temp_path, "r") as zip_file:
                zip_file.extractall(self.wix_dir)

            # Clean up temporary file
            temp_path.unlink()

            # Verify extraction
            if self.is_available():
                self.logger.info("WiX Toolset downloaded and extracted successfully")
                return True
            else:
                self.logger.error("WiX extraction completed but heat.exe not found")
                return False

        except urllib.error.URLError as e:
            self.logger.error(f"Failed to download WiX: Network error - {e}")
            return False
        except Exception as e:
            self.logger.error(f"Failed to download WiX: {e}")
            return False

    def run_heat(self, dll_path: Path, output_dir: Optional[Path] = None) -> WiXResult:
        """
        Run WiX heat.exe tool on a DLL file to harvest metadata.

        Args:
            dll_path: Path to DLL file to analyze
            output_dir: Directory for heat output files (defaults to temp)

        Returns:
            WiXResult containing analysis results
        """
        if not self.is_available():
            return WiXResult(
                dll_path=dll_path,
                wix_metadata={},
                heat_output="",
                success=False,
                error_message="WiX Toolset not available",
            )

        if not dll_path.exists():
            return WiXResult(
                dll_path=dll_path,
                wix_metadata={},
                heat_output="",
                success=False,
                error_message=f"DLL file not found: {dll_path}",
            )

        try:
            # Create temporary output directory if not specified
            if output_dir is None:
                output_dir = Path(tempfile.mkdtemp(prefix="wix_heat_"))
                cleanup_output = True
            else:
                output_dir.mkdir(parents=True, exist_ok=True)
                cleanup_output = False

            output_file = output_dir / f"{dll_path.stem}_heat.wxs"

            # Build heat command
            # heat file command harvests a single file
            cmd = [
                str(self.heat_exe),
                "file",
                str(dll_path),
                "-out",
                str(output_file),
                "-ag",  # autogenerate component guids
                "-sfrag",  # suppress fragments
                "-srd",  # suppress root directory
                "-var",
                "var.SourceDir",  # use SourceDir variable
            ]

            self.logger.debug(f"Running heat command: {' '.join(cmd)}")

            # Execute heat.exe
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=30, cwd=output_dir
            )

            if result.returncode == 0:
                # Parse the WXS output file for metadata
                wix_metadata = self._parse_wxs_output(output_file)

                return WiXResult(
                    dll_path=dll_path,
                    wix_metadata=wix_metadata,
                    heat_output=result.stdout,
                    success=True,
                )
            else:
                self.logger.warning(
                    f"heat.exe failed with return code {result.returncode}"
                )
                return WiXResult(
                    dll_path=dll_path,
                    wix_metadata={},
                    heat_output=result.stdout + "\n" + result.stderr,
                    success=False,
                    error_message=f"heat.exe failed: {result.stderr}",
                )

        except subprocess.TimeoutExpired:
            return WiXResult(
                dll_path=dll_path,
                wix_metadata={},
                heat_output="",
                success=False,
                error_message="heat.exe timed out",
            )
        except Exception as e:
            return WiXResult(
                dll_path=dll_path,
                wix_metadata={},
                heat_output="",
                success=False,
                error_message=f"heat.exe execution failed: {e}",
            )
        finally:
            # Clean up temporary directory if we created it
            if cleanup_output and output_dir is not None and output_dir.exists():
                try:
                    shutil.rmtree(output_dir)
                except Exception as e:
                    self.logger.warning(
                        f"Failed to clean up temp directory {output_dir}: {e}"
                    )

    def _parse_wxs_output(self, wxs_file: Path) -> Dict[str, Any]:
        """
        Parse WiX WXS output file to extract metadata.

        Args:
            wxs_file: Path to WXS file generated by heat.exe

        Returns:
            Dictionary containing extracted metadata
        """
        metadata: Dict[str, Any] = {}

        if not wxs_file.exists():
            return metadata

        try:
            import xml.etree.ElementTree as ET

            tree = ET.parse(wxs_file)
            root = tree.getroot()

            # WiX namespaces
            namespaces = {"wix": "http://schemas.microsoft.com/wix/2006/wi"}

            # Find File elements
            for file_elem in root.findall(".//wix:File", namespaces):
                file_attrs = file_elem.attrib

                # Extract file metadata
                if "Id" in file_attrs:
                    metadata["wix_file_id"] = file_attrs["Id"]
                if "Name" in file_attrs:
                    metadata["wix_file_name"] = file_attrs["Name"]
                if "Source" in file_attrs:
                    metadata["wix_source"] = file_attrs["Source"]
                if "KeyPath" in file_attrs:
                    metadata["wix_key_path"] = file_attrs["KeyPath"]

            # Find Component elements
            for comp_elem in root.findall(".//wix:Component", namespaces):
                comp_attrs = comp_elem.attrib

                if "Id" in comp_attrs:
                    metadata["wix_component_id"] = comp_attrs["Id"]
                if "Guid" in comp_attrs:
                    metadata["wix_component_guid"] = comp_attrs["Guid"]

            # Find Directory elements for path info
            for dir_elem in root.findall(".//wix:Directory", namespaces):
                dir_attrs = dir_elem.attrib

                if "Id" in dir_attrs and dir_attrs["Id"] == "TARGETDIR":
                    metadata["wix_target_dir"] = dir_attrs.get("Name", "")

        except Exception as e:
            self.logger.warning(f"Failed to parse WXS file {wxs_file}: {e}")

        return metadata

    def analyze_dll_with_wix(self, dll_path: Path) -> Dict[str, Any]:
        """
        Analyze a DLL file using WiX tools and return enhanced metadata.

        Args:
            dll_path: Path to DLL file to analyze

        Returns:
            Dictionary containing WiX-enhanced metadata
        """
        if not self.is_windows():
            return {
                "wix_available": False,
                "wix_error": "WiX Toolset is only available on Windows",
            }

        if not self.is_available():
            self.logger.info("WiX not available, attempting to download...")
            if not self.download_wix():
                return {
                    "wix_available": False,
                    "wix_error": "Failed to download WiX Toolset",
                }

        wix_result = self.run_heat(dll_path)

        result = {
            "wix_available": True,
            "wix_success": wix_result.success,
            "wix_metadata": wix_result.wix_metadata,
        }

        if not wix_result.success:
            result["wix_error"] = wix_result.error_message

        if wix_result.heat_output:
            result["wix_heat_output"] = wix_result.heat_output

        return result

    def enhance_scan_result(self, scan_result: ScanResult) -> ScanResult:
        """
        Enhance a scan result with WiX analysis for all DLL files.

        Args:
            scan_result: Original scan result to enhance

        Returns:
            Enhanced scan result with WiX metadata
        """
        if not self.is_windows():
            self.logger.info("Skipping WiX enhancement on non-Windows platform")
            return scan_result

        enhanced_dlls = []

        for dll_metadata in scan_result.dll_files:
            # Run WiX analysis
            wix_data = self.analyze_dll_with_wix(Path(dll_metadata.file_path))

            # Create enhanced metadata
            enhanced_metadata = DLLMetadata(
                file_path=dll_metadata.file_path,
                file_name=dll_metadata.file_name,
                file_size=dll_metadata.file_size,
                modification_time=dll_metadata.modification_time,
                machine_type=dll_metadata.machine_type,
                architecture=dll_metadata.architecture,
                subsystem=dll_metadata.subsystem,
                dll_characteristics=dll_metadata.dll_characteristics,
                product_name=dll_metadata.product_name,
                product_version=dll_metadata.product_version,
                file_version=dll_metadata.file_version,
                company_name=dll_metadata.company_name,
                file_description=dll_metadata.file_description,
                internal_name=dll_metadata.internal_name,
                copyright=dll_metadata.copyright,
                legal_copyright=dll_metadata.legal_copyright,
                original_filename=dll_metadata.original_filename,
                imported_dlls=dll_metadata.imported_dlls,
                exported_functions=dll_metadata.exported_functions,
                is_signed=dll_metadata.is_signed,
                checksum=dll_metadata.checksum,
                scan_timestamp=dll_metadata.scan_timestamp,
                analysis_errors=dll_metadata.analysis_errors,
                additional_metadata=dll_metadata.additional_metadata.copy(),
            )

            # Add WiX metadata to additional_metadata
            enhanced_metadata.additional_metadata.update(wix_data)

            enhanced_dlls.append(enhanced_metadata)

        # Return enhanced scan result
        return ScanResult(
            scan_path=scan_result.scan_path,
            recursive=scan_result.recursive,
            dll_files=enhanced_dlls,
            total_files_scanned=scan_result.total_files_scanned,
            total_dlls_found=scan_result.total_dlls_found,
            scan_duration_seconds=scan_result.scan_duration_seconds,
            errors=scan_result.errors,
        )
