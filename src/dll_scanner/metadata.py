"""
DLL metadata extraction functionality.
"""

from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any, Set
from dataclasses import dataclass, asdict, field
from enum import Enum
import json
import logging

try:
    import pefile
except ImportError:
    pefile = None

try:
    import win32api
    import win32con

    # Try to import LOWORD and HIWORD directly from win32api
    try:
        from win32api import GetFileVersionInfo, LOWORD, HIWORD
    except ImportError:
        # If not available, define them as helper functions
        GetFileVersionInfo = getattr(win32api, "GetFileVersionInfo", None)

        def LOWORD(x: int) -> int:
            return x & 0xFFFF

        def HIWORD(x: int) -> int:
            return (x >> 16) & 0xFFFF

except ImportError:
    win32api = None
    win32con = None
    GetFileVersionInfo = None

    def LOWORD(x: int) -> int:
        return x & 0xFFFF

    def HIWORD(x: int) -> int:
        return (x >> 16) & 0xFFFF


class ExtractionMethod(Enum):
    """Available version extraction methods."""

    WIN32API = "win32api"
    PEFILE = "pefile"
    FILEINFO = "fileinfo"
    ALL = "all"  # Use all methods in order (default behavior)


def _extract_version_string_win32apigetVersionString(filename: str) -> str:
    """
    Extract version string using win32api GetFileVersionInfo with HIWORD/LOWORD helpers.

    Args:
        filename: Path to the DLL file

    Returns:
        str: Version string in format "major.minor.build.revision" or "---" if failed
    """
    # requirement: "$ pip install pywin32"
    # inspiration taken from:
    # http://timgolden.me.uk/python/win32_how_do_i/get_dll_version.html

    if GetFileVersionInfo is None:
        return "---"  # win32api not available

    try:
        info = GetFileVersionInfo(str(filename), "\\")
    except Exception:
        return "---"  # f'failed for {filename}'

    ms = info["FileVersionMS"]
    ls = info["FileVersionLS"]
    versionAsList = [HIWORD(ms), LOWORD(ms), HIWORD(ls), LOWORD(ls)]
    versionStr = ".".join([str(i) for i in versionAsList])

    return versionStr


@dataclass
class DLLMetadata:
    """Container for DLL file metadata."""

    # Basic file information
    file_path: str
    file_name: str
    file_size: int
    modification_time: datetime

    # PE Header information
    machine_type: Optional[str] = None
    architecture: Optional[str] = None
    subsystem: Optional[str] = None
    dll_characteristics: List[str] = field(default_factory=list)

    # Version information
    product_name: Optional[str] = None
    product_version: Optional[str] = None
    file_version: Optional[str] = None
    company_name: Optional[str] = None
    file_description: Optional[str] = None
    internal_name: Optional[str] = None
    copyright: Optional[str] = None
    legal_copyright: Optional[str] = None
    original_filename: Optional[str] = None

    # Dependencies
    imported_dlls: List[str] = field(default_factory=list)
    exported_functions: List[str] = field(default_factory=list)

    # Security and integrity
    is_signed: bool = False
    checksum: Optional[str] = None

    # Analysis metadata
    scan_timestamp: Optional[datetime] = None
    analysis_errors: List[str] = field(default_factory=list)
    additional_metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.scan_timestamp is None:
            self.scan_timestamp = datetime.now()

    def to_dict(self) -> Dict[str, Any]:
        """Convert metadata to dictionary for serialization."""
        data = asdict(self)
        # Convert datetime objects to ISO format strings
        data["modification_time"] = (
            self.modification_time.isoformat() if self.modification_time else None
        )
        data["scan_timestamp"] = (
            self.scan_timestamp.isoformat() if self.scan_timestamp else None
        )
        return data

    def to_json(self, indent: int = 2) -> str:
        """Convert metadata to JSON string."""
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "DLLMetadata":
        """Create DLLMetadata from dictionary."""
        # Convert ISO format strings back to datetime objects
        if data.get("modification_time"):
            data["modification_time"] = datetime.fromisoformat(
                data["modification_time"]
            )
        if data.get("scan_timestamp"):
            data["scan_timestamp"] = datetime.fromisoformat(data["scan_timestamp"])
        return cls(**data)


class DLLMetadataExtractor:
    """Extracts metadata from DLL files using PE analysis."""
    def __init__(
        self,
        extraction_methods: Optional[Set[ExtractionMethod]] = None,
        logger: Optional["logging.Logger"] = None,
    ) -> None:
        if pefile is None:
            raise ImportError(
                "pefile library is required. Install with: pip install pefile"
            )
        
        import logging
        self.logger = logger or logging.getLogger(__name__)
        
        # Set default extraction methods if none specified
        if extraction_methods is None:
            self.extraction_methods = {ExtractionMethod.ALL}
        else:
            self.extraction_methods = extraction_methods

    def extract_metadata(self, dll_path: Path) -> DLLMetadata:
        """
        Extract comprehensive metadata from a DLL file.

        Args:
            dll_path: Path to the DLL file

        Returns:
            DLLMetadata object containing extracted information
        """
        # Basic file information
        stat = dll_path.stat()
        metadata = DLLMetadata(
            file_path=str(dll_path),
            file_name=dll_path.name,
            file_size=stat.st_size,
            modification_time=datetime.fromtimestamp(stat.st_mtime),
        )

        try:
            # Parse PE file
            pe = pefile.PE(str(dll_path))

            # Extract PE header information
            self._extract_pe_header_info(pe, metadata)

            # Extract version information
            self._extract_version_info(pe, metadata)

            # Extract import/export information
            self._extract_import_export_info(pe, metadata)

            # Extract security information
            self._extract_security_info(pe, metadata)

            pe.close()

        except Exception as e:
            metadata.analysis_errors.append(f"PE analysis failed: {str(e)}")

        return metadata

    def _extract_pe_header_info(self, pe: "pefile.PE", metadata: DLLMetadata) -> None:
        """Extract PE header information."""
        try:
            # Machine type
            machine_types = {
                0x014C: "i386",
                0x0200: "ia64",
                0x8664: "amd64",
                0x01C0: "arm",
                0xAA64: "arm64",
            }
            machine = pe.FILE_HEADER.Machine
            metadata.machine_type = machine_types.get(
                machine, f"Unknown (0x{machine:04x})"
            )

            # Architecture
            if machine in [0x014C]:
                metadata.architecture = "x86"
            elif machine in [0x8664]:
                metadata.architecture = "x64"
            elif machine in [0x01C0, 0xAA64]:
                metadata.architecture = "ARM"
            else:
                metadata.architecture = "Unknown"

            # Subsystem
            subsystems = {
                1: "Native",
                2: "Windows GUI",
                3: "Windows CUI",
                7: "POSIX CUI",
                9: "Windows CE GUI",
                10: "EFI Application",
                11: "EFI Boot Service Driver",
                12: "EFI Runtime Driver",
                13: "EFI ROM",
                14: "XBOX",
                16: "Windows Boot Application",
            }
            subsystem = pe.OPTIONAL_HEADER.Subsystem
            metadata.subsystem = subsystems.get(subsystem, f"Unknown ({subsystem})")

            # DLL Characteristics
            dll_chars = pe.OPTIONAL_HEADER.DllCharacteristics
            characteristics = []

            if dll_chars & 0x0001:
                characteristics.append("Reserved")
            if dll_chars & 0x0002:
                characteristics.append("Reserved")
            if dll_chars & 0x0004:
                characteristics.append("Reserved")
            if dll_chars & 0x0008:
                characteristics.append("Reserved")
            if dll_chars & 0x0040:
                characteristics.append("Dynamic Base")
            if dll_chars & 0x0080:
                characteristics.append("Force Integrity")
            if dll_chars & 0x0100:
                characteristics.append("NX Compatible")
            if dll_chars & 0x0200:
                characteristics.append("No Isolation")
            if dll_chars & 0x0400:
                characteristics.append("No SEH")
            if dll_chars & 0x0800:
                characteristics.append("No Bind")
            if dll_chars & 0x1000:
                characteristics.append("AppContainer")
            if dll_chars & 0x2000:
                characteristics.append("WDM Driver")
            if dll_chars & 0x4000:
                characteristics.append("Control Flow Guard")
            if dll_chars & 0x8000:
                characteristics.append("Terminal Server Aware")

            metadata.dll_characteristics = characteristics

        except Exception as e:
            metadata.analysis_errors.append(f"PE header extraction failed: {str(e)}")

    def _extract_version_info(self, pe: "pefile.PE", metadata: DLLMetadata) -> None:
        """Extract version information from resources."""
        try:
            # Check if user wants all methods (default behavior)
            if ExtractionMethod.ALL in self.extraction_methods:
                # Original behavior: try all methods in order
                if self._extract_version_info_win32api(metadata):
                    return
                if self._extract_version_info_fileinfo(pe, metadata):
                    return
                self._extract_version_info_pefile(pe, metadata)
                return

            # Try only the specified methods
            if ExtractionMethod.WIN32API in self.extraction_methods:
                if self._extract_version_info_win32api(metadata):
                    return

            if ExtractionMethod.FILEINFO in self.extraction_methods:
                if self._extract_version_info_fileinfo(pe, metadata):
                    return

            if ExtractionMethod.PEFILE in self.extraction_methods:
                self._extract_version_info_pefile(pe, metadata)

        except Exception as e:
            metadata.analysis_errors.append(f"Version info extraction failed: {str(e)}")

    def _extract_version_info_pefile(
        self, pe: "pefile.PE", metadata: DLLMetadata
    ) -> None:
        """Extract version information using pefile VS_VERSIONINFO approach."""
        # Fallback to the original VS_VERSIONINFO approach
        if hasattr(pe, "VS_VERSIONINFO"):
            for version_info in pe.VS_VERSIONINFO:
                # Extract binary version information from FixedFileInfo
                if hasattr(version_info, "FixedFileInfo"):
                    fixed_info = version_info.FixedFileInfo[0]

                    # Extract file version from binary format
                    # (HIWORD.LOWORD.HIWORD.LOWORD)
                    if hasattr(fixed_info, "FileVersionMS") and hasattr(
                        fixed_info, "FileVersionLS"
                    ):
                        file_ver_ms = fixed_info.FileVersionMS
                        file_ver_ls = fixed_info.FileVersionLS
                        if file_ver_ms or file_ver_ls:  # Only if version info exists
                            file_version = (
                                f"{file_ver_ms >> 16}.{file_ver_ms & 0xFFFF}."
                                f"{file_ver_ls >> 16}.{file_ver_ls & 0xFFFF}"
                            )
                            # Only set if we don't already have a string version
                            if not metadata.file_version:
                                metadata.file_version = file_version

                    # Extract product version from binary format
                    if hasattr(fixed_info, "ProductVersionMS") and hasattr(
                        fixed_info, "ProductVersionLS"
                    ):
                        prod_ver_ms = fixed_info.ProductVersionMS
                        prod_ver_ls = fixed_info.ProductVersionLS
                        if prod_ver_ms or prod_ver_ls:  # Only if version info exists
                            product_version = (
                                f"{prod_ver_ms >> 16}.{prod_ver_ms & 0xFFFF}."
                                f"{prod_ver_ls >> 16}.{prod_ver_ls & 0xFFFF}"
                            )
                            # Only set if we don't already have a string version
                            if not metadata.product_version:
                                metadata.product_version = product_version

                # Extract string version information from StringFileInfo
                # First try to get translations from VarFileInfo to find
                # correct string tables
                translation_keys = self._get_version_translations(version_info)

                # Extract using discovered translations
                if translation_keys:
                    for translation_key in translation_keys:
                        success = self._extract_string_version_info(
                            version_info, metadata, translation_key
                        )
                        if success:
                            # Successfully extracted with this translation, break
                            break
                else:
                    # Fallback: try default method for older or non-standard DLLs
                    self._extract_string_version_info_fallback(version_info, metadata)

    def _extract_version_info_win32api(self, metadata: DLLMetadata) -> bool:
        """
        Extract version information using win32api.GetFileVersionInfo.
        This method can be more reliable for certain Windows DLLs,
        especially system DLLs that might not be fully parsed by pefile.

        Args:
            metadata: DLL metadata to populate

        Returns:
            True if version information was successfully extracted, False otherwise
        """
        if win32api is None or win32con is None:
            self.logger.debug(
                f"win32api not available for {metadata.file_name}, skipping win32api extraction"
            )
            return False

        try:
            self.logger.debug(
                f"Attempting win32api version extraction for {metadata.file_name}"
            )
            # First try the new win32apigetVersionString function
            version_string = _extract_version_string_win32apigetVersionString(
                metadata.file_path
            )
            if version_string != "---" and not metadata.file_version:
                metadata.file_version = version_string

            # Get version info using win32api
            info = win32api.GetFileVersionInfo(metadata.file_path, "\\")
            if not info:
                return False

            # Extract version numbers from the fixed info using HIWORD/LOWORD helpers
            ms = info.get("FileVersionMS", 0)
            ls = info.get("FileVersionLS", 0)
            if ms or ls:
                file_version = f"{HIWORD(ms)}.{LOWORD(ms)}.{HIWORD(ls)}.{LOWORD(ls)}"
                if not metadata.file_version:
                    metadata.file_version = file_version

            ms = info.get("ProductVersionMS", 0)
            ls = info.get("ProductVersionLS", 0)
            if ms or ls:
                product_version = f"{HIWORD(ms)}.{LOWORD(ms)}.{HIWORD(ls)}.{LOWORD(ls)}"
                if not metadata.product_version:
                    metadata.product_version = product_version

            # Extract string information
            try:
                # Get string file info
                string_info = win32api.GetFileVersionInfo(
                    metadata.file_path, "\\StringFileInfo"
                )
                if string_info:
                    # Try common language/codepage combinations
                    lang_codepage_pairs = ["040904b0", "040004b0", "040904e4"]

                    for lang_codepage in lang_codepage_pairs:
                        try:
                            version_info = win32api.GetFileVersionInfo(
                                metadata.file_path, f"\\StringFileInfo\\{lang_codepage}"
                            )
                            if version_info:
                                # Extract version fields (string overrides binary)
                                base = f"\\StringFileInfo\\{lang_codepage}\\"

                                file_ver = win32api.GetFileVersionInfo(
                                    metadata.file_path, base + "FileVersion"
                                )
                                if file_ver:
                                    metadata.file_version = file_ver

                                prod_ver = win32api.GetFileVersionInfo(
                                    metadata.file_path, base + "ProductVersion"
                                )
                                if prod_ver:
                                    metadata.product_version = prod_ver

                                if not metadata.company_name:
                                    company = win32api.GetFileVersionInfo(
                                        metadata.file_path, base + "CompanyName"
                                    )
                                    if company:
                                        metadata.company_name = company

                                if not metadata.file_description:
                                    desc = win32api.GetFileVersionInfo(
                                        metadata.file_path, base + "FileDescription"
                                    )
                                    if desc:
                                        metadata.file_description = desc

                                if not metadata.product_name:
                                    prod_name = win32api.GetFileVersionInfo(
                                        metadata.file_path, base + "ProductName"
                                    )
                                    if prod_name:
                                        metadata.product_name = prod_name

                                if not metadata.legal_copyright:
                                    copyright = win32api.GetFileVersionInfo(
                                        metadata.file_path, base + "LegalCopyright"
                                    )
                                    if copyright:
                                        metadata.legal_copyright = copyright

                                if not metadata.original_filename:
                                    orig_name = win32api.GetFileVersionInfo(
                                        metadata.file_path, base + "OriginalFilename"
                                    )
                                    if orig_name:
                                        metadata.original_filename = orig_name

                                if not metadata.internal_name:
                                    internal = win32api.GetFileVersionInfo(
                                        metadata.file_path, base + "InternalName"
                                    )
                                    if internal:
                                        metadata.internal_name = internal

                                # If we extracted fields, consider it successful
                                if (
                                    metadata.file_version
                                    or metadata.product_version
                                    or metadata.company_name
                                    or metadata.file_description
                                ):
                                    return True

                        except Exception:
                            # Try next language/codepage combination
                            continue

            except Exception:
                # String info extraction failed, but we might still have version numbers
                pass

            # Return True if we extracted any version information
            result = bool(
                metadata.file_version
                or metadata.product_version
                or metadata.company_name
                or metadata.file_description
            )

            if result:
                self.logger.debug(
                    f"win32api extraction succeeded for {metadata.file_name}"
                )
            else:
                self.logger.debug(
                    f"win32api extraction found no version info for {metadata.file_name}"
                )

            return result

        except Exception as e:
            # win32api extraction failed, let other methods handle it
            self.logger.debug(
                f"win32api extraction failed for {metadata.file_name}: {str(e)}"
            )
            return False

    def _extract_version_info_fileinfo(
        self, pe: "pefile.PE", metadata: DLLMetadata
    ) -> bool:
        """
        Extract version information using FileInfo approach.
        This alternative method may work better for some Microsoft DLLs.

        Args:
            pe: PE file object
            metadata: DLL metadata to populate

        Returns:
            True if version information was successfully extracted, False otherwise
        """
        if not hasattr(pe, "FileInfo") or not pe.FileInfo:
            self.logger.debug(f"No FileInfo available for {metadata.file_name}")
            return False

        extracted = False
        self.logger.debug(
            f"Attempting FileInfo version extraction for {metadata.file_name}"
        )

        try:
            for fileinfo in pe.FileInfo:
                if fileinfo.Key != b"StringFileInfo":
                    continue

                # Iterate all StringTables (multiple translations)
                for st in fileinfo.StringTable:
                    for key, value in st.entries.items():
                        decoded_key = (
                            key.decode(errors="ignore")
                            if isinstance(key, bytes)
                            else str(key)
                        )
                        decoded_value = (
                            value.decode(errors="ignore")
                            if isinstance(value, bytes)
                            else str(value)
                        )

                        if decoded_key == "FileVersion":
                            metadata.file_version = decoded_value
                            extracted = True
                        elif decoded_key == "ProductVersion":
                            metadata.product_version = decoded_value
                            extracted = True
                        elif decoded_key == "CompanyName":
                            metadata.company_name = decoded_value
                            extracted = True
                        elif decoded_key == "FileDescription":
                            metadata.file_description = decoded_value
                            extracted = True
                        elif decoded_key == "OriginalFilename":
                            metadata.original_filename = decoded_value
                            extracted = True
                        elif decoded_key == "ProductName":
                            metadata.product_name = decoded_value
                            extracted = True
                        elif decoded_key == "InternalName":
                            metadata.internal_name = decoded_value
                            extracted = True
                        elif decoded_key == "LegalCopyright":
                            metadata.legal_copyright = decoded_value
                            extracted = True

                    # If we found version info, check if we have essential fields
                    if (
                        metadata.file_version
                        or metadata.product_version
                        or metadata.company_name
                        or metadata.file_description
                        or metadata.original_filename
                    ):
                        return True

        except Exception as e:
            # If FileInfo approach fails, let the fallback handle it
            self.logger.debug(
                f"FileInfo extraction failed for {metadata.file_name}: {str(e)}"
            )
            pass

        if extracted:
            self.logger.debug(f"FileInfo extraction succeeded for {metadata.file_name}")
        else:
            self.logger.debug(
                f"FileInfo extraction found no version info for {metadata.file_name}"
            )

        return extracted

    def _get_version_translations(self, version_info: Any) -> List[str]:
        """
        Extract available translations from VarFileInfo to find correct string tables.

        Returns:
            List of translation keys (e.g., ["040904b0", "040004b0"])
        """
        translation_keys = []

        try:
            if hasattr(version_info, "VarFileInfo"):
                for var_file_info in version_info.VarFileInfo:
                    if hasattr(var_file_info, "Var"):
                        for var in var_file_info.Var:
                            if hasattr(var, "entry") and var.entry:
                                # Each translation entry contains language and codepage
                                for lang_codepage in var.entry:
                                    if hasattr(lang_codepage, "lang") and hasattr(
                                        lang_codepage, "codepage"
                                    ):
                                        # Format: language (2 bytes) + codepage
                                        # (2 bytes) as hex
                                        lang = lang_codepage.lang & 0xFFFF
                                        codepage = lang_codepage.codepage & 0xFFFF
                                        translation_key = f"{lang:04x}{codepage:04x}"
                                        translation_keys.append(translation_key)
        except Exception:
            # Ignore errors in translation extraction, fallback will handle it
            pass

        return translation_keys

    def _extract_string_version_info(
        self, version_info: Any, metadata: DLLMetadata, translation_key: str
    ) -> bool:
        """
        Extract string version information using a specific translation key.

        Args:
            version_info: PE version info structure
            metadata: DLL metadata to populate
            translation_key: Translation key (e.g., "040904b0")

        Returns:
            True if extraction was successful, False otherwise
        """
        try:
            if hasattr(version_info, "StringFileInfo"):
                for string_file_info in version_info.StringFileInfo:
                    # Look for the specific string table that matches our translation
                    for string_table in string_file_info.StringTable:
                        # Check if this string table matches our translation key
                        if (
                            hasattr(string_table, "LangID")
                            and string_table.LangID.lower() == translation_key.lower()
                        ):
                            return self._process_string_table_entries(
                                string_table, metadata
                            )
        except Exception:
            pass

        return False

    def _extract_string_version_info_fallback(
        self, version_info: Any, metadata: DLLMetadata
    ) -> None:
        """
        Fallback method for extracting string version info when translation
        lookup fails. This is the original logic for compatibility with
        third-party DLLs.
        """
        try:
            if hasattr(version_info, "StringFileInfo"):
                for string_file_info in version_info.StringFileInfo:
                    for string_table in string_file_info.StringTable:
                        self._process_string_table_entries(string_table, metadata)
        except Exception:
            pass

    def _process_string_table_entries(
        self, string_table: Any, metadata: DLLMetadata
    ) -> bool:
        """
        Process entries from a string table and populate metadata.

        Returns:
            True if any version information was extracted
        """
        extracted = False

        try:
            if hasattr(string_table, "entries"):
                for entry in string_table.entries.items():
                    key, value = entry
                    key_str = key.decode("utf-8", errors="ignore")
                    value_str = value.decode("utf-8", errors="ignore")

                    if key_str == "ProductName":
                        metadata.product_name = value_str
                        extracted = True
                    elif key_str == "ProductVersion":
                        metadata.product_version = value_str
                        extracted = True
                    elif key_str == "FileVersion":
                        metadata.file_version = value_str
                        extracted = True
                    elif key_str == "CompanyName":
                        metadata.company_name = value_str
                        extracted = True
                    elif key_str == "FileDescription":
                        metadata.file_description = value_str
                        extracted = True
                    elif key_str == "InternalName":
                        metadata.internal_name = value_str
                        extracted = True
                    elif key_str == "LegalCopyright":
                        metadata.legal_copyright = value_str
                        extracted = True
                    elif key_str == "OriginalFilename":
                        metadata.original_filename = value_str
                        extracted = True
                    # Handle additional version variants that might appear in
                    # Windows Properties
                    elif key_str == "Version" and not metadata.file_version:
                        metadata.file_version = value_str
                        extracted = True
                    elif key_str == "Assembly Version" and not metadata.file_version:
                        metadata.file_version = value_str
                        extracted = True
                    elif key_str == "PrivateBuild" and not metadata.file_version:
                        metadata.file_version = value_str
                        extracted = True
                    elif key_str == "LegalTrademarks":
                        # Some DLLs have trademark info that might be useful
                        pass
        except Exception:
            pass

        return extracted

    def _extract_import_export_info(
        self, pe: "pefile.PE", metadata: DLLMetadata
    ) -> None:
        """Extract import and export information."""
        try:
            # Extract imported DLLs
            imported_dlls = set()
            if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll_name = entry.dll.decode("utf-8", errors="ignore")
                    imported_dlls.add(dll_name)
            metadata.imported_dlls = sorted(list(imported_dlls))

            # Extract exported functions
            exported_functions = []
            if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
                for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                    if exp.name:
                        func_name = exp.name.decode("utf-8", errors="ignore")
                        exported_functions.append(func_name)
            metadata.exported_functions = sorted(exported_functions)

        except Exception as e:
            metadata.analysis_errors.append(
                f"Import/Export extraction failed: {str(e)}"
            )

    def _extract_security_info(self, pe: "pefile.PE", metadata: DLLMetadata) -> None:
        """Extract security and integrity information."""
        try:
            # Check if file is signed (has security directory)
            if hasattr(pe, "OPTIONAL_HEADER") and hasattr(
                pe.OPTIONAL_HEADER, "DATA_DIRECTORY"
            ):
                security_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[
                    4
                ]  # Security directory
                metadata.is_signed = security_dir.Size > 0

            # Calculate checksum
            if hasattr(pe, "OPTIONAL_HEADER"):
                metadata.checksum = f"0x{pe.OPTIONAL_HEADER.CheckSum:08x}"

        except Exception as e:
            metadata.analysis_errors.append(
                f"Security info extraction failed: {str(e)}"
            )


def extract_dll_metadata(
    dll_path: Path, extraction_methods: Optional[Set[ExtractionMethod]] = None
) -> DLLMetadata:
    """
    Convenience function to extract metadata from a DLL file.

    Args:
        dll_path: Path to the DLL file
        extraction_methods: Optional set of extraction methods to use

    Returns:
        DLLMetadata object containing extracted information
    """
    extractor = DLLMetadataExtractor(extraction_methods)
    return extractor.extract_metadata(dll_path)
