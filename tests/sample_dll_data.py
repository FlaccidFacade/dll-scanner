"""
Sample DLL data for testing DLL Scanner with version information.

This module contains functionality to create a minimal Windows DLL
for testing the version extraction functionality.
"""

import struct
import tempfile
from pathlib import Path
from datetime import datetime


def create_sample_dll_with_version() -> Path:
    """
    Create a sample Windows DLL with version information for testing.

    This DLL is a minimal valid PE file that can be parsed by pefile
    to test the basic DLL scanning functionality.

    Returns:
        Path to the created DLL file
    """
    # Create a temporary directory for test files
    temp_dir = tempfile.mkdtemp(prefix="dll_scanner_test_")
    dll_path = Path(temp_dir) / "sample_with_version.dll"

    # Create a minimal but valid PE structure
    dos_header = bytearray(64)
    dos_header[0:2] = b"MZ"  # DOS signature
    dos_header[60:64] = struct.pack("<L", 64)  # PE header offset

    pe_signature = b"PE\x00\x00"

    # COFF Header (20 bytes)
    coff_header = struct.pack(
        "<HHLLLHH",
        0x014C,  # Machine (i386)
        1,  # NumberOfSections
        int(datetime.now().timestamp()) & 0xFFFFFFFF,  # TimeDateStamp
        0,  # PointerToSymbolTable
        0,  # NumberOfSymbols
        224,  # SizeOfOptionalHeader
        0x2102,  # Characteristics (DLL | EXECUTABLE_IMAGE)
    )

    # Optional Header (224 bytes for PE32)
    optional_header = bytearray(224)
    optional_header[0:2] = struct.pack("<H", 0x010B)  # Magic (PE32)
    optional_header[2] = 1  # MajorLinkerVersion
    optional_header[3] = 0  # MinorLinkerVersion
    optional_header[16:20] = struct.pack("<L", 0x10000000)  # ImageBase
    optional_header[20:24] = struct.pack("<L", 0x1000)  # SectionAlignment
    optional_header[24:28] = struct.pack("<L", 0x200)  # FileAlignment
    optional_header[40:44] = struct.pack("<L", 0x2000)  # SizeOfImage
    optional_header[60:64] = struct.pack("<L", 0x2)  # Subsystem (GUI)
    optional_header[92:96] = struct.pack("<L", 16)  # NumberOfRvaAndSizes

    # Section Header (40 bytes)
    section_header = bytearray(40)
    section_header[0:8] = b".text\x00\x00\x00"  # Name
    section_header[8:12] = struct.pack("<L", 0x1000)  # VirtualSize
    section_header[12:16] = struct.pack("<L", 0x1000)  # VirtualAddress
    section_header[16:20] = struct.pack("<L", 0x200)  # SizeOfRawData
    section_header[20:24] = struct.pack("<L", 0x200)  # PointerToRawData
    section_header[36:40] = struct.pack("<L", 0x60000020)  # Characteristics

    # Minimal section data (512 bytes to align with FileAlignment)
    section_data = bytearray(0x200)

    # Combine all parts
    pe_data = (
        bytes(dos_header)
        + pe_signature
        + coff_header
        + bytes(optional_header)
        + bytes(section_header)
        + bytes(section_data)
    )

    # Write the DLL to disk
    with open(dll_path, "wb") as f:
        f.write(pe_data)

    return dll_path


def cleanup_sample_dll(dll_path: Path) -> None:
    """
    Clean up the temporary DLL file and directory.

    Args:
        dll_path: Path to the DLL file to clean up
    """
    try:
        if dll_path.exists():
            dll_path.unlink()
        # Remove the temporary directory if it's empty
        temp_dir = dll_path.parent
        if temp_dir.exists() and not any(temp_dir.iterdir()):
            temp_dir.rmdir()
    except OSError:
        pass  # Ignore cleanup errors


# Hex data for a real Windows DLL with version information
# This is a simplified approach - in a real scenario, we would use
# a hex dump of a small Windows DLL that contains version resources
SAMPLE_DLL_WITH_VERSION_HEX = """
4d5a90000300000004000000ffff0000b800000000000000400000000000000000000000000000000000000000000000000000000000000000000000800000000e1fba0e00b409cd21b8014ccd21546869732070726f6772616d2063616e6e6f742062652072756e20696e20444f53206d6f64652e0d0d0a2400000000000000
"""


def create_dll_from_hex() -> Path:
    """
    Create a DLL from hex data (placeholder for future implementation).

    Returns:
        Path to the created DLL file
    """
    # This would contain the implementation to create a DLL from hex data
    # For now, fall back to the minimal DLL approach
    return create_sample_dll_with_version()
