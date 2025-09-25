"""
Test file logging functionality for version extraction.
"""

import logging
import tempfile
from pathlib import Path
from typing import Tuple
from unittest.mock import MagicMock, patch

from dll_scanner.cli import setup_logging
from dll_scanner.metadata import DLLMetadataExtractor
from dll_scanner.scanner import DLLScanner


def _get_log_file_path() -> Tuple[Path, Path]:
    """Helper function to get the log directory and file path."""
    log_dir = Path.home() / ".dll-scanner" / "logs"
    log_file = log_dir / "dll_version_extraction.log"
    return log_dir, log_file


def _cleanup_log_file() -> None:
    """Helper function to clean up the log file if it exists."""
    log_dir, log_file = _get_log_file_path()
    if log_file.exists():
        log_file.unlink()


def test_setup_logging_creates_file_handler():
    """Test that setup_logging creates a file handler for version extraction logs."""

    # Clear any existing handlers
    logger_name = "dll_scanner"
    logger = logging.getLogger(logger_name)
    for handler in logger.handlers[:]:
        handler.close()
        logger.removeHandler(handler)

    try:
        # Call setup_logging
        logger = setup_logging(verbose=False)

        # Check that log directory and file are created
        log_dir, log_file = _get_log_file_path()

        assert log_dir.exists(), "Log directory should be created"
        assert log_file.exists(), "Log file should be created"

        # Check that file handler was added
        logger = logging.getLogger(logger_name)
        file_handlers = [
            h for h in logger.handlers if isinstance(h, logging.FileHandler)
        ]
        assert len(file_handlers) >= 1, "At least one file handler should be added"

    finally:
        # Clean up handlers
        for handler in logger.handlers[:]:
            handler.close()
            logger.removeHandler(handler)


def test_version_extraction_logging():
    """Test that version extraction attempts are logged to file."""

    # Clear any existing handlers from previous tests
    logger_name = "dll_scanner"
    logger = logging.getLogger(logger_name)
    for handler in logger.handlers[:]:
        handler.close()
        logger.removeHandler(handler)

    # Clear existing log file
    _cleanup_log_file()

    # Get log file path for later use
    log_dir, log_file = _get_log_file_path()

    # Set up logging first
    logger = setup_logging(verbose=True)

    # Create a temporary DLL file
    with tempfile.NamedTemporaryFile(suffix=".dll", delete=False) as tmp_file:
        tmp_file.write(b"MZ" + b"\x00" * 100)  # Minimal fake DLL header
        dll_path = Path(tmp_file.name)

    try:
        # Test version extraction logging
        with patch("dll_scanner.metadata.pefile") as mock_pefile_module:
            # Create mock PE object
            mock_pe = MagicMock()
            mock_pe.close.return_value = None
            mock_pe.VS_VERSIONINFO = []
            mock_pe.FileInfo = None
            mock_pefile_module.PE.return_value = mock_pe

            # Create extractor with logger and extract metadata
            extractor = DLLMetadataExtractor(logger=logger)
            metadata = extractor.extract_metadata(dll_path)

            # Verify metadata was created
            assert metadata is not None
            assert metadata.file_name == dll_path.name

        # Check that log file contains version extraction logs
        assert log_file.exists(), "Log file should be created"

        with open(log_file, "r") as f:
            log_content = f.read()

            # Verify key logging messages are present
            assert "Starting version info extraction" in log_content
            assert (
                "win32api not available" in log_content
                or "Attempting win32api" in log_content
            )
            assert (
                "No FileInfo available" in log_content
                or "FileInfo extraction" in log_content
            )
            assert (
                "No version information could be extracted" in log_content
                or "Version info extracted" in log_content
            )

    finally:
        # Clean up handlers and temporary file
        for handler in logger.handlers[:]:
            handler.close()
            logger.removeHandler(handler)
        if dll_path.exists():
            dll_path.unlink()


def test_scanner_uses_file_logging():
    """Test that DLL Scanner uses file logging through CLI setup."""

    # Clear any existing handlers from previous tests
    logger_name = "dll_scanner"
    logger = logging.getLogger(logger_name)
    for handler in logger.handlers[:]:
        handler.close()
        logger.removeHandler(handler)

    # Clear existing log file
    _cleanup_log_file()

    # Get log file path for later use
    log_dir, log_file = _get_log_file_path()

    # Set up logging first
    logger = setup_logging(verbose=False)

    # Create a temporary DLL file
    with tempfile.NamedTemporaryFile(suffix=".dll", delete=False) as tmp_file:
        tmp_file.write(b"MZ" + b"\x00" * 100)
        dll_path = Path(tmp_file.name)

    try:
        # Test scanner with file logging
        with patch("dll_scanner.metadata.pefile") as mock_pefile_module:
            mock_pe = MagicMock()
            mock_pe.close.return_value = None
            mock_pe.VS_VERSIONINFO = []
            mock_pe.FileInfo = None
            mock_pefile_module.PE.return_value = mock_pe

            # Use scanner with logger
            scanner = DLLScanner(logger=logger)
            metadata = scanner.scan_file(dll_path)

            assert metadata is not None

        # Verify log file has content
        assert log_file.exists(), "Log file should exist after scanner use"

        with open(log_file, "r") as f:
            log_content = f.read()
            assert len(log_content.strip()) > 0, "Log file should have content"

    finally:
        # Clean up handlers and temporary file
        for handler in logger.handlers[:]:
            handler.close()
            logger.removeHandler(handler)
        if dll_path.exists():
            dll_path.unlink()
