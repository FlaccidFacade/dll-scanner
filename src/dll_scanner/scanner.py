"""
DLL scanner functionality for discovering DLL files in directories.
"""

from pathlib import Path
from typing import List, Iterator, Dict, Any, Optional, Callable, Set
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging
from dataclasses import dataclass

from dll_scanner.metadata import DLLMetadata, extract_dll_metadata, ExtractionMethod


@dataclass
class ScanResult:
    """Result of a directory scan operation."""

    # Scan configuration
    scan_path: str
    recursive: bool

    # Results
    dll_files: List[DLLMetadata]
    total_files_scanned: int
    total_dlls_found: int

    # Statistics
    scan_duration_seconds: float
    errors: List[str]

    def to_dict(self) -> Dict[str, Any]:
        """Convert scan result to dictionary."""
        return {
            "scan_path": self.scan_path,
            "recursive": self.recursive,
            "total_files_scanned": self.total_files_scanned,
            "total_dlls_found": self.total_dlls_found,
            "scan_duration_seconds": self.scan_duration_seconds,
            "errors": self.errors,
            "dll_files": [dll.to_dict() for dll in self.dll_files],
        }


class DLLScanner:
    """Scanner for finding and analyzing DLL files in directories."""

    def __init__(
        self,
        max_workers: int = 4,
        progress_callback: Optional[Callable[[str], None]] = None,
        logger: Optional[logging.Logger] = None,
        extraction_methods: Optional[Set[ExtractionMethod]] = None,
    ):
        """
        Initialize DLL scanner.

        Args:
            max_workers: Maximum number of threads for parallel processing
            progress_callback: Optional callback function for progress updates
            logger: Optional logger for debug information
            extraction_methods: Optional set of extraction methods to use
        """
        self.max_workers = max_workers
        self.progress_callback = progress_callback
        self.logger = logger or logging.getLogger(__name__)
        self.extraction_methods = extraction_methods

    def scan_directory(
        self, directory: Path, recursive: bool = True, parallel: bool = True
    ) -> ScanResult:
        """
        Scan a directory for DLL files and extract metadata.

        Args:
            directory: Directory path to scan
            recursive: Whether to scan subdirectories recursively
            parallel: Whether to use parallel processing for metadata extraction

        Returns:
            ScanResult containing all discovered DLL files and their metadata
        """
        import time

        start_time = time.time()

        if not directory.exists():
            raise FileNotFoundError(f"Directory not found: {directory}")

        if not directory.is_dir():
            raise ValueError(f"Path is not a directory: {directory}")

        self.logger.info(f"Starting DLL scan of {directory}")

        # Discover DLL files
        dll_paths = list(self._discover_dll_files(directory, recursive))
        self.logger.info(f"Found {len(dll_paths)} DLL files")

        errors: List[str] = []
        dll_metadata_list: List[DLLMetadata] = []

        if parallel and len(dll_paths) > 1:
            # Parallel processing
            dll_metadata_list, errors = self._extract_metadata_parallel(dll_paths)
        else:
            # Sequential processing
            dll_metadata_list, errors = self._extract_metadata_sequential(dll_paths)

        end_time = time.time()
        duration = end_time - start_time

        result = ScanResult(
            scan_path=str(directory),
            recursive=recursive,
            dll_files=dll_metadata_list,
            total_files_scanned=len(dll_paths),
            total_dlls_found=len(dll_metadata_list),
            scan_duration_seconds=duration,
            errors=errors,
        )

        self.logger.info(f"Scan completed in {duration:.2f} seconds")
        return result

    def _discover_dll_files(self, directory: Path, recursive: bool) -> Iterator[Path]:
        """
        Discover DLL files in the specified directory.

        Args:
            directory: Directory to search
            recursive: Whether to search recursively

        Yields:
            Path objects for discovered DLL files
        """
        if recursive:
            # Use rglob for recursive search
            for dll_path in directory.rglob("*.dll"):
                if dll_path.is_file():
                    if self.progress_callback:
                        self.progress_callback(f"Found: {dll_path.name}")
                    yield dll_path
        else:
            # Search only in the current directory
            for dll_path in directory.glob("*.dll"):
                if dll_path.is_file():
                    if self.progress_callback:
                        self.progress_callback(f"Found: {dll_path.name}")
                    yield dll_path

    def _extract_metadata_sequential(
        self, dll_paths: List[Path]
    ) -> tuple[List[DLLMetadata], List[str]]:
        """
        Extract metadata from DLL files sequentially.

        Args:
            dll_paths: List of DLL file paths

        Returns:
            Tuple of (metadata_list, errors)
        """
        metadata_list = []
        errors = []

        for i, dll_path in enumerate(dll_paths, 1):
            try:
                if self.progress_callback:
                    self.progress_callback(
                        f"Analyzing {dll_path.name} ({i}/{len(dll_paths)})"
                    )


                metadata = extract_dll_metadata(dll_path, self.extraction_methods)
                metadata_list.append(metadata)

            except Exception as e:
                error_msg = f"Failed to analyze {dll_path}: {str(e)}"
                errors.append(error_msg)
                self.logger.error(error_msg)

        return metadata_list, errors

    def _extract_metadata_with_extraction_methods(self, dll_path: Path) -> DLLMetadata:
        """Helper function to extract metadata with extraction methods for parallel processing."""
        return extract_dll_metadata(dll_path, self.extraction_methods)

    def _extract_metadata_parallel(
        self, dll_paths: List[Path]
    ) -> tuple[List[DLLMetadata], List[str]]:
        """
        Extract metadata from DLL files in parallel.

        Args:
            dll_paths: List of DLL file paths

        Returns:
            Tuple of (metadata_list, errors)
        """
        metadata_list = []
        errors = []

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # Submit all tasks
            future_to_path = {
                executor.submit(self._extract_metadata_with_extraction_methods, dll_path): dll_path
                for dll_path in dll_paths
            }

            # Process completed tasks
            for i, future in enumerate(as_completed(future_to_path), 1):
                dll_path = future_to_path[future]

                try:
                    if self.progress_callback:
                        self.progress_callback(
                            f"Analyzed {dll_path.name} ({i}/{len(dll_paths)})"
                        )

                    metadata = future.result()
                    metadata_list.append(metadata)

                except Exception as e:
                    error_msg = f"Failed to analyze {dll_path}: {str(e)}"
                    errors.append(error_msg)
                    self.logger.error(error_msg)

        return metadata_list, errors

    def scan_file(self, dll_path: Path) -> DLLMetadata:
        """
        Scan a single DLL file and extract metadata.

        Args:
            dll_path: Path to the DLL file

        Returns:
            DLLMetadata for the file
        """
        if not dll_path.exists():
            raise FileNotFoundError(f"File not found: {dll_path}")

        if not dll_path.is_file():
            raise ValueError(f"Path is not a file: {dll_path}")

        if not dll_path.suffix.lower() == ".dll":
            raise ValueError(f"File is not a DLL: {dll_path}")
            
        return extract_dll_metadata(dll_path, self.extraction_methods)

    def get_summary_stats(self, scan_result: ScanResult) -> Dict[str, Any]:
        """
        Generate summary statistics from a scan result.

        Args:
            scan_result: Result from a directory scan

        Returns:
            Dictionary containing summary statistics
        """
        if not scan_result.dll_files:
            return {
                "total_dlls": 0,
                "architectures": {},
                "companies": {},
                "most_common_imports": {},
                "signed_dlls": 0,
                "unsigned_dlls": 0,
            }

        # Architecture distribution
        architectures: Dict[str, int] = {}
        for dll in scan_result.dll_files:
            arch = dll.architecture or "Unknown"
            architectures[arch] = architectures.get(arch, 0) + 1

        # Company distribution
        companies: Dict[str, int] = {}
        for dll in scan_result.dll_files:
            company = dll.company_name or "Unknown"
            companies[company] = companies.get(company, 0) + 1

        # Most common imports
        import_counts: Dict[str, int] = {}
        for dll in scan_result.dll_files:
            if dll.imported_dlls:
                for imported_dll in dll.imported_dlls:
                    import_counts[imported_dll] = import_counts.get(imported_dll, 0) + 1

        # Sort and get top 10
        most_common_imports = dict(
            sorted(import_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        )

        # Signature statistics
        signed_count = sum(1 for dll in scan_result.dll_files if dll.is_signed)
        unsigned_count = len(scan_result.dll_files) - signed_count

        return {
            "total_dlls": len(scan_result.dll_files),
            "architectures": architectures,
            "companies": dict(
                sorted(companies.items(), key=lambda x: x[1], reverse=True)[:10]
            ),
            "most_common_imports": most_common_imports,
            "signed_dlls": signed_count,
            "unsigned_dlls": unsigned_count,
            "scan_duration": scan_result.scan_duration_seconds,
            "errors_count": len(scan_result.errors),
        }
