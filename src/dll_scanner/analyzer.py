"""
Static code analysis functionality for confirming DLL dependencies.
"""

import re
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
import logging

from .metadata import DLLMetadata


@dataclass
class DependencyMatch:
    """Represents a found dependency reference in source code."""

    file_path: str
    line_number: int
    line_content: str
    match_type: str  # 'import', 'loadlibrary', 'getprocaddress', 'pragma', etc.
    dll_name: str
    confidence: float  # 0.0 to 1.0


@dataclass
class AnalysisResult:
    """Result of dependency analysis."""

    dll_metadata: DLLMetadata
    confirmed_dependencies: List[DependencyMatch]
    potential_dependencies: List[DependencyMatch]
    source_files_analyzed: int
    analysis_confidence: float


class DependencyAnalyzer:
    """Analyzes source code to confirm DLL dependencies through static analysis."""

    # File extensions to analyze
    SOURCE_EXTENSIONS = {
        ".c",
        ".cpp",
        ".cc",
        ".cxx",
        ".c++",  # C/C++
        ".h",
        ".hpp",
        ".hh",
        ".hxx",
        ".h++",  # Headers
        ".cs",  # C#
        ".py",  # Python
        ".java",  # Java
        ".js",
        ".ts",  # JavaScript/TypeScript
        ".go",  # Go
        ".rs",  # Rust
        ".php",  # PHP
        ".rb",  # Ruby
    }

    def __init__(self, logger: Optional[logging.Logger] = None):
        """
        Initialize dependency analyzer.

        Args:
            logger: Optional logger for debug information
        """
        self.logger = logger or logging.getLogger(__name__)

        # Compile regex patterns for better performance
        self._compile_patterns()

    def _compile_patterns(self):
        """Compile regex patterns for dependency detection."""
        # C/C++ patterns
        self.loadlibrary_pattern = re.compile(
            r'LoadLibrary[AW]?\s*\(\s*["\']([^"\']+\.dll)["\']', re.IGNORECASE
        )

        self.getprocaddress_pattern = re.compile(
            r'GetProcAddress\s*\([^,]+,\s*["\']([^"\']+)["\']', re.IGNORECASE
        )

        self.pragma_pattern = re.compile(
            r'#pragma\s+comment\s*\(\s*lib\s*,\s*["\']([^"\']+\.lib)["\']',
            re.IGNORECASE,
        )

        self.include_pattern = re.compile(
            r'#include\s*[<"]([^>"]+\.h)[>"]', re.IGNORECASE
        )

        # C# patterns
        self.dllimport_pattern = re.compile(
            r'\[DllImport\s*\(\s*["\']([^"\']+\.dll)["\']', re.IGNORECASE
        )

        # Python patterns
        self.python_ctypes_pattern = re.compile(
            r"ctypes\.(?:windll|cdll|oledll)\.([^.\s]+)", re.IGNORECASE
        )

        self.python_loadlibrary_pattern = re.compile(
            r'LoadLibrary\s*\(\s*["\']([^"\']+\.dll)["\']', re.IGNORECASE
        )

        # Generic DLL reference patterns
        self.dll_reference_pattern = re.compile(
            r'["\']([^"\']*\.dll)["\']', re.IGNORECASE
        )

        # Function export patterns (for checking if functions are used)
        self.function_call_pattern = re.compile(
            r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(", re.IGNORECASE
        )

    def analyze_dll_dependencies(
        self, dll_metadata: DLLMetadata, source_directory: Path, recursive: bool = True
    ) -> AnalysisResult:
        """
        Analyze source code to confirm DLL dependencies.

        Args:
            dll_metadata: Metadata of the DLL to analyze
            source_directory: Directory containing source code
            recursive: Whether to search subdirectories

        Returns:
            AnalysisResult containing confirmed and potential dependencies
        """
        if not source_directory.exists():
            raise FileNotFoundError(f"Source directory not found: {source_directory}")

        self.logger.info(f"Analyzing dependencies for {dll_metadata.file_name}")

        # Find source files
        source_files = self._find_source_files(source_directory, recursive)
        self.logger.info(f"Found {len(source_files)} source files to analyze")

        confirmed_dependencies = []
        potential_dependencies = []

        # Analyze each source file
        for source_file in source_files:
            try:
                matches = self._analyze_source_file(source_file, dll_metadata)

                for match in matches:
                    if match.confidence >= 0.8:
                        confirmed_dependencies.append(match)
                    else:
                        potential_dependencies.append(match)

            except Exception as e:
                self.logger.error(f"Failed to analyze {source_file}: {str(e)}")

        # Calculate overall analysis confidence
        total_matches = len(confirmed_dependencies) + len(potential_dependencies)
        if total_matches == 0:
            analysis_confidence = 0.0
        else:
            avg_confidence = (
                sum(
                    m.confidence
                    for m in confirmed_dependencies + potential_dependencies
                )
                / total_matches
            )
            analysis_confidence = min(avg_confidence, 1.0)

        return AnalysisResult(
            dll_metadata=dll_metadata,
            confirmed_dependencies=confirmed_dependencies,
            potential_dependencies=potential_dependencies,
            source_files_analyzed=len(source_files),
            analysis_confidence=analysis_confidence,
        )

    def _find_source_files(self, directory: Path, recursive: bool) -> List[Path]:
        """Find source code files to analyze."""
        source_files = []

        if recursive:
            for ext in self.SOURCE_EXTENSIONS:
                pattern = f"**/*{ext}"
                source_files.extend(directory.rglob(pattern))
        else:
            for ext in self.SOURCE_EXTENSIONS:
                pattern = f"*{ext}"
                source_files.extend(directory.glob(pattern))

        return [f for f in source_files if f.is_file()]

    def _analyze_source_file(
        self, source_file: Path, dll_metadata: DLLMetadata
    ) -> List[DependencyMatch]:
        """Analyze a single source file for DLL dependencies."""
        matches = []

        try:
            with open(source_file, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()

            for line_num, line in enumerate(lines, 1):
                line_matches = self._analyze_line(
                    line, line_num, source_file, dll_metadata
                )
                matches.extend(line_matches)

        except Exception as e:
            self.logger.error(f"Error reading {source_file}: {str(e)}")

        return matches

    def _analyze_line(
        self, line: str, line_num: int, source_file: Path, dll_metadata: DLLMetadata
    ) -> List[DependencyMatch]:
        """Analyze a single line of source code."""
        matches = []
        dll_name = dll_metadata.file_name

        # High confidence patterns

        # LoadLibrary calls
        for match in self.loadlibrary_pattern.finditer(line):
            referenced_dll = match.group(1)
            if self._dll_names_match(referenced_dll, dll_name):
                matches.append(
                    DependencyMatch(
                        file_path=str(source_file),
                        line_number=line_num,
                        line_content=line.strip(),
                        match_type="loadlibrary",
                        dll_name=referenced_dll,
                        confidence=0.95,
                    )
                )

        # DllImport attributes (C#)
        for match in self.dllimport_pattern.finditer(line):
            referenced_dll = match.group(1)
            if self._dll_names_match(referenced_dll, dll_name):
                matches.append(
                    DependencyMatch(
                        file_path=str(source_file),
                        line_number=line_num,
                        line_content=line.strip(),
                        match_type="dllimport",
                        dll_name=referenced_dll,
                        confidence=0.95,
                    )
                )

        # Pragma lib comments
        for match in self.pragma_pattern.finditer(line):
            lib_name = match.group(1)
            # Convert .lib to .dll for comparison
            dll_equivalent = lib_name.replace(".lib", ".dll")
            if self._dll_names_match(dll_equivalent, dll_name):
                matches.append(
                    DependencyMatch(
                        file_path=str(source_file),
                        line_number=line_num,
                        line_content=line.strip(),
                        match_type="pragma_lib",
                        dll_name=dll_equivalent,
                        confidence=0.9,
                    )
                )

        # Python ctypes patterns
        for match in self.python_ctypes_pattern.finditer(line):
            referenced_dll = match.group(1) + ".dll"
            if self._dll_names_match(referenced_dll, dll_name):
                matches.append(
                    DependencyMatch(
                        file_path=str(source_file),
                        line_number=line_num,
                        line_content=line.strip(),
                        match_type="python_ctypes",
                        dll_name=referenced_dll,
                        confidence=0.9,
                    )
                )

        # Medium confidence patterns

        # Function calls that match exported functions
        if dll_metadata.exported_functions:
            for exported_func in dll_metadata.exported_functions:
                if exported_func in line:
                    # Look for function call pattern
                    func_pattern = re.compile(rf"\b{re.escape(exported_func)}\s*\(")
                    if func_pattern.search(line):
                        matches.append(
                            DependencyMatch(
                                file_path=str(source_file),
                                line_number=line_num,
                                line_content=line.strip(),
                                match_type="function_call",
                                dll_name=dll_name,
                                confidence=0.7,
                            )
                        )

        # Low confidence patterns

        # Generic DLL references
        for match in self.dll_reference_pattern.finditer(line):
            referenced_dll = match.group(1)
            if self._dll_names_match(referenced_dll, dll_name):
                # Check if it's not already found by high-confidence patterns
                existing_types = {
                    m.match_type for m in matches if m.line_number == line_num
                }
                if not existing_types.intersection(
                    {"loadlibrary", "dllimport", "pragma_lib"}
                ):
                    matches.append(
                        DependencyMatch(
                            file_path=str(source_file),
                            line_number=line_num,
                            line_content=line.strip(),
                            match_type="generic_reference",
                            dll_name=referenced_dll,
                            confidence=0.4,
                        )
                    )

        return matches

    def _dll_names_match(self, name1: str, name2: str) -> bool:
        """Check if two DLL names match (case-insensitive)."""
        if not name1 or not name2:
            return False

        # Normalize names
        norm1 = name1.lower().replace(".dll", "")
        norm2 = name2.lower().replace(".dll", "")

        return norm1 == norm2

    def generate_dependency_report(
        self, analysis_results: List[AnalysisResult]
    ) -> Dict[str, Any]:
        """
        Generate a comprehensive dependency analysis report.

        Args:
            analysis_results: List of analysis results for multiple DLLs

        Returns:
            Dictionary containing the dependency report
        """
        total_dlls = len(analysis_results)
        total_confirmed = sum(
            len(result.confirmed_dependencies) for result in analysis_results
        )
        total_potential = sum(
            len(result.potential_dependencies) for result in analysis_results
        )

        # DLLs with confirmed dependencies
        confirmed_dlls = [
            result for result in analysis_results if result.confirmed_dependencies
        ]

        # DLLs with no evidence of use
        unused_dlls = [
            result
            for result in analysis_results
            if not result.confirmed_dependencies and not result.potential_dependencies
        ]

        # Analysis by file type
        file_type_analysis = {}
        for result in analysis_results:
            for dep in result.confirmed_dependencies + result.potential_dependencies:
                ext = Path(dep.file_path).suffix.lower()
                if ext not in file_type_analysis:
                    file_type_analysis[ext] = {"confirmed": 0, "potential": 0}

                if dep in result.confirmed_dependencies:
                    file_type_analysis[ext]["confirmed"] += 1
                else:
                    file_type_analysis[ext]["potential"] += 1

        return {
            "summary": {
                "total_dlls_analyzed": total_dlls,
                "dlls_with_confirmed_usage": len(confirmed_dlls),
                "dlls_potentially_unused": len(unused_dlls),
                "total_confirmed_dependencies": total_confirmed,
                "total_potential_dependencies": total_potential,
            },
            "confirmed_dlls": [
                {
                    "dll_name": result.dll_metadata.file_name,
                    "dll_path": result.dll_metadata.file_path,
                    "confirmed_references": len(result.confirmed_dependencies),
                    "analysis_confidence": result.analysis_confidence,
                }
                for result in confirmed_dlls
            ],
            "potentially_unused_dlls": [
                {
                    "dll_name": result.dll_metadata.file_name,
                    "dll_path": result.dll_metadata.file_path,
                    "file_size": result.dll_metadata.file_size,
                    "company": result.dll_metadata.company_name,
                }
                for result in unused_dlls
            ],
            "analysis_by_file_type": file_type_analysis,
            "detailed_results": [
                {
                    "dll_name": result.dll_metadata.file_name,
                    "confirmed_dependencies": [
                        {
                            "file": dep.file_path,
                            "line": dep.line_number,
                            "type": dep.match_type,
                            "confidence": dep.confidence,
                        }
                        for dep in result.confirmed_dependencies
                    ],
                    "potential_dependencies": [
                        {
                            "file": dep.file_path,
                            "line": dep.line_number,
                            "type": dep.match_type,
                            "confidence": dep.confidence,
                        }
                        for dep in result.potential_dependencies
                    ],
                }
                for result in analysis_results
            ],
        }
