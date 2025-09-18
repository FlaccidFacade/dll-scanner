"""
Page generation utilities for GitHub Pages.
"""

import json
import shutil
from pathlib import Path
from typing import Dict, Any, Optional, List
from datetime import datetime

from .metadata import DLLMetadata
from .scanner import ScanResult


class PageGenerator:
    """Generate dynamic content for GitHub Pages."""

    def __init__(self, pages_dir: Optional[Path] = None):
        """Initialize the page generator.

        Args:
            pages_dir: Path to the pages directory. If None, uses default location.
        """
        if pages_dir is None:
            # Find pages directory relative to this module
            module_path = Path(__file__).parent.parent.parent
            pages_dir = module_path / "pages"

        self.pages_dir = Path(pages_dir)
        self.ensure_pages_directory()

    def ensure_pages_directory(self) -> None:
        """Ensure pages directory structure exists."""
        required_dirs = [
            self.pages_dir,
            self.pages_dir / "data",
            self.pages_dir / "generated",
        ]

        for dir_path in required_dirs:
            dir_path.mkdir(parents=True, exist_ok=True)

    def generate_scan_result_page(
        self,
        scan_result: ScanResult,
        project_name: str,
        output_filename: Optional[str] = None,
    ) -> Path:
        """Generate a standalone HTML page for scan results.

        Args:
            scan_result: The scan result to generate a page for
            project_name: Name of the project being scanned
            output_filename: Optional custom filename for the output

        Returns:
            Path to the generated HTML file
        """
        if output_filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_filename = f"scan_result_{timestamp}.html"

        # Save scan data as JSON
        data_filename = output_filename.replace(".html", ".json")
        data_path = self.pages_dir / "data" / data_filename

        with open(data_path, "w", encoding="utf-8") as f:
            json.dump(scan_result.to_dict(), f, indent=2, default=str)

        # Generate HTML page
        html_content = self._generate_scan_result_html(
            project_name, f"data/{data_filename}", scan_result
        )

        output_path = self.pages_dir / "generated" / output_filename
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html_content)

        return output_path

    def _generate_scan_result_html(
        self, project_name: str, data_url: str, scan_result: ScanResult
    ) -> str:
        """Generate HTML content for a scan result page."""

        summary_stats = self._calculate_summary_stats(scan_result)

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DLL Scanner - {project_name} Results</title>
    <link rel="stylesheet" href="../styles/main.css">
    <link rel="icon" type="image/svg+xml" href="../assets/favicon.svg">
</head>
<body>
    <header class="header">
        <div class="container">
            <nav class="nav">
                <div class="nav-brand">
                    <h1>🔍 DLL Scanner</h1>
                </div>
                <ul class="nav-links">
                    <li><a href="../index.html">Home</a></li>
                    <li><a href="../scan-results.html">Scan Results</a></li>
                    <li><a href="../changelog.html">Changelog</a></li>
                    <li><a href="https://github.com/FlaccidFacade/dll-scanner" target="_blank">GitHub</a></li>
                </ul>
            </nav>
        </div>
    </header>

    <main class="main">
        <div class="container">
            <div class="page-header">
                <h2>📊 Scan Results: {project_name}</h2>
                <p>Generated on {datetime.now().strftime("%Y-%m-%d at %H:%M:%S")}</p>
            </div>

            <!-- Quick Stats -->
            <section class="summary-section">
                <div class="summary-cards">
                    <div class="summary-card">
                        <div class="summary-icon">📁</div>
                        <div class="summary-content">
                            <h3>{scan_result.total_files_scanned}</h3>
                            <p>Files Scanned</p>
                        </div>
                    </div>
                    <div class="summary-card">
                        <div class="summary-icon">🔧</div>
                        <div class="summary-content">
                            <h3>{scan_result.total_dlls_found}</h3>
                            <p>DLLs Found</p>
                        </div>
                    </div>
                    <div class="summary-card">
                        <div class="summary-icon">⏱️</div>
                        <div class="summary-content">
                            <h3>{scan_result.scan_duration_seconds:.1f}s</h3>
                            <p>Scan Duration</p>
                        </div>
                    </div>
                    <div class="summary-card">
                        <div class="summary-icon">🛡️</div>
                        <div class="summary-content">
                            <h3>{summary_stats['signed_count']}</h3>
                            <p>Signed DLLs</p>
                        </div>
                    </div>
                </div>
            </section>

            <!-- Architecture Breakdown -->
            <section class="stats-section">
                <div class="container">
                    <h3>Architecture Distribution</h3>
                    <div class="stats-grid">
                        {self._generate_arch_stats_html(summary_stats['architectures'])}
                    </div>
                </div>
            </section>

            <!-- Actions -->
            <section class="actions-section">
                <div class="container">
                    <h3>Actions</h3>
                    <div class="action-buttons">
                        <a href="../scan-results.html?url={data_url}" class="btn btn-primary">
                            Open in Interactive Viewer
                        </a>
                        <a href="{data_url}" class="btn btn-outline" download>
                            Download JSON Data
                        </a>
                        <button onclick="navigator.share({{title: 'DLL Scanner Results - {project_name}', url: window.location.href}})" class="btn btn-outline">
                            Share Results
                        </button>
                    </div>
                </div>
            </section>
        </div>
    </main>

    <footer class="footer">
        <div class="container">
            <div class="footer-content">
                <p>&copy; 2024 DLL Scanner Contributors. Licensed under MIT License.</p>
                <div class="footer-links">
                    <a href="https://github.com/FlaccidFacade/dll-scanner/issues" target="_blank">Report Issues</a>
                    <a href="https://github.com/FlaccidFacade/dll-scanner/blob/main/CONTRIBUTING.md" target="_blank">Contributing</a>
                    <a href="https://github.com/FlaccidFacade/dll-scanner/blob/main/LICENSE" target="_blank">License</a>
                </div>
            </div>
        </div>
    </footer>

    <script src="../js/main.js"></script>
    <style>
        .stats-section {{
            background: white;
            padding: 2rem;
            border-radius: 12px;
            margin: 2rem 0;
        }}
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 1rem;
            margin-top: 1rem;
        }}
        .stat-item {{
            text-align: center;
            padding: 1rem;
            background: #f8f9fa;
            border-radius: 8px;
        }}
        .stat-value {{
            font-size: 1.5rem;
            font-weight: 700;
            color: #4f46e5;
        }}
        .stat-label {{
            color: #6b7280;
            font-size: 0.9rem;
        }}
        .actions-section {{
            background: white;
            padding: 2rem;
            border-radius: 12px;
            margin: 2rem 0;
        }}
        .action-buttons {{
            display: flex;
            gap: 1rem;
            flex-wrap: wrap;
            margin-top: 1rem;
        }}
    </style>
</body>
</html>"""

    def _calculate_summary_stats(self, scan_result: ScanResult) -> Dict[str, Any]:
        """Calculate summary statistics from scan result."""
        architectures: Dict[str, int] = {}
        signed_count = 0

        for dll in scan_result.dll_files:
            # Count architectures
            arch = dll.architecture or "Unknown"
            architectures[arch] = architectures.get(arch, 0) + 1

            # Count signed DLLs
            if dll.is_signed:
                signed_count += 1

        return {
            "architectures": architectures,
            "signed_count": signed_count,
            "unsigned_count": len(scan_result.dll_files) - signed_count,
        }

    def _generate_arch_stats_html(self, architectures: Dict[str, int]) -> str:
        """Generate HTML for architecture statistics."""
        html = ""
        for arch, count in architectures.items():
            html += f"""
                <div class="stat-item">
                    <div class="stat-value">{count}</div>
                    <div class="stat-label">{arch}</div>
                </div>
            """
        return html

    def generate_changelog_data(self, changelog_path: Optional[Path] = None) -> Path:
        """Generate JSON data from CHANGELOG.md for the changelog page.

        Args:
            changelog_path: Path to CHANGELOG.md file

        Returns:
            Path to the generated JSON file
        """
        if changelog_path is None:
            changelog_path = Path(__file__).parent.parent.parent / "CHANGELOG.md"

        if not changelog_path.exists():
            raise FileNotFoundError(f"Changelog not found at {changelog_path}")

        # Parse changelog
        changelog_data = self._parse_changelog(changelog_path)

        # Save as JSON
        output_path = self.pages_dir / "data" / "changelog.json"
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(changelog_data, f, indent=2, default=str)

        return output_path

    def _parse_changelog(self, changelog_path: Path) -> List[Dict[str, Any]]:
        """Parse CHANGELOG.md into structured data."""
        with open(changelog_path, "r", encoding="utf-8") as f:
            content = f.read()

        entries: List[Dict[str, Any]] = []
        lines = content.split("\n")
        current_entry: Optional[Dict[str, Any]] = None
        current_section: Optional[str] = None

        for line in lines:
            line = line.strip()

            # Version header: ## [version] - date
            if line.startswith("## [") and "] -" in line:
                if current_entry:
                    entries.append(current_entry)

                # Extract version and date
                version_part = line[4:]  # Remove "## ["
                version_end = version_part.find("]")
                version = version_part[:version_end]
                date = version_part[version_end + 3 :].strip()  # Remove "] - "

                current_entry = {
                    "version": version,
                    "date": date,
                    "sections": {},
                    "timestamp": datetime.now().isoformat(),
                }
                current_section = None
                continue

            # Section header: ### Added, ### Changed, etc.
            if line.startswith("### ") and current_entry:
                section_name = line[4:].strip().lower()
                current_section = section_name
                current_entry["sections"][section_name] = []
                continue

            # List items
            if line.startswith("- ") and current_entry and current_section:
                item = line[2:].strip()
                current_entry["sections"][current_section].append(item)

        if current_entry:
            entries.append(current_entry)

        return entries

    def copy_static_assets(self, destination: Path) -> None:
        """Copy static assets to destination directory.

        Args:
            destination: Directory to copy assets to
        """
        assets_source = self.pages_dir

        # Copy entire pages directory structure
        if destination.exists():
            shutil.rmtree(destination)

        shutil.copytree(assets_source, destination)

    def create_index_redirect(self, destination: Path) -> None:
        """Create an index.html that redirects to pages/index.html.

        Args:
            destination: Directory to create index.html in
        """
        index_html = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DLL Scanner</title>
    <meta http-equiv="refresh" content="0; url=pages/index.html">
    <link rel="canonical" href="pages/index.html">
</head>
<body>
    <p>Redirecting to <a href="pages/index.html">DLL Scanner</a>...</p>
</body>
</html>"""

        with open(destination / "index.html", "w", encoding="utf-8") as f:
            f.write(index_html)
