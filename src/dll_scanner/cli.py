"""
Command-line interface for DLL Scanner.
"""

import click
import json
import logging
import sys
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.table import Table
from rich.progress import Progress
from rich.panel import Panel
from rich.text import Text

from . import __version__
from .scanner import DLLScanner, ScanResult
from .analyzer import DependencyAnalyzer, AnalysisResult
from .metadata import DLLMetadata, ExtractionMethod
from .cyclonedx_exporter import CycloneDXExporter
from .page_generator import PageGenerator


def setup_logging(verbose: bool) -> logging.Logger:
    """Set up logging configuration."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        handlers=[logging.StreamHandler()],
    )
    return logging.getLogger("dll_scanner")


def _parse_extraction_methods(methods: tuple[str, ...]) -> set[ExtractionMethod]:
    """Convert CLI extraction method strings to ExtractionMethod enum set."""
    if not methods:
        return {ExtractionMethod.ALL}

    method_map = {
        "win32api": ExtractionMethod.WIN32API,
        "pefile": ExtractionMethod.PEFILE,
        "fileinfo": ExtractionMethod.FILEINFO,
        "all": ExtractionMethod.ALL,
    }

    result = set()
    for method in methods:
        if method.lower() in method_map:
            result.add(method_map[method.lower()])

    return result if result else {ExtractionMethod.ALL}


@click.group()
@click.version_option(version=__version__)
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose output")
@click.pass_context
def cli(ctx: click.Context, verbose: bool) -> None:
    """DLL Scanner - Extract metadata from DLL files and analyze dependencies."""
    ctx.ensure_object(dict)
    ctx.obj["verbose"] = verbose
    ctx.obj["logger"] = setup_logging(verbose)
    ctx.obj["console"] = Console()


@cli.command()
@click.argument(
    "directory", type=click.Path(exists=True, file_okay=False, path_type=Path)
)
@click.option(
    "--recursive/--no-recursive",
    default=True,
    help="Scan subdirectories recursively (default: True)",
)
@click.option(
    "--parallel/--no-parallel",
    default=True,
    help="Use parallel processing (default: True)",
)
@click.option(
    "--output",
    "-o",
    type=click.Path(path_type=Path),
    help="Output file for scan results (JSON format)",
)
@click.option(
    "--max-workers",
    default=4,
    type=int,
    help="Maximum number of worker threads for parallel processing",
)
@click.option(
    "--analyze-dependencies",
    "-a",
    is_flag=True,
    help="Perform static code analysis to confirm dependencies",
)
@click.option(
    "--source-dir",
    type=click.Path(exists=True, file_okay=False, path_type=Path),
    help="Source directory for dependency analysis (required with -a)",
)
@click.option(
    "--cyclonedx",
    is_flag=True,
    help="Export results in CycloneDX SBOM format",
)
@click.option(
    "--project-name",
    default="DLL Analysis Project",
    help="Project name for CycloneDX SBOM (default: 'DLL Analysis Project')",
)
@click.option(
    "--project-version",
    default="1.0.0",
    help="Project version for CycloneDX SBOM (default: '1.0.0')",
)
@click.option(
    "--wix",
    is_flag=True,
    help="Enable WiX metadata extraction for enhanced Windows DLL analysis",
)
@click.option(
    "--extraction-method",
    multiple=True,
    type=click.Choice(["win32api", "pefile", "fileinfo", "all"], case_sensitive=False),
    help="Version extraction method(s) to use. Can specify multiple. Default: all",
)
@click.pass_context
def scan(
    ctx: click.Context,
    directory: Path,
    recursive: bool,
    parallel: bool,
    output: Optional[Path],
    max_workers: int,
    analyze_dependencies: bool,
    source_dir: Optional[Path],
    cyclonedx: bool,
    project_name: str,
    project_version: str,
    wix: bool,
    extraction_method: tuple[str, ...],
) -> None:
    """Scan a directory for DLL files and extract metadata."""
    console: Console = ctx.obj["console"]
    logger: logging.Logger = ctx.obj["logger"]

    if analyze_dependencies and not source_dir:
        console.print(
            "[red]Error: --source-dir is required when using "
            "--analyze-dependencies[/red]"
        )
        sys.exit(1)

    # Parse extraction methods
    extraction_methods = _parse_extraction_methods(extraction_method)

    console.print(f"[bold blue]Scanning directory:[/bold blue] {directory}")
    console.print(f"[blue]Recursive:[/blue] {recursive}")
    console.print(f"[blue]Parallel processing:[/blue] {parallel}")
    console.print(
        f"[blue]Extraction methods:[/blue] {', '.join(m.value for m in extraction_methods)}"
    )
    if analyze_dependencies:
        console.print(
            f"[blue]Dependency analysis:[/blue] Enabled (source: {source_dir})"
        )

    # Create progress callback

    def progress_callback(message: str) -> None:
        if ctx.obj["verbose"]:
            console.print(f"[dim]{message}[/dim]")

    # Initialize scanner
    scanner = DLLScanner(
        max_workers=max_workers,
        progress_callback=progress_callback,
        logger=logger,
        extraction_methods=extraction_methods,
    )

    try:
        # Perform scan
        with console.status("[bold green]Scanning for DLL files..."):
            scan_result = scanner.scan_directory(directory, recursive, parallel)

        # Enhance with WiX metadata if requested
        if wix:
            console.print(f"[blue]WiX enhancement:[/blue] Enabled")
            try:
                from .wix_integration import WiXIntegration

                wix_integration = WiXIntegration(logger=logger)

                if not wix_integration.is_windows():
                    console.print(
                        "[yellow]⚠️  Warning:[/yellow] WiX Toolset is only available on Windows"
                    )
                    console.print("Proceeding with standard scan results...")
                else:
                    if not wix_integration.is_available():
                        console.print(
                            "📥 WiX not available locally, attempting to download..."
                        )
                        if wix_integration.download_wix():
                            console.print(
                                "[green]✅ WiX Toolset downloaded successfully[/green]"
                            )
                        else:
                            console.print(
                                "[yellow]⚠️  Failed to download WiX Toolset, proceeding without WiX enhancement[/yellow]"
                            )

                    if wix_integration.is_available():
                        console.print("🚀 Enhancing scan results with WiX metadata...")
                        scan_result = wix_integration.enhance_scan_result(scan_result)
                        console.print("[green]✅ WiX enhancement completed[/green]")

            except ImportError as e:
                console.print(
                    f"[yellow]Warning:[/yellow] WiX integration not available: {e}"
                )
                console.print("Proceeding with standard scan results...")
            except Exception as e:
                logger.error(f"WiX enhancement failed: {e}")
                console.print(f"[yellow]Warning:[/yellow] WiX enhancement failed: {e}")
                console.print("Proceeding with standard scan results...")

        # Display results
        _display_scan_results(console, scan_result)

        # Perform dependency analysis if requested
        analysis_results = []
        if analyze_dependencies and source_dir:
            console.print(
                "\n[bold yellow]Performing dependency analysis...[/bold yellow]"
            )
            analyzer = DependencyAnalyzer(logger=logger)

            with Progress() as progress:
                task = progress.add_task(
                    "Analyzing dependencies...", total=len(scan_result.dll_files)
                )

                for dll_metadata in scan_result.dll_files:
                    try:
                        analysis_result = analyzer.analyze_dll_dependencies(
                            dll_metadata, source_dir, recursive=True
                        )
                        analysis_results.append(analysis_result)
                        progress.update(task, advance=1)
                    except Exception as e:
                        logger.error(
                            f"Failed to analyze {dll_metadata.file_name}: {str(e)}"
                        )
                        progress.update(task, advance=1)

            # Display dependency analysis results
            _display_dependency_analysis(console, analysis_results)

        # Save results to file if requested
        if output:
            if cyclonedx:
                # Export in CycloneDX SBOM format
                try:
                    cyclonedx_exporter = CycloneDXExporter()
                    cyclonedx_json = cyclonedx_exporter.export_to_json(
                        scan_result,
                        analysis_results,
                        project_name,
                        project_version,
                        output,
                    )
                    console.print(f"\n[green]CycloneDX SBOM saved to:[/green] {output}")

                    # Display summary
                    bom = cyclonedx_exporter.export_to_cyclonedx(
                        scan_result, analysis_results, project_name, project_version
                    )
                    summary = cyclonedx_exporter.get_component_summary(bom)
                    console.print(
                        f"[blue]SBOM contains {summary['total_components']} components[/blue]"
                    )

                except ImportError as e:
                    console.print(f"[red]Error:[/red] {str(e)}")
                    console.print(
                        "[yellow]Install CycloneDX support with:[/yellow] pip install cyclonedx-bom"
                    )
                    sys.exit(1)
                except Exception as e:
                    console.print(
                        f"[red]Error exporting CycloneDX SBOM:[/red] {str(e)}"
                    )
                    logger.error(f"CycloneDX export failed: {str(e)}")
            else:
                # Export in custom JSON format
                result_data = scan_result.to_dict()
                if analysis_results:
                    dependency_report = analyzer.generate_dependency_report(
                        analysis_results
                    )
                    result_data["dependency_analysis"] = dependency_report

                with open(output, "w") as f:
                    json.dump(result_data, f, indent=2)
                console.print(f"\n[green]Results saved to:[/green] {output}")
        elif cyclonedx:
            console.print(
                "[yellow]Warning:[/yellow] --cyclonedx flag requires --output to be specified"
            )

        # Display WiX-specific information if used
        if wix:
            try:
                from .wix_integration import WiXIntegration

                wix_integration = WiXIntegration(logger=logger)

                if wix_integration.is_windows() and wix_integration.is_available():
                    wix_dll_count = sum(
                        1
                        for dll in scan_result.dll_files
                        if dll.additional_metadata
                        and dll.additional_metadata.get("wix_available", False)
                    )
                    if wix_dll_count > 0:
                        console.print(
                            f"\n[blue]ℹ️  WiX analysis applied to {wix_dll_count} DLL(s)[/blue]"
                        )
                        console.print(
                            "[dim]WiX metadata includes component GUIDs, file IDs, and harvesting info[/dim]"
                        )
                    else:
                        console.print(
                            "\n[blue]ℹ️  WiX analysis was enabled but no enhanced metadata was extracted[/blue]"
                        )
            except ImportError:
                pass  # Already handled above

    except Exception as e:
        console.print(f"[red]Error during scan:[/red] {str(e)}")
        if ctx.obj["verbose"]:
            logger.exception("Detailed error information:")
        sys.exit(1)


@cli.command()
@click.argument(
    "dll_file", type=click.Path(exists=True, dir_okay=False, path_type=Path)
)
@click.option(
    "--output",
    "-o",
    type=click.Path(path_type=Path),
    help="Output file for metadata (JSON format)",
)
@click.option(
    "--cyclonedx",
    is_flag=True,
    help="Export metadata in CycloneDX SBOM format",
)
@click.option(
    "--extraction-method",
    multiple=True,
    type=click.Choice(["win32api", "pefile", "fileinfo", "all"], case_sensitive=False),
    help="Version extraction method(s) to use. Can specify multiple. Default: all",
)
@click.pass_context
def inspect(
    ctx: click.Context,
    dll_file: Path,
    output: Optional[Path],
    cyclonedx: bool,
    extraction_method: tuple[str, ...],
) -> None:
    """Inspect a single DLL file and display metadata."""
    console: Console = ctx.obj["console"]
    logger: logging.Logger = ctx.obj["logger"]

    if not dll_file.suffix.lower() == ".dll":
        console.print(f"[red]Error:[/red] {dll_file} is not a DLL file")
        sys.exit(1)

    try:
        # Parse extraction methods
        extraction_methods = _parse_extraction_methods(extraction_method)

        scanner = DLLScanner(logger=logger, extraction_methods=extraction_methods)
        metadata = scanner.scan_file(dll_file)

        _display_dll_metadata(console, metadata)

        if output:
            if cyclonedx:
                # Create a single-file scan result for CycloneDX export
                from .scanner import ScanResult

                scan_result = ScanResult(
                    scan_path=str(dll_file.parent),
                    recursive=False,
                    dll_files=[metadata],
                    total_files_scanned=1,
                    total_dlls_found=1,
                    scan_duration_seconds=0.0,
                    errors=[],
                )

                try:
                    cyclonedx_exporter = CycloneDXExporter()
                    cyclonedx_json = cyclonedx_exporter.export_to_json(
                        scan_result,
                        None,  # No dependency analysis for single file
                        dll_file.stem,  # Use filename as project name
                        metadata.file_version or "1.0.0",
                        output,
                    )
                    console.print(f"\n[green]CycloneDX SBOM saved to:[/green] {output}")
                except ImportError as e:
                    console.print(f"[red]Error:[/red] {str(e)}")
                    console.print(
                        "[yellow]Install CycloneDX support with:[/yellow] pip install cyclonedx-bom"
                    )
                    sys.exit(1)
                except Exception as e:
                    console.print(
                        f"[red]Error exporting CycloneDX SBOM:[/red] {str(e)}"
                    )
                    logger.error(f"CycloneDX export failed: {str(e)}")
            else:
                with open(output, "w") as f:
                    f.write(metadata.to_json())
                console.print(f"\n[green]Metadata saved to:[/green] {output}")
        elif cyclonedx:
            console.print(
                "[yellow]Warning:[/yellow] --cyclonedx flag requires --output to be specified"
            )

    except Exception as e:
        console.print(f"[red]Error inspecting DLL:[/red] {str(e)}")
        if ctx.obj["verbose"]:
            logger.exception("Detailed error information:")
        sys.exit(1)


@cli.command()
@click.argument(
    "source_directory", type=click.Path(exists=True, file_okay=False, path_type=Path)
)
@click.argument(
    "dll_files", nargs=-1, type=click.Path(exists=True, dir_okay=False, path_type=Path)
)
@click.option(
    "--output",
    "-o",
    type=click.Path(path_type=Path),
    help="Output file for analysis results (JSON format)",
)
@click.pass_context
def analyze(
    ctx: click.Context,
    source_directory: Path,
    dll_files: tuple[Path, ...],
    output: Optional[Path],
) -> None:
    """Analyze source code to confirm DLL dependencies."""
    console: Console = ctx.obj["console"]
    logger: logging.Logger = ctx.obj["logger"]

    if not dll_files:
        console.print("[red]Error:[/red] No DLL files specified")
        sys.exit(1)

    analyzer = DependencyAnalyzer(logger=logger)
    scanner = DLLScanner(logger=logger)
    analysis_results = []

    console.print(
        f"[bold blue]Analyzing dependencies in:[/bold blue] {source_directory}"
    )
    console.print(f"[blue]DLL files to analyze:[/blue] {len(dll_files)}")

    try:
        with Progress() as progress:
            task = progress.add_task("Analyzing dependencies...", total=len(dll_files))

            for dll_file in dll_files:
                if not dll_file.suffix.lower() == ".dll":
                    console.print(
                        f"[yellow]Warning:[/yellow] Skipping {dll_file} (not a DLL)"
                    )
                    progress.update(task, advance=1)
                    continue

                try:
                    # Extract metadata first
                    metadata = scanner.scan_file(dll_file)

                    # Perform dependency analysis
                    analysis_result = analyzer.analyze_dll_dependencies(
                        metadata, source_directory, recursive=True
                    )
                    analysis_results.append(analysis_result)

                except Exception as e:
                    logger.error(f"Failed to analyze {dll_file}: {str(e)}")

                progress.update(task, advance=1)

        # Display results
        _display_dependency_analysis(console, analysis_results)

        # Save results if requested
        if output:
            dependency_report = analyzer.generate_dependency_report(analysis_results)
            with open(output, "w") as f:
                json.dump(dependency_report, f, indent=2)
            console.print(f"\n[green]Analysis results saved to:[/green] {output}")

    except Exception as e:
        console.print(f"[red]Error during analysis:[/red] {str(e)}")
        if ctx.obj["verbose"]:
            logger.exception("Detailed error information:")
        sys.exit(1)


def _display_scan_results(console: Console, scan_result: ScanResult) -> None:
    """Display scan results in a formatted table."""
    console.print("\n[bold green]Scan completed![/bold green]")
    console.print(
        f"[green]Found {scan_result.total_dlls_found} DLL files in "
        f"{scan_result.scan_duration_seconds:.2f} seconds[/green]"
    )

    if scan_result.errors:
        console.print(f"[yellow]Errors encountered: {len(scan_result.errors)}[/yellow]")

    if not scan_result.dll_files:
        console.print("[yellow]No DLL files found[/yellow]")
        return

    # Create summary table
    table = Table(title="DLL Files Found")
    table.add_column("File Name", style="cyan")
    table.add_column("Architecture", style="magenta")
    table.add_column("Size", style="green")
    table.add_column("Company", style="blue")
    table.add_column("Version", style="yellow")

    for dll in scan_result.dll_files[:20]:  # Show first 20
        size_str = f"{dll.file_size / 1024:.1f} KB" if dll.file_size else "Unknown"
        table.add_row(
            dll.file_name or "Unknown",
            dll.architecture or "Unknown",
            size_str,
            dll.company_name or "Unknown",
            dll.file_version or "Unknown",
        )

    console.print(table)

    if len(scan_result.dll_files) > 20:
        console.print(
            f"[dim]... and {len(scan_result.dll_files) - 20} more DLL files[/dim]"
        )


def _display_dll_metadata(console: Console, metadata: DLLMetadata) -> None:
    """Display detailed metadata for a single DLL file."""

    # Basic information panel
    basic_info = Table.grid(padding=1)
    basic_info.add_column(style="bold blue")
    basic_info.add_column()

    basic_info.add_row("File Name:", metadata.file_name or "Unknown")
    basic_info.add_row("File Path:", metadata.file_path)
    basic_info.add_row(
        "File Size:",
        f"{metadata.file_size / 1024:.1f} KB" if metadata.file_size else "Unknown",
    )
    basic_info.add_row("Architecture:", metadata.architecture or "Unknown")
    basic_info.add_row("Machine Type:", metadata.machine_type or "Unknown")
    basic_info.add_row("Subsystem:", metadata.subsystem or "Unknown")

    console.print(Panel(basic_info, title="Basic Information"))

    # Version information panel
    if any([metadata.product_name, metadata.product_version, metadata.company_name]):
        version_info = Table.grid(padding=1)
        version_info.add_column(style="bold green")
        version_info.add_column()

        if metadata.product_name:
            version_info.add_row("Product Name:", metadata.product_name)
        if metadata.product_version:
            version_info.add_row("Product Version:", metadata.product_version)
        if metadata.file_version:
            version_info.add_row("File Version:", metadata.file_version)
        if metadata.company_name:
            version_info.add_row("Company:", metadata.company_name)
        if metadata.file_description:
            version_info.add_row("Description:", metadata.file_description)

        console.print(Panel(version_info, title="Version Information"))

    # Dependencies
    if metadata.imported_dlls:
        deps_text = Text()
        for i, dll in enumerate(metadata.imported_dlls[:10]):
            if i > 0:
                deps_text.append(", ")
            deps_text.append(dll, style="cyan")
        if len(metadata.imported_dlls) > 10:
            deps_text.append(
                f" ... and {len(metadata.imported_dlls) - 10} more", style="dim"
            )

        console.print(
            Panel(deps_text, title=f"Imported DLLs ({len(metadata.imported_dlls)})")
        )

    # Exported functions
    if metadata.exported_functions:
        exports_text = Text()
        for i, func in enumerate(metadata.exported_functions[:10]):
            if i > 0:
                exports_text.append(", ")
            exports_text.append(func, style="yellow")
        if len(metadata.exported_functions) > 10:
            exports_text.append(
                f" ... and {len(metadata.exported_functions) - 10} more", style="dim"
            )

        console.print(
            Panel(
                exports_text,
                title=f"Exported Functions ({len(metadata.exported_functions)})",
            )
        )


def _display_dependency_analysis(
    console: Console, analysis_results: list[AnalysisResult]
) -> None:
    """Display dependency analysis results."""
    if not analysis_results:
        console.print("[yellow]No analysis results to display[/yellow]")
        return

    confirmed_count = sum(
        len(result.confirmed_dependencies) for result in analysis_results
    )
    potential_count = sum(
        len(result.potential_dependencies) for result in analysis_results
    )

    console.print("\n[bold cyan]Dependency Analysis Results[/bold cyan]")
    console.print(f"[green]Confirmed dependencies: {confirmed_count}[/green]")
    console.print(f"[yellow]Potential dependencies: {potential_count}[/yellow]")

    # Show confirmed dependencies
    if confirmed_count > 0:
        table = Table(title="Confirmed Dependencies")
        table.add_column("DLL", style="cyan")
        table.add_column("Source File", style="blue")
        table.add_column("Line", style="green")
        table.add_column("Type", style="magenta")
        table.add_column("Confidence", style="yellow")

        for result in analysis_results:
            for dep in result.confirmed_dependencies:
                table.add_row(
                    result.dll_metadata.file_name,
                    Path(dep.file_path).name,
                    str(dep.line_number),
                    dep.match_type,
                    f"{dep.confidence:.1%}",
                )

        console.print(table)

    # Summary of potentially unused DLLs
    unused_dlls = [
        result
        for result in analysis_results
        if not result.confirmed_dependencies and not result.potential_dependencies
    ]

    if unused_dlls:
        console.print(
            f"\n[bold red]Potentially Unused DLLs ({len(unused_dlls)})[/bold red]"
        )
        for result in unused_dlls:
            console.print(f"  • {result.dll_metadata.file_name}")


@cli.command()
@click.option(
    "--input",
    "-i",
    "input_file",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help="Input JSON file from scan results",
)
@click.option(
    "--project-name",
    default="DLL Analysis Project",
    help="Project name for the generated page",
)
@click.option(
    "--output",
    "-o",
    type=click.Path(path_type=Path),
    help="Output directory for generated pages (default: ./pages-output)",
)
@click.option(
    "--generate-data",
    is_flag=True,
    help="Generate data files (changelog.json) from project sources",
)
@click.pass_context
def generate_pages(
    ctx: click.Context,
    input_file: Optional[Path],
    project_name: str,
    output: Optional[Path],
    generate_data: bool,
) -> None:
    """Generate GitHub Pages content for DLL scan results."""
    console: Console = ctx.obj["console"]
    logger: logging.Logger = ctx.obj["logger"]

    if output is None:
        output = Path("./pages-output")

    try:
        generator = PageGenerator()

        console.print(f"[bold blue]Generating GitHub Pages content...[/bold blue]")

        # Create output directory
        output.mkdir(parents=True, exist_ok=True)

        # Copy static assets
        console.print("📁 Copying static assets...")
        generator.copy_static_assets(output / "pages")

        # Create root index.html redirect
        console.print("🏠 Creating root index.html...")
        generator.create_index_redirect(output)

        # Generate data files if requested
        if generate_data:
            console.print("📋 Generating changelog data...")
            try:
                changelog_path = generator.generate_changelog_data()
                console.print(f"✅ Changelog data generated: {changelog_path}")
            except FileNotFoundError as e:
                console.print(f"⚠️  [yellow]Warning: {e}[/yellow]")

        # Generate scan result page if input provided
        if input_file:
            console.print(f"📊 Generating scan result page from {input_file}...")

            # Load scan result from JSON
            with open(input_file, "r", encoding="utf-8") as f:
                data = json.load(f)

            # Convert to ScanResult object
            scan_result = ScanResult(
                scan_path=data.get("scan_path", ""),
                recursive=data.get("recursive", True),
                dll_files=[],  # We'll populate this from the data
                total_files_scanned=data.get("total_files_scanned", 0),
                total_dlls_found=data.get("total_dlls_found", 0),
                scan_duration_seconds=data.get("scan_duration_seconds", 0.0),
                errors=data.get("errors", []),
            )

            # Convert DLL files data back to DLLMetadata objects
            for dll_data in data.get("dll_files", []):
                # Handle datetime conversion
                mod_time = dll_data.get("modification_time", "")
                if isinstance(mod_time, str):
                    try:
                        from datetime import datetime

                        mod_time = datetime.fromisoformat(
                            mod_time.replace("Z", "+00:00")
                        )
                    except:
                        mod_time = datetime.now()

                dll_metadata = DLLMetadata(
                    file_path=dll_data.get("file_path", ""),
                    file_name=dll_data.get("file_name", ""),
                    file_size=dll_data.get("file_size", 0),
                    modification_time=mod_time,
                    machine_type=dll_data.get("machine_type"),
                    architecture=dll_data.get("architecture"),
                    subsystem=dll_data.get("subsystem"),
                    dll_characteristics=dll_data.get("dll_characteristics", []),
                    product_name=dll_data.get("product_name"),
                    product_version=dll_data.get("product_version"),
                    file_version=dll_data.get("file_version"),
                    company_name=dll_data.get("company_name"),
                    file_description=dll_data.get("file_description"),
                    internal_name=dll_data.get("internal_name"),
                    legal_copyright=dll_data.get("legal_copyright"),
                    original_filename=dll_data.get("original_filename"),
                    imported_dlls=dll_data.get("imported_dlls", []),
                    exported_functions=dll_data.get("exported_functions", []),
                    is_signed=dll_data.get("is_signed", False),
                    checksum=dll_data.get("checksum"),
                )
                scan_result.dll_files.append(dll_metadata)

            # Generate the page
            # First set the generator to use the output directory
            output_generator = PageGenerator(output / "pages")
            result_page = output_generator.generate_scan_result_page(
                scan_result,
                project_name,
                f"{project_name.lower().replace(' ', '_')}_results.html",
            )

            console.print(f"✅ Scan result page generated: {result_page}")

        console.print(f"\n[bold green]✅ Pages generated successfully![/bold green]")
        console.print(f"📁 Output directory: {output.absolute()}")
        console.print(f"🌐 To serve locally: python -m http.server 8000 -d {output}")
        console.print(f"🔗 Then visit: http://localhost:8000")

    except Exception as e:
        logger.error(f"Page generation failed: {e}")
        console.print(f"[bold red]❌ Error: {e}[/bold red]")
        sys.exit(1)


@cli.command()
@click.argument(
    "directory", type=click.Path(exists=True, file_okay=False, path_type=Path)
)
@click.option(
    "--output",
    "-o",
    type=click.Path(path_type=Path),
    help="Output file for WiX analysis results (JSON format)",
)
@click.option(
    "--recursive/--no-recursive",
    default=True,
    help="Scan directories recursively (default: True)",
)
@click.option(
    "--download-wix",
    is_flag=True,
    help="Force download WiX Toolset even if already available",
)
@click.option(
    "--cyclonedx",
    is_flag=True,
    help="Export results in CycloneDX SBOM format with WiX metadata",
)
@click.option(
    "--project-name",
    default="WiX DLL Analysis Project",
    help="Project name for CycloneDX SBOM (default: 'WiX DLL Analysis Project')",
)
@click.option(
    "--project-version",
    default="1.0.0",
    help="Project version for CycloneDX SBOM (default: '1.0.0')",
)
@click.pass_context
def wix(
    ctx: click.Context,
    directory: Path,
    output: Optional[Path],
    recursive: bool,
    download_wix: bool,
    cyclonedx: bool,
    project_name: str,
    project_version: str,
) -> None:
    """Analyze DLL files using WiX Toolset for enhanced Windows metadata."""
    console: Console = ctx.obj["console"]
    logger: logging.Logger = ctx.obj["logger"]

    try:
        from .wix_integration import WiXIntegration
    except ImportError as e:
        console.print(f"[red]Error:[/red] WiX integration not available: {e}")
        sys.exit(1)

    console.print(f"[bold blue]🔍 WiX DLL Analysis[/bold blue]")
    console.print(f"📁 Target directory: {directory}")

    try:
        # Initialize WiX integration
        wix = WiXIntegration(logger=logger)

        # Check platform compatibility
        if not wix.is_windows():
            console.print(
                "[yellow]⚠️  Warning:[/yellow] WiX Toolset is only available on Windows"
            )
            console.print("Falling back to standard DLL scanning...")

            # Fall back to standard scanning
            scanner = DLLScanner(logger=logger)
            scan_result = scanner.scan_directory(directory, recursive=recursive)
        else:
            # Windows platform - use WiX enhanced analysis
            if download_wix or not wix.is_available():
                console.print("📥 Downloading WiX Toolset...")

                with Progress() as progress:
                    task = progress.add_task("[blue]Downloading WiX...", total=100)

                    if wix.download_wix():
                        progress.update(task, completed=100)
                        console.print(
                            "[green]✅ WiX Toolset downloaded successfully[/green]"
                        )
                    else:
                        console.print("[red]❌ Failed to download WiX Toolset[/red]")
                        console.print("Falling back to standard DLL scanning...")
                        scanner = DLLScanner(logger=logger)
                        scan_result = scanner.scan_directory(
                            directory, recursive=recursive
                        )

            if wix.is_available():
                console.print("🔧 Using WiX Toolset for enhanced analysis...")

                # First do standard scan
                scanner = DLLScanner(logger=logger)
                scan_result = scanner.scan_directory(directory, recursive=recursive)

                # Then enhance with WiX
                console.print("🚀 Enhancing results with WiX metadata...")
                scan_result = wix.enhance_scan_result(scan_result)
                console.print("[green]✅ WiX enhancement completed[/green]")
            else:
                console.print(
                    "[yellow]⚠️  WiX not available, using standard scanning[/yellow]"
                )
                scanner = DLLScanner(logger=logger)
                scan_result = scanner.scan_directory(directory, recursive=recursive)

        # Display results
        _display_scan_results(console, scan_result)

        # Output results
        if output:
            if cyclonedx:
                exporter = CycloneDXExporter()
                json_output = exporter.export_to_json(
                    scan_result,
                    project_name=project_name,
                    project_version=project_version,
                    output_file=output,
                )
                console.print(f"[green]✅ CycloneDX SBOM exported to:[/green] {output}")
            else:
                output.parent.mkdir(parents=True, exist_ok=True)
                with open(output, "w") as f:
                    json.dump(scan_result.to_dict(), f, indent=2, default=str)
                console.print(f"[green]✅ Results exported to:[/green] {output}")

        # Show WiX-specific information if available
        if wix.is_windows() and wix.is_available():
            wix_dll_count = sum(
                1
                for dll in scan_result.dll_files
                if dll.additional_metadata
                and dll.additional_metadata.get("wix_available", False)
            )
            if wix_dll_count > 0:
                console.print(
                    f"\n[blue]ℹ️  WiX analysis applied to {wix_dll_count} DLL(s)[/blue]"
                )
                console.print(
                    "[dim]WiX metadata includes component GUIDs, file IDs, and harvesting info[/dim]"
                )

    except Exception as e:
        logger.error(f"WiX analysis failed: {e}")
        console.print(f"[bold red]❌ Error: {e}[/bold red]")
        sys.exit(1)


def main() -> None:
    """Main entry point for the CLI."""
    cli()


if __name__ == "__main__":
    main()
