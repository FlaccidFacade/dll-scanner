"""
CycloneDX SBOM export functionality for DLL Scanner.
"""

from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from cyclonedx.model.bom import Bom, Tool
    from cyclonedx.model.component import Component, ComponentType, ComponentScope
    from cyclonedx.model import (
        HashType,
        ExternalReference,
        ExternalReferenceType,
        Property,
        XsUri,
    )
    from cyclonedx.output.json import JsonV1Dot6
    from cyclonedx.validation.json import JsonStrictValidator
    from cyclonedx.schema import SchemaVersion
    from packageurl import PackageURL

try:
    from cyclonedx.model.bom import Bom, Tool
    from cyclonedx.model.component import Component, ComponentType, ComponentScope
    from cyclonedx.model.dependency import Dependency
    from cyclonedx.model import (
        HashType,
        ExternalReference,
        ExternalReferenceType,
        Property,
        XsUri,
    )
    from cyclonedx.output.json import JsonV1Dot6
    from cyclonedx.validation.json import JsonStrictValidator
    from cyclonedx.schema import SchemaVersion
    from packageurl import PackageURL

    CYCLONEDX_AVAILABLE = True
except ImportError:
    CYCLONEDX_AVAILABLE = False
    # Define dummy classes when CycloneDX is not available

    class Bom:  # type: ignore
        pass

    class Component:  # type: ignore
        pass

    class ComponentType:  # type: ignore
        pass

    class ComponentScope:  # type: ignore
        pass

    class HashType:  # type: ignore
        pass

    class ExternalReference:  # type: ignore
        pass

    class ExternalReferenceType:  # type: ignore
        pass

    class Tool:  # type: ignore
        pass

    class Property:  # type: ignore
        pass

    class JsonV1Dot6:  # type: ignore
        pass

    class JsonStrictValidator:  # type: ignore
        pass

    class PackageURL:  # type: ignore
        pass

    class Dependency:  # type: ignore
        pass

    class SchemaVersion:  # type: ignore
        pass


from .metadata import DLLMetadata
from .scanner import ScanResult
from .analyzer import AnalysisResult


class CycloneDXExporter:
    """Exports DLL scan results to CycloneDX SBOM format."""

    def __init__(self) -> None:
        """Initialize the CycloneDX exporter."""
        if not CYCLONEDX_AVAILABLE:
            raise ImportError(
                "CycloneDX library is not available. "
                "Install with: pip install cyclonedx-bom"
            )
        self.validator = JsonStrictValidator(SchemaVersion.V1_6)

    def export_to_cyclonedx(
        self,
        scan_result: ScanResult,
        analysis_results: Optional[List[AnalysisResult]] = None,
        project_name: str = "DLL Analysis Project",
        project_version: str = "1.0.0",
    ) -> "Bom":
        """
        Export scan results to CycloneDX BOM format.

        Args:
            scan_result: DLL scan results
            analysis_results: Optional dependency analysis results
            project_name: Name of the project being analyzed
            project_version: Version of the project being analyzed

        Returns:
            CycloneDX BOM object
        """
        # Create the main component (the project being analyzed)
        project_purl = PackageURL(
            type="generic",
            name=project_name.replace(" ", "-").lower(),
            version=project_version,
        )

        main_component = Component(
            type=ComponentType.APPLICATION,
            name=project_name,
            version=project_version,
            bom_ref=str(project_purl),
            purl=project_purl,
        )

        # Create BOM with metadata
        bom = Bom()
        bom.metadata.component = main_component
        bom.metadata.timestamp = datetime.now()

        # Add DLL Scanner as a tool
        dll_scanner_tool = Tool(
            vendor="DLL Scanner Contributors",
            name="dll-scanner",
            version="0.1.0",
        )
        bom.metadata.tools.tools.add(dll_scanner_tool)

        # Add properties for scan metadata
        bom.metadata.properties.add(
            Property(name="scan.path", value=scan_result.scan_path)
        )
        bom.metadata.properties.add(
            Property(name="scan.recursive", value=str(scan_result.recursive))
        )
        # Add scan metadata properties
        bom.metadata.properties.add(
            Property(
                name="scan.duration_seconds",
                value=str(scan_result.scan_duration_seconds),
            )
        )
        bom.metadata.properties.add(
            Property(
                name="scan.total_files_scanned",
                value=str(scan_result.total_files_scanned),
            )
        )
        bom.metadata.properties.add(
            Property(
                name="scan.total_dlls_found", value=str(scan_result.total_dlls_found)
            )
        )

        # Convert DLL files to components
        dependency_analysis_map = {}
        if analysis_results:
            dependency_analysis_map = {
                result.dll_metadata.file_path: result for result in analysis_results
            }

        dll_components = []
        for dll_metadata in scan_result.dll_files:
            component = self._dll_to_component(dll_metadata, dependency_analysis_map)
            bom.components.add(component)
            dll_components.append(component)

        # Create dependency relationship between main component and DLL components
        # This resolves the CycloneDX validation warning about incomplete dependency
        # graph
        if dll_components:
            main_dependency = Dependency(ref=main_component.bom_ref)
            for dll_component in dll_components:
                # Create a child dependency for each DLL component
                dll_dependency = Dependency(ref=dll_component.bom_ref)
                main_dependency.dependencies.add(dll_dependency)
            bom.dependencies.add(main_dependency)

        return bom

    def _dll_to_component(
        self,
        dll_metadata: DLLMetadata,
        dependency_analysis_map: Dict[str, AnalysisResult],
    ) -> "Component":
        """
        Convert DLL metadata to CycloneDX component.

        Args:
            dll_metadata: DLL metadata
            dependency_analysis_map: Map of file paths to analysis results

        Returns:
            CycloneDX Component
        """
        # Create component name and version
        component_name = dll_metadata.file_name or "unknown.dll"
        component_version = (
            dll_metadata.file_version or dll_metadata.product_version or "unknown"
        )

        # Create a package URL for the DLL
        # Use 'dll' as package type, file name as name, and version from
        # metadata. Include namespace if we have a company name
        namespace = None
        if dll_metadata.company_name:
            # Clean up company name for use as namespace (remove special
            # chars, spaces)
            namespace = (
                dll_metadata.company_name.replace(" ", "-")
                .replace(".", "-")
                .replace(",", "")
                .lower()
            )

        purl = PackageURL(
            type="dll",
            namespace=namespace,
            name=component_name,
            version=component_version,
            qualifiers=(
                {
                    "arch": dll_metadata.architecture or "unknown",
                    "checksum": dll_metadata.checksum or "",
                }
                if dll_metadata.architecture or dll_metadata.checksum
                else None
            ),
        )

        # Create component with DLL-specific type
        component = Component(
            type=ComponentType.LIBRARY,
            name=component_name,
            version=component_version,
            bom_ref=str(purl),  # Use the package URL as bom reference
            purl=purl,  # Set the actual purl attribute
            scope=ComponentScope.REQUIRED,
        )

        # Add basic properties
        if dll_metadata.company_name:
            component.publisher = dll_metadata.company_name

        if dll_metadata.file_description:
            component.description = dll_metadata.file_description

        # Add file properties
        if dll_metadata.file_path:
            component.properties.add(
                Property(name="dll.file_path", value=dll_metadata.file_path)
            )

        if dll_metadata.file_size:
            component.properties.add(
                Property(name="dll.file_size", value=str(dll_metadata.file_size))
            )

        if dll_metadata.architecture:
            component.properties.add(
                Property(name="dll.architecture", value=dll_metadata.architecture)
            )

        if dll_metadata.machine_type:
            component.properties.add(
                Property(name="dll.machine_type", value=dll_metadata.machine_type)
            )

        if dll_metadata.subsystem:
            component.properties.add(
                Property(name="dll.subsystem", value=dll_metadata.subsystem)
            )

        # Add version information
        if dll_metadata.product_name:
            component.properties.add(
                Property(name="dll.product_name", value=dll_metadata.product_name)
            )

        if dll_metadata.product_version:
            component.properties.add(
                Property(name="dll.product_version", value=dll_metadata.product_version)
            )

        if dll_metadata.file_version:
            component.properties.add(
                Property(name="dll.file_version", value=dll_metadata.file_version)
            )

        if dll_metadata.internal_name:
            component.properties.add(
                Property(name="dll.internal_name", value=dll_metadata.internal_name)
            )

        if dll_metadata.original_filename:
            component.properties.add(
                Property(
                    name="dll.original_filename", value=dll_metadata.original_filename
                )
            )

        if dll_metadata.legal_copyright:
            component.properties.add(
                Property(name="dll.legal_copyright", value=dll_metadata.legal_copyright)
            )

        # Add security properties
        component.properties.add(
            Property(name="dll.is_signed", value=str(dll_metadata.is_signed))
        )

        if dll_metadata.checksum:
            component.properties.add(
                Property(name="dll.checksum", value=dll_metadata.checksum)
            )

        # Add DLL characteristics
        if dll_metadata.dll_characteristics:
            component.properties.add(
                Property(
                    name="dll.characteristics",
                    value=", ".join(dll_metadata.dll_characteristics),
                )
            )

        # Add import/export information
        if dll_metadata.imported_dlls:
            component.properties.add(
                Property(
                    name="dll.imported_dlls",
                    value=", ".join(dll_metadata.imported_dlls),
                )
            )

        if dll_metadata.exported_functions:
            # Limit to first 50 functions to avoid overly large properties
            functions = dll_metadata.exported_functions[:50]
            if len(dll_metadata.exported_functions) > 50:
                functions.append(
                    f"... and {len(dll_metadata.exported_functions) - 50} " "more"
                )
            component.properties.add(
                Property(name="dll.exported_functions", value=", ".join(functions))
            )

        # Add dependency analysis results if available
        analysis_result = dependency_analysis_map.get(dll_metadata.file_path)
        if analysis_result:
            component.properties.add(
                Property(
                    name="dll.confirmed_dependencies",
                    value=str(len(analysis_result.confirmed_dependencies)),
                )
            )
            component.properties.add(
                Property(
                    name="dll.potential_dependencies",
                    value=str(len(analysis_result.potential_dependencies)),
                )
            )
            component.properties.add(
                Property(
                    name="dll.analysis_confidence",
                    value=f"{analysis_result.analysis_confidence:.2f}",
                )
            )
            component.properties.add(
                Property(
                    name="dll.source_files_analyzed",
                    value=str(analysis_result.source_files_analyzed),
                )
            )

        # Add file reference as external reference
        if dll_metadata.file_path:
            file_ref = ExternalReference(
                type=ExternalReferenceType.DISTRIBUTION,
                url=XsUri(f"file://{dll_metadata.file_path}"),
                comment="Original DLL file location",
            )
            component.external_references.add(file_ref)

        # Add analysis errors if any
        if dll_metadata.analysis_errors:
            component.properties.add(
                Property(
                    name="dll.analysis_errors",
                    value="; ".join(dll_metadata.analysis_errors),
                )
            )

        return component

    def export_to_json(
        self,
        scan_result: ScanResult,
        analysis_results: Optional[List[AnalysisResult]] = None,
        project_name: str = "DLL Analysis Project",
        project_version: str = "1.0.0",
        output_file: Optional[Path] = None,
    ) -> str:
        """
        Export scan results to CycloneDX JSON format.

        Args:
            scan_result: DLL scan results
            analysis_results: Optional dependency analysis results
            project_name: Name of the project being analyzed
            project_version: Version of the project being analyzed
            output_file: Optional output file path

        Returns:
            JSON string of the CycloneDX BOM
        """
        bom = self.export_to_cyclonedx(
            scan_result, analysis_results, project_name, project_version
        )

        # Generate JSON output
        json_outputter = JsonV1Dot6(bom)
        json_output: str = json_outputter.output_as_string()

        # Validate the output
        try:
            validation_errors = self.validator.validate_str(json_output)
            if validation_errors:
                # validation_errors can be a single JsonValidationError or an iterable
                # Handle both cases properly
                if hasattr(validation_errors, "__iter__") and not isinstance(
                    validation_errors, str
                ):
                    # It's an iterable of errors
                    error_count = len(list(validation_errors))
                else:
                    # It's a single error
                    error_count = 1
                print(f"Warning: CycloneDX validation found " f"{error_count} issues")
        except Exception as e:
            print(f"Warning: Could not validate CycloneDX output: {e}")

        # Save to file if specified
        if output_file:
            with open(output_file, "w", encoding="utf-8") as f:
                f.write(json_output)

        return json_output

    def get_component_summary(self, bom: "Bom") -> Dict[str, Any]:
        """
        Get a summary of components in the BOM.

        Args:
            bom: CycloneDX BOM object

        Returns:
            Dictionary with component statistics
        """
        total_components = len(bom.components)

        # Count by architecture
        architectures: Dict[str, int] = {}
        signed_count = 0

        for component in bom.components:
            # Extract architecture from properties
            arch_prop = next(
                (p for p in component.properties if p.name == "dll.architecture"), None
            )
            if arch_prop:
                arch = arch_prop.value
                architectures[arch] = architectures.get(arch, 0) + 1

            # Count signed DLLs
            signed_prop = next(
                (p for p in component.properties if p.name == "dll.is_signed"), None
            )
            if signed_prop and signed_prop.value.lower() == "true":
                signed_count += 1

        return {
            "total_components": total_components,
            "architectures": architectures,
            "signed_dlls": signed_count,
            "unsigned_dlls": total_components - signed_count,
            "bom_version": bom.version,
            "generation_timestamp": (
                bom.metadata.timestamp.isoformat() if bom.metadata.timestamp else None
            ),
        }
