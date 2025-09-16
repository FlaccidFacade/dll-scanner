"""
Example of using DLL Scanner as a Python library.
"""

from pathlib import Path
from dll_scanner import DLLScanner, DependencyAnalyzer
import json

def main():
    """Example usage of DLL Scanner library."""
    # Initialize scanner
    scanner = DLLScanner(max_workers=4)
    
    # Scan a directory for DLL files
    project_path = Path("/path/to/your/project")
    
    if project_path.exists():
        print(f"Scanning {project_path} for DLL files...")
        
        # Perform scan
        result = scanner.scan_directory(project_path, recursive=True)
        
        print(f"Found {result.total_dlls_found} DLL files")
        print(f"Scan took {result.scan_duration_seconds:.2f} seconds")
        
        # Display results
        for dll in result.dll_files[:5]:  # Show first 5
            print(f"- {dll.file_name}")
            print(f"  Architecture: {dll.architecture}")
            print(f"  Company: {dll.company_name}")
            print(f"  Version: {dll.file_version}")
            print(f"  Imports: {len(dll.imported_dlls or [])} DLLs")
            print(f"  Exports: {len(dll.exported_functions or [])} functions")
            print()
        
        # Get summary statistics
        stats = scanner.get_summary_stats(result)
        print("Summary Statistics:")
        print(f"- Total DLLs: {stats['total_dlls']}")
        print(f"- Architectures: {stats['architectures']}")
        print(f"- Signed DLLs: {stats['signed_dlls']}")
        print(f"- Unsigned DLLs: {stats['unsigned_dlls']}")
        
        # Perform dependency analysis if source directory exists
        source_path = Path("/path/to/source/code")
        if source_path.exists():
            print("\nPerforming dependency analysis...")
            
            analyzer = DependencyAnalyzer()
            analysis_results = []
            
            for dll_metadata in result.dll_files:
                try:
                    analysis = analyzer.analyze_dll_dependencies(
                        dll_metadata, source_path
                    )
                    analysis_results.append(analysis)
                except Exception as e:
                    print(f"Failed to analyze {dll_metadata.file_name}: {e}")
            
            # Generate dependency report
            if analysis_results:
                report = analyzer.generate_dependency_report(analysis_results)
                
                print(f"Analysis Results:")
                print(f"- DLLs with confirmed usage: {report['summary']['dlls_with_confirmed_usage']}")
                print(f"- Potentially unused DLLs: {report['summary']['dlls_potentially_unused']}")
                
                # Save results to file
                with open("dll_analysis_results.json", "w") as f:
                    json.dump({
                        "scan_results": result.to_dict(),
                        "dependency_analysis": report
                    }, f, indent=2)
                
                print("Results saved to dll_analysis_results.json")
        
    else:
        print(f"Directory {project_path} does not exist")
        print("Update the path in this script to point to your project directory")

if __name__ == "__main__":
    main()