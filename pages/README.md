# GitHub Pages for DLL Scanner

This directory contains the static HTML and JavaScript pages for GitHub Pages hosting.

## Features

### 🏠 Home Page (`index.html`)
- Project overview and feature highlights
- Getting started guide with installation and usage examples
- Links to interactive tools and documentation

### 📊 Scan Results Viewer (`scan-results.html`)
- **Interactive Data Loading**:
  - Upload JSON files from local computer
  - Load scan results from URLs
  - Paste JSON data directly
  - URL parameter support for direct linking
- **Visualizations**:
  - Architecture distribution (doughnut chart)
  - Company distribution (bar chart)
  - Summary statistics cards
- **Filtering and Search**:
  - Search DLL files by name
  - Filter by architecture (x64, x86, etc.)
  - Filter by signing status
- **Export Capabilities**:
  - Export filtered results as JSON
  - Export summary reports
  - Export data as CSV
- **Detailed View**:
  - Modal dialogs with complete DLL metadata
  - Import/export function lists
  - File properties and security info

### 📋 Changelog (`changelog.html`)
- Dynamic changelog loading from GitHub API
- Search and filter by version or change type
- Timeline view with version badges
- Fallback to static content if API unavailable

## Architecture

### Static Assets
```
pages/
├── index.html              # Home page
├── scan-results.html       # Interactive scan results viewer
├── changelog.html          # Dynamic changelog viewer
├── styles/
│   └── main.css           # Responsive CSS with modern design
├── js/
│   ├── main.js            # Common utilities and functionality
│   ├── scan-results.js    # Scan results viewer logic
│   └── changelog.js       # Changelog functionality
├── assets/
│   └── favicon.svg        # Project favicon
├── data/                  # Generated data files
│   ├── changelog.json     # Parsed changelog data
│   └── *.json            # Scan result JSON files
└── generated/             # Generated static pages
    └── *.html            # Specific scan result pages
```

### JavaScript Modules

#### `main.js`
- Utility functions (file size formatting, debouncing, etc.)
- Common UI interactions
- URL parameter handling
- Notification system

#### `scan-results.js`
- File upload and URL loading
- Chart generation with Chart.js
- Table rendering and filtering
- Data export functionality
- Modal dialog management

#### `changelog.js`
- GitHub API integration
- Markdown parsing
- Search and filtering
- Timeline rendering

## Page Generation

### CLI Command
```bash
# Generate static pages
dll-scanner generate-pages --output ./pages-output --generate-data

# Generate pages with scan results
dll-scanner generate-pages \
  --input scan_results.json \
  --project-name "My Project" \
  --output ./pages-output
```

### Python API
```python
from dll_scanner import PageGenerator

# Initialize generator
generator = PageGenerator()

# Generate scan result page
page_path = generator.generate_scan_result_page(
    scan_result, 
    project_name="My Project"
)

# Generate changelog data
changelog_path = generator.generate_changelog_data()

# Copy static assets
generator.copy_static_assets(output_dir)
```

## URL Parameters

### Scan Results Viewer
- `?url=path/to/results.json` - Load scan results from URL
- `?data=<encoded_json>` - Load scan results from encoded JSON data

### Changelog
- `?version=1.0.0` - Filter to specific version
- `?type=added` - Filter to specific change type

## Development

### Local Development
```bash
# Generate pages
dll-scanner generate-pages --output ./test-pages --generate-data

# Serve locally
python -m http.server 8000 -d ./test-pages

# Visit http://localhost:8000
```

### Adding New Features
1. Update HTML templates in `pages/` directory
2. Add JavaScript functionality to appropriate JS files
3. Update CSS styling in `styles/main.css`
4. Test with sample data

## Deployment

### GitHub Actions
The `.github/workflows/pages.yml` workflow automatically:
1. Generates static pages on push to main
2. Creates sample data for demonstration
3. Deploys to GitHub Pages

### Manual Deployment
```bash
# Generate production pages
dll-scanner generate-pages --output ./dist --generate-data

# Deploy to GitHub Pages
# (Copy contents of ./dist to your pages repository)
```

## Dependencies

### Frontend
- **Chart.js** (CDN): Interactive charts and visualizations
- **Modern CSS**: Responsive design with CSS Grid and Flexbox
- **Vanilla JavaScript**: No framework dependencies for maximum compatibility

### Backend
- **DLL Scanner**: Core scanning and analysis functionality
- **Python 3.8+**: Page generation utilities

## Browser Support

- **Modern Browsers**: Chrome 80+, Firefox 75+, Safari 13+, Edge 80+
- **JavaScript Features**: ES6+, Fetch API, URL API
- **CSS Features**: Grid, Flexbox, Custom Properties

## Contributing

To add new pages or features:

1. Create HTML templates in the `pages/` directory
2. Add corresponding JavaScript in the `js/` directory
3. Update CSS styling as needed
4. Add page generation logic to `PageGenerator` class
5. Update CLI commands if needed
6. Test locally before submitting

## Examples

### Sample Data Format
The scan results viewer expects JSON in this format:
```json
{
  "scan_path": "/path/to/project",
  "recursive": true,
  "total_files_scanned": 150,
  "total_dlls_found": 25,
  "scan_duration_seconds": 2.34,
  "errors": [],
  "dll_files": [
    {
      "file_name": "example.dll",
      "file_path": "/path/to/example.dll",
      "file_size": 65536,
      "architecture": "x64",
      "company_name": "Microsoft Corporation",
      "is_signed": true,
      "imported_dlls": ["kernel32.dll"],
      "exported_functions": ["ExampleFunction"]
    }
  ]
}
```

### URL Linking Examples
```html
<!-- Link to scan results with data -->
<a href="pages/scan-results.html?url=data/my_scan.json">
  View Scan Results
</a>

<!-- Link to specific changelog version -->
<a href="pages/changelog.html?version=1.0.0">
  Version 1.0.0 Changes
</a>
```