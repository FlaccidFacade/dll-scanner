/**
 * Scan Results Viewer functionality
 */

class ScanResultsViewer {
    constructor() {
        this.data = null;
        this.filteredData = null;
        this.charts = {};
        
        this.init();
    }

    init() {
        this.bindEvents();
        this.checkUrlParams();
    }

    bindEvents() {
        // File upload
        const uploadArea = document.getElementById('upload-area');
        const fileInput = document.getElementById('file-input');

        uploadArea?.addEventListener('click', () => fileInput?.click());
        uploadArea?.addEventListener('dragover', this.handleDragOver.bind(this));
        uploadArea?.addEventListener('dragleave', this.handleDragLeave.bind(this));
        uploadArea?.addEventListener('drop', this.handleDrop.bind(this));
        fileInput?.addEventListener('change', this.handleFileSelect.bind(this));

        // URL and JSON input
        document.getElementById('load-url-btn')?.addEventListener('click', this.loadFromUrl.bind(this));
        document.getElementById('load-json-btn')?.addEventListener('click', this.loadFromJson.bind(this));

        // Filters and search
        document.getElementById('search-input')?.addEventListener('input', 
            utils.debounce(this.applyFilters.bind(this), 300));
        document.getElementById('architecture-filter')?.addEventListener('change', this.applyFilters.bind(this));
        document.getElementById('signed-filter')?.addEventListener('change', this.applyFilters.bind(this));

        // Export buttons
        document.getElementById('export-filtered')?.addEventListener('click', this.exportFiltered.bind(this));
        document.getElementById('export-summary')?.addEventListener('click', this.exportSummary.bind(this));
        document.getElementById('export-csv')?.addEventListener('click', this.exportCsv.bind(this));

        // Modal close
        document.getElementById('modal-close')?.addEventListener('click', this.closeModal.bind(this));
        document.getElementById('dll-modal')?.addEventListener('click', (e) => {
            if (e.target.id === 'dll-modal') this.closeModal();
        });
    }

    checkUrlParams() {
        const params = utils.getUrlParams();
        if (params.url) {
            document.getElementById('results-url').value = params.url;
            this.loadFromUrl();
        } else if (params.data) {
            try {
                const decodedData = decodeURIComponent(params.data);
                document.getElementById('json-input').value = decodedData;
                this.loadFromJson();
            } catch (error) {
                console.error('Error decoding URL data:', error);
            }
        }
    }

    handleDragOver(e) {
        e.preventDefault();
        e.currentTarget.classList.add('dragover');
    }

    handleDragLeave(e) {
        e.preventDefault();
        e.currentTarget.classList.remove('dragover');
    }

    handleDrop(e) {
        e.preventDefault();
        e.currentTarget.classList.remove('dragover');
        
        const files = e.dataTransfer.files;
        if (files.length > 0) {
            this.loadFile(files[0]);
        }
    }

    handleFileSelect(e) {
        const files = e.target.files;
        if (files.length > 0) {
            this.loadFile(files[0]);
        }
    }

    async loadFile(file) {
        if (!file.type.includes('json') && !file.name.endsWith('.json')) {
            utils.notify('Please select a valid JSON file', 'error');
            return;
        }

        try {
            this.showLoading();
            const text = await file.text();
            const data = JSON.parse(text);
            this.processData(data);
        } catch (error) {
            this.showError('Failed to parse JSON file: ' + error.message);
        }
    }

    async loadFromUrl() {
        const url = document.getElementById('results-url')?.value.trim();
        if (!url) {
            utils.notify('Please enter a URL', 'warning');
            return;
        }

        try {
            this.showLoading();
            const response = await fetch(url);
            if (!response.ok) {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }
            const data = await response.json();
            this.processData(data);
            
            // Update URL params
            utils.updateUrlParams({ url });
        } catch (error) {
            this.showError('Failed to load data from URL: ' + error.message);
        }
    }

    loadFromJson() {
        const jsonText = document.getElementById('json-input')?.value.trim();
        if (!jsonText) {
            utils.notify('Please enter JSON data', 'warning');
            return;
        }

        try {
            this.showLoading();
            const data = JSON.parse(jsonText);
            this.processData(data);
            
            // Update URL params
            utils.updateUrlParams({ data: encodeURIComponent(jsonText) });
        } catch (error) {
            this.showError('Failed to parse JSON: ' + error.message);
        }
    }

    processData(data) {
        // Validate data structure
        if (!data || typeof data !== 'object') {
            throw new Error('Invalid data format');
        }

        if (!data.dll_files || !Array.isArray(data.dll_files)) {
            throw new Error('Missing or invalid dll_files array');
        }

        this.data = data;
        this.filteredData = [...data.dll_files];
        
        this.hideLoading();
        this.hideError();
        this.displayResults();
    }

    displayResults() {
        utils.show(document.getElementById('results-container'));
        
        this.updateSummary();
        this.createCharts();
        this.populateFilters();
        this.renderTable();
    }

    updateSummary() {
        const data = this.data;
        const dllFiles = data.dll_files || [];
        
        document.getElementById('total-files').textContent = data.total_files_scanned || 0;
        document.getElementById('total-dlls').textContent = dllFiles.length;
        document.getElementById('scan-duration').textContent = 
            utils.formatDuration(data.scan_duration_seconds || 0);
        
        const signedCount = dllFiles.filter(dll => dll.is_signed).length;
        document.getElementById('signed-dlls').textContent = signedCount;
    }

    createCharts() {
        this.createArchitectureChart();
        this.createCompanyChart();
    }

    createArchitectureChart() {
        const canvas = document.getElementById('architecture-chart');
        if (!canvas) return;

        // Count architectures
        const archCounts = {};
        this.data.dll_files.forEach(dll => {
            const arch = dll.architecture || 'Unknown';
            archCounts[arch] = (archCounts[arch] || 0) + 1;
        });

        const ctx = canvas.getContext('2d');
        if (this.charts.architecture) {
            this.charts.architecture.destroy();
        }

        this.charts.architecture = new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: Object.keys(archCounts),
                datasets: [{
                    data: Object.values(archCounts),
                    backgroundColor: [
                        '#4f46e5', '#06b6d4', '#10b981', '#f59e0b',
                        '#ef4444', '#8b5cf6', '#f97316', '#84cc16'
                    ]
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'bottom'
                    }
                }
            }
        });
    }

    createCompanyChart() {
        const canvas = document.getElementById('company-chart');
        if (!canvas) return;

        // Count companies (top 8)
        const companyCounts = {};
        this.data.dll_files.forEach(dll => {
            const company = dll.company_name || 'Unknown';
            companyCounts[company] = (companyCounts[company] || 0) + 1;
        });

        const sortedCompanies = Object.entries(companyCounts)
            .sort(([,a], [,b]) => b - a)
            .slice(0, 8);

        const ctx = canvas.getContext('2d');
        if (this.charts.company) {
            this.charts.company.destroy();
        }

        this.charts.company = new Chart(ctx, {
            type: 'bar',
            data: {
                labels: sortedCompanies.map(([name]) => name.length > 20 ? name.substring(0, 17) + '...' : name),
                datasets: [{
                    label: 'DLL Count',
                    data: sortedCompanies.map(([,count]) => count),
                    backgroundColor: '#4f46e5'
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        display: false
                    }
                },
                scales: {
                    y: {
                        beginAtZero: true,
                        ticks: {
                            stepSize: 1
                        }
                    }
                }
            }
        });
    }

    populateFilters() {
        // Populate architecture filter
        const architectures = [...new Set(this.data.dll_files.map(dll => dll.architecture || 'Unknown'))];
        const archFilter = document.getElementById('architecture-filter');
        if (archFilter) {
            // Clear existing options except first
            while (archFilter.children.length > 1) {
                archFilter.removeChild(archFilter.lastChild);
            }
            
            architectures.forEach(arch => {
                const option = document.createElement('option');
                option.value = arch;
                option.textContent = arch;
                archFilter.appendChild(option);
            });
        }
    }

    applyFilters() {
        const searchTerm = document.getElementById('search-input')?.value.toLowerCase() || '';
        const archFilter = document.getElementById('architecture-filter')?.value || '';
        const signedFilter = document.getElementById('signed-filter')?.value || '';

        this.filteredData = this.data.dll_files.filter(dll => {
            // Search filter
            if (searchTerm && !dll.file_name.toLowerCase().includes(searchTerm)) {
                return false;
            }

            // Architecture filter
            if (archFilter && dll.architecture !== archFilter) {
                return false;
            }

            // Signed filter
            if (signedFilter && dll.is_signed.toString() !== signedFilter) {
                return false;
            }

            return true;
        });

        this.renderTable();
    }

    renderTable() {
        const tbody = document.getElementById('dll-table-body');
        if (!tbody) return;

        tbody.innerHTML = '';

        this.filteredData.forEach((dll, index) => {
            const row = document.createElement('tr');
            
            row.innerHTML = `
                <td>${this.escapeHtml(dll.file_name)}</td>
                <td>${this.escapeHtml(dll.architecture || 'Unknown')}</td>
                <td>${this.escapeHtml(dll.company_name || 'Unknown')}</td>
                <td>${this.escapeHtml(dll.file_version || 'Unknown')}</td>
                <td>${utils.formatFileSize(dll.file_size || 0)}</td>
                <td>
                    <span class="signed-badge ${dll.is_signed ? 'signed' : 'unsigned'}">
                        ${dll.is_signed ? 'Signed' : 'Unsigned'}
                    </span>
                </td>
                <td>
                    <button class="view-btn" onclick="scanResultsViewer.showDllDetails(${index})">
                        View
                    </button>
                </td>
            `;
            
            tbody.appendChild(row);
        });
    }

    showDllDetails(index) {
        const dll = this.filteredData[index];
        if (!dll) return;

        const modal = document.getElementById('dll-modal');
        const title = document.getElementById('modal-title');
        const body = document.getElementById('modal-body');

        if (title) title.textContent = dll.file_name;
        
        if (body) {
            body.innerHTML = `
                <div class="dll-details">
                    <div class="details-grid">
                        <div class="detail-item">
                            <strong>File Path:</strong> ${this.escapeHtml(dll.file_path || 'Unknown')}
                        </div>
                        <div class="detail-item">
                            <strong>File Size:</strong> ${utils.formatFileSize(dll.file_size || 0)}
                        </div>
                        <div class="detail-item">
                            <strong>Architecture:</strong> ${this.escapeHtml(dll.architecture || 'Unknown')}
                        </div>
                        <div class="detail-item">
                            <strong>Company:</strong> ${this.escapeHtml(dll.company_name || 'Unknown')}
                        </div>
                        <div class="detail-item">
                            <strong>Product Version:</strong> ${this.escapeHtml(dll.product_version || 'Unknown')}
                        </div>
                        <div class="detail-item">
                            <strong>File Version:</strong> ${this.escapeHtml(dll.file_version || 'Unknown')}
                        </div>
                        <div class="detail-item">
                            <strong>Digital Signature:</strong> 
                            <span class="signed-badge ${dll.is_signed ? 'signed' : 'unsigned'}">
                                ${dll.is_signed ? 'Signed' : 'Unsigned'}
                            </span>
                        </div>
                        ${dll.imported_dlls && dll.imported_dlls.length > 0 ? `
                        <div class="detail-item full-width">
                            <strong>Imported DLLs (${dll.imported_dlls.length}):</strong>
                            <div class="imported-list">
                                ${dll.imported_dlls.map(imp => `<span class="import-tag">${this.escapeHtml(imp)}</span>`).join('')}
                            </div>
                        </div>
                        ` : ''}
                        ${dll.exported_functions && dll.exported_functions.length > 0 ? `
                        <div class="detail-item full-width">
                            <strong>Exported Functions (${dll.exported_functions.length}):</strong>
                            <div class="exported-list">
                                ${dll.exported_functions.slice(0, 20).map(exp => `<span class="export-tag">${this.escapeHtml(exp)}</span>`).join('')}
                                ${dll.exported_functions.length > 20 ? `<span class="more-indicator">... and ${dll.exported_functions.length - 20} more</span>` : ''}
                            </div>
                        </div>
                        ` : ''}
                    </div>
                </div>
                <style>
                    .dll-details .details-grid {
                        display: grid;
                        grid-template-columns: 1fr 1fr;
                        gap: 1rem;
                    }
                    .dll-details .detail-item {
                        padding: 0.5rem 0;
                        border-bottom: 1px solid #e5e7eb;
                    }
                    .dll-details .detail-item.full-width {
                        grid-column: 1 / -1;
                    }
                    .dll-details .imported-list,
                    .dll-details .exported-list {
                        margin-top: 0.5rem;
                        display: flex;
                        flex-wrap: wrap;
                        gap: 0.25rem;
                    }
                    .dll-details .import-tag,
                    .dll-details .export-tag {
                        background: #f3f4f6;
                        padding: 0.2rem 0.5rem;
                        border-radius: 4px;
                        font-size: 0.8rem;
                        font-family: monospace;
                    }
                    .dll-details .more-indicator {
                        color: #6b7280;
                        font-style: italic;
                        font-size: 0.9rem;
                    }
                </style>
            `;
        }

        utils.show(modal);
    }

    closeModal() {
        utils.hide(document.getElementById('dll-modal'));
    }

    exportFiltered() {
        const exportData = {
            ...this.data,
            dll_files: this.filteredData,
            total_dlls_found: this.filteredData.length,
            export_timestamp: new Date().toISOString(),
            filter_applied: true
        };

        const filename = `dll-scan-filtered-${new Date().toISOString().split('T')[0]}.json`;
        utils.downloadAsFile(JSON.stringify(exportData, null, 2), filename);
        utils.notify('Filtered results exported successfully', 'success');
    }

    exportSummary() {
        const summary = {
            scan_summary: {
                scan_path: this.data.scan_path,
                total_files_scanned: this.data.total_files_scanned,
                total_dlls_found: this.data.total_dlls_found,
                scan_duration_seconds: this.data.scan_duration_seconds,
                filtered_dlls_count: this.filteredData.length
            },
            statistics: {
                architectures: this.getArchitectureStats(),
                companies: this.getCompanyStats(),
                signed_status: this.getSignedStats()
            },
            export_timestamp: new Date().toISOString()
        };

        const filename = `dll-scan-summary-${new Date().toISOString().split('T')[0]}.json`;
        utils.downloadAsFile(JSON.stringify(summary, null, 2), filename);
        utils.notify('Summary report exported successfully', 'success');
    }

    exportCsv() {
        const headers = [
            'File Name', 'File Path', 'Architecture', 'Company', 
            'Product Version', 'File Version', 'File Size', 'Is Signed'
        ];

        const csvData = [
            headers.join(','),
            ...this.filteredData.map(dll => [
                this.escapeCsv(dll.file_name),
                this.escapeCsv(dll.file_path || ''),
                this.escapeCsv(dll.architecture || ''),
                this.escapeCsv(dll.company_name || ''),
                this.escapeCsv(dll.product_version || ''),
                this.escapeCsv(dll.file_version || ''),
                dll.file_size || 0,
                dll.is_signed ? 'Yes' : 'No'
            ].join(','))
        ].join('\n');

        const filename = `dll-scan-results-${new Date().toISOString().split('T')[0]}.csv`;
        utils.downloadAsFile(csvData, filename, 'text/csv');
        utils.notify('CSV exported successfully', 'success');
    }

    getArchitectureStats() {
        const stats = {};
        this.filteredData.forEach(dll => {
            const arch = dll.architecture || 'Unknown';
            stats[arch] = (stats[arch] || 0) + 1;
        });
        return stats;
    }

    getCompanyStats() {
        const stats = {};
        this.filteredData.forEach(dll => {
            const company = dll.company_name || 'Unknown';
            stats[company] = (stats[company] || 0) + 1;
        });
        return stats;
    }

    getSignedStats() {
        const signed = this.filteredData.filter(dll => dll.is_signed).length;
        const unsigned = this.filteredData.length - signed;
        return { signed, unsigned };
    }

    showLoading() {
        utils.show(document.getElementById('loading'));
        utils.hide(document.getElementById('results-container'));
        utils.hide(document.getElementById('error-display'));
    }

    hideLoading() {
        utils.hide(document.getElementById('loading'));
    }

    showError(message) {
        const errorDisplay = document.getElementById('error-display');
        const errorMessage = document.getElementById('error-message');
        
        if (errorMessage) errorMessage.textContent = message;
        utils.show(errorDisplay);
        utils.hide(document.getElementById('loading'));
        utils.hide(document.getElementById('results-container'));
    }

    hideError() {
        utils.hide(document.getElementById('error-display'));
    }

    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    escapeCsv(text) {
        if (text == null) return '';
        const str = String(text);
        if (str.includes(',') || str.includes('"') || str.includes('\n')) {
            return `"${str.replace(/"/g, '""')}"`;
        }
        return str;
    }
}

// Initialize when DOM is loaded
let scanResultsViewer;
document.addEventListener('DOMContentLoaded', () => {
    scanResultsViewer = new ScanResultsViewer();
});