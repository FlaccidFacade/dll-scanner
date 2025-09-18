/**
 * Changelog functionality
 */

class ChangelogViewer {
    constructor() {
        this.changelogData = null;
        this.filteredEntries = null;
        
        this.init();
    }

    init() {
        this.bindEvents();
        this.loadChangelog();
    }

    bindEvents() {
        // Search and filter
        document.getElementById('changelog-search')?.addEventListener('input', 
            utils.debounce(this.applyFilters.bind(this), 300));
        document.getElementById('version-filter')?.addEventListener('change', this.applyFilters.bind(this));
        document.getElementById('type-filter')?.addEventListener('change', this.applyFilters.bind(this));

        // Retry button
        document.getElementById('retry-btn')?.addEventListener('click', this.loadChangelog.bind(this));
    }

    async loadChangelog() {
        try {
            utils.show(document.getElementById('changelog-loading'));
            utils.hide(document.getElementById('changelog-error'));
            utils.hide(document.getElementById('changelog-content'));
            utils.hide(document.getElementById('fallback-changelog'));

            // Try to load from GitHub API first
            const response = await fetch('https://api.github.com/repos/FlaccidFacade/dll-scanner/contents/CHANGELOG.md');
            
            if (response.ok) {
                const data = await response.json();
                const content = atob(data.content);
                this.parseChangelog(content);
            } else {
                throw new Error('Failed to fetch from GitHub API');
            }
        } catch (error) {
            console.error('Error loading changelog:', error);
            this.showFallback();
        }
    }

    parseChangelog(content) {
        try {
            const entries = this.parseMarkdownChangelog(content);
            if (entries.length > 0) {
                this.changelogData = entries;
                this.filteredEntries = [...entries];
                this.displayChangelog();
            } else {
                throw new Error('No changelog entries found');
            }
        } catch (error) {
            console.error('Error parsing changelog:', error);
            this.showFallback();
        }
    }

    parseMarkdownChangelog(content) {
        const entries = [];
        const lines = content.split('\n');
        let currentEntry = null;
        let currentSection = null;

        for (let i = 0; i < lines.length; i++) {
            const line = lines[i].trim();

            // Version header: ## [version] - date
            const versionMatch = line.match(/^##\s*\[([^\]]+)\]\s*-\s*(.+)/);
            if (versionMatch) {
                if (currentEntry) {
                    entries.push(currentEntry);
                }

                currentEntry = {
                    version: versionMatch[1],
                    date: versionMatch[2],
                    sections: {},
                    raw_content: []
                };
                currentSection = null;
                continue;
            }

            // Section header: ### Added, ### Changed, etc.
            const sectionMatch = line.match(/^###\s*(.+)/);
            if (sectionMatch && currentEntry) {
                const sectionType = sectionMatch[1].toLowerCase();
                currentSection = sectionType;
                currentEntry.sections[sectionType] = [];
                continue;
            }

            // List items
            if (line.startsWith('-') && currentEntry && currentSection) {
                const item = line.substring(1).trim();
                currentEntry.sections[currentSection].push(item);
            }

            // Store raw content for fallback
            if (currentEntry) {
                currentEntry.raw_content.push(line);
            }
        }

        if (currentEntry) {
            entries.push(currentEntry);
        }

        return entries;
    }

    displayChangelog() {
        utils.hide(document.getElementById('changelog-loading'));
        utils.hide(document.getElementById('changelog-error'));
        utils.show(document.getElementById('changelog-content'));

        this.populateFilters();
        this.renderTimeline();
    }

    populateFilters() {
        // Populate version filter
        const versionFilter = document.getElementById('version-filter');
        if (versionFilter && this.changelogData) {
            // Clear existing options except first
            while (versionFilter.children.length > 1) {
                versionFilter.removeChild(versionFilter.lastChild);
            }

            this.changelogData.forEach(entry => {
                const option = document.createElement('option');
                option.value = entry.version;
                option.textContent = `v${entry.version}`;
                versionFilter.appendChild(option);
            });
        }
    }

    applyFilters() {
        const searchTerm = document.getElementById('changelog-search')?.value.toLowerCase() || '';
        const versionFilter = document.getElementById('version-filter')?.value || '';
        const typeFilter = document.getElementById('type-filter')?.value || '';

        this.filteredEntries = this.changelogData.filter(entry => {
            // Version filter
            if (versionFilter && entry.version !== versionFilter) {
                return false;
            }

            // Type filter
            if (typeFilter && !entry.sections[typeFilter]) {
                return false;
            }

            // Search filter
            if (searchTerm) {
                const searchableText = [
                    entry.version,
                    entry.date,
                    ...Object.values(entry.sections).flat()
                ].join(' ').toLowerCase();

                if (!searchableText.includes(searchTerm)) {
                    return false;
                }
            }

            return true;
        });

        this.renderTimeline();
    }

    renderTimeline() {
        const timeline = document.getElementById('changelog-timeline');
        if (!timeline) return;

        timeline.innerHTML = '';

        this.filteredEntries.forEach(entry => {
            const entryElement = this.createVersionEntry(entry);
            timeline.appendChild(entryElement);
        });

        if (this.filteredEntries.length === 0) {
            timeline.innerHTML = '<div class="no-results">No changelog entries match your filters.</div>';
        }
    }

    createVersionEntry(entry) {
        const entryDiv = document.createElement('div');
        entryDiv.className = 'version-entry';

        const badge = this.getVersionBadge(entry.version);
        
        entryDiv.innerHTML = `
            <div class="version-header">
                <h3 class="version-number">v${this.escapeHtml(entry.version)}</h3>
                <span class="version-date">${this.escapeHtml(entry.date)}</span>
                ${badge ? `<span class="version-badge ${badge.class}">${badge.text}</span>` : ''}
            </div>
            <div class="version-content">
                ${this.renderSections(entry.sections)}
            </div>
        `;

        return entryDiv;
    }

    renderSections(sections) {
        const sectionOrder = ['added', 'changed', 'deprecated', 'removed', 'fixed', 'security'];
        const sectionIcons = {
            added: '✨',
            changed: '🔄',
            deprecated: '⚠️',
            removed: '🗑️',
            fixed: '🐛',
            security: '🛡️'
        };

        let html = '';

        // Render ordered sections first
        sectionOrder.forEach(sectionType => {
            if (sections[sectionType] && sections[sectionType].length > 0) {
                const icon = sectionIcons[sectionType] || '•';
                const title = sectionType.charAt(0).toUpperCase() + sectionType.slice(1);
                
                html += `
                    <div class="change-section">
                        <h4 class="change-type ${sectionType}">${icon} ${title}</h4>
                        <ul class="change-list">
                            ${sections[sectionType].map(item => 
                                `<li>${this.formatChangeItem(item)}</li>`
                            ).join('')}
                        </ul>
                    </div>
                `;
            }
        });

        // Render any other sections
        Object.keys(sections).forEach(sectionType => {
            if (!sectionOrder.includes(sectionType) && sections[sectionType].length > 0) {
                const title = sectionType.charAt(0).toUpperCase() + sectionType.slice(1);
                
                html += `
                    <div class="change-section">
                        <h4 class="change-type">${title}</h4>
                        <ul class="change-list">
                            ${sections[sectionType].map(item => 
                                `<li>${this.formatChangeItem(item)}</li>`
                            ).join('')}
                        </ul>
                    </div>
                `;
            }
        });

        return html || '<p class="no-changes">No detailed changes available.</p>';
    }

    formatChangeItem(item) {
        // Convert markdown-style formatting
        let formatted = this.escapeHtml(item);
        
        // Bold text
        formatted = formatted.replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>');
        
        // Inline code
        formatted = formatted.replace(/`([^`]+)`/g, '<code>$1</code>');
        
        // Links
        formatted = formatted.replace(/\[([^\]]+)\]\(([^)]+)\)/g, '<a href="$2" target="_blank">$1</a>');

        return formatted;
    }

    getVersionBadge(version) {
        // Determine version type based on semantic versioning
        const parts = version.split('.');
        
        if (parts[0] === '0' && parts[1] === '1' && parts[2] === '0') {
            return { class: 'initial', text: 'Initial Release' };
        }
        
        if (parts[2] === '0' && parts[1] === '0') {
            return { class: 'major', text: 'Major Release' };
        }
        
        if (parts[2] === '0') {
            return { class: 'minor', text: 'Minor Release' };
        }
        
        return { class: 'patch', text: 'Patch Release' };
    }

    showFallback() {
        utils.hide(document.getElementById('changelog-loading'));
        utils.show(document.getElementById('changelog-error'));
        utils.show(document.getElementById('fallback-changelog'));
        
        // If we have some data but couldn't parse it fully, show what we have
        if (this.changelogData && this.changelogData.length > 0) {
            utils.hide(document.getElementById('changelog-error'));
            this.displayChangelog();
        }
    }

    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }
}

// Initialize when DOM is loaded
let changelogViewer;
document.addEventListener('DOMContentLoaded', () => {
    changelogViewer = new ChangelogViewer();
});