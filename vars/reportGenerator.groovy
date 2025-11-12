#!/usr/bin/env groovy

import org.jenkins.plugins.validator.PDFGenerator

def generateReports() {
    echo "📝 Generating validation reports..."
    
    def pluginData = readJSON text: env.PLUGIN_DATA
    def vulnData = readJSON text: env.VULNERABILITIES
    def outdatedData = readJSON text: env.OUTDATED_PLUGINS
    
    // Generate HTML Report
    def htmlReport = generateHTMLReport(
        pluginData,
        vulnData,
        outdatedData,
        env.RISK_SCORE,
        env.RISK_RATING
    )
    
    writeFile file: 'plugin-validation-report.html', text: htmlReport
    
    // Generate JSON Report
    def jsonReport = groovy.json.JsonOutput.prettyPrint(
        groovy.json.JsonOutput.toJson([
            timestamp: new Date().format('yyyy-MM-dd HH:mm:ss', TimeZone.getTimeZone('UTC')),
            jenkins_version: Jenkins.instance.version.toString(),
            total_plugins: pluginData.size(),
            outdated_plugins: Integer.parseInt(env.OUTDATED_COUNT),
            vulnerabilities: Integer.parseInt(env.VULN_COUNT),
            critical_vulns: Integer.parseInt(env.CRITICAL_COUNT),
            high_vulns: Integer.parseInt(env.HIGH_COUNT),
            medium_vulns: Integer.parseInt(env.MEDIUM_COUNT),
            risk_score: Integer.parseInt(env.RISK_SCORE),
            risk_rating: env.RISK_RATING,
            sbom_generated: env.SBOM_GENERATED == 'true',
            scan_source: 'Jenkins Update Center',
            plugins: pluginData,
            vulnerable_plugins: vulnData,
            outdated_plugins_list: outdatedData
        ])
    )
    
    writeFile file: 'plugin-validation-report.json', text: jsonReport
    
    archiveArtifacts artifacts: '*.html,*.json'
    
    try {
        publishHTML([
            allowMissing: false,
            alwaysLinkToLastBuild: true,
            keepAll: true,
            reportDir: '.',
            reportFiles: 'plugin-validation-report.html',
            reportName: 'Plugin Validation Report',
            reportTitles: 'Jenkins Plugin Security Report'
        ])
    } catch (Exception e) {
        echo "⚠️ HTML Publisher not available: ${e.message}"
        echo "💡 Install 'HTML Publisher Plugin' to view reports in Jenkins UI"
    }
    
    echo "✅ Reports generated successfully!"
}

def sendSuccessNotification() {
    echo "✅ Plugin validation completed successfully!"
    
    // Check if Slack is available
    def hasSlack = checkPluginInstalled('slack')
    
    if (!hasSlack) {
        echo "💡 Slack plugin not installed. Skipping Slack notification."
        echo "💡 Install 'Slack Notification Plugin' to enable Slack alerts"
        return
    }
    
    try {
        def pluginCount = readJSON(text: env.PLUGIN_DATA).size()
        
        slackSend(
            color: env.RISK_RATING == 'LOW' ? 'good' : env.RISK_RATING == 'CRITICAL' ? 'danger' : 'warning',
            message: """
                🔒 Jenkins Plugin Validation Report
                
                *Status:* ${currentBuild.result}
                *Total Plugins:* ${pluginCount}
                *Risk Score:* ${env.RISK_SCORE}/100 (${env.RISK_RATING})
                
                *Vulnerabilities Found:*
                • Critical: ${env.CRITICAL_COUNT}
                • High: ${env.HIGH_COUNT}
                • Medium: ${env.MEDIUM_COUNT}
                
                *Outdated Plugins:* ${env.OUTDATED_COUNT}
                *SBOM:* ${env.SBOM_GENERATED == 'true' ? '✅ Generated' : 'Skipped'}
                
                <${env.BUILD_URL}Plugin_20Validation_20Report/|📊 View Full Report>
            """.stripIndent()
        )
    } catch (Exception e) {
        echo "⚠️ Slack notification failed: ${e.message}"
        echo "💡 Configure Slack webhook in Jenkins: Manage Jenkins → Configure System → Slack"
    }
}

def sendSecurityAlert() {
    if (currentBuild.result != 'UNSTABLE') {
        return
    }
    
    echo "⚠️ Vulnerabilities detected!"
    
    // Check if Slack is available
    def hasSlack = checkPluginInstalled('slack')
    
    if (!hasSlack) {
        echo "💡 Slack plugin not installed. Skipping security alert."
        return
    }
    
    try {
        slackSend(
            color: 'danger',
            message: """
                🚨 SECURITY ALERT: Vulnerable Jenkins Plugins Detected
                
                *Critical:* ${env.CRITICAL_COUNT}
                *High:* ${env.HIGH_COUNT}
                *Risk Score:* ${env.RISK_SCORE}/100 (${env.RISK_RATING})
                
                <${env.BUILD_URL}Plugin_20Validation_20Report/|🔍 View Full Report>
                
                ⚠️ Immediate action required!
            """.stripIndent()
        )
    } catch (Exception e) {
        echo "⚠️ Security alert via Slack failed: ${e.message}"
    }
}

@NonCPS
def checkPluginInstalled(String pluginName) {
    def jenkins = Jenkins.instance
    def pluginManager = jenkins.pluginManager
    def plugin = pluginManager.getPlugin(pluginName)
    return plugin != null && plugin.isEnabled()
}

@NonCPS
private String generateHTMLReport(plugins, vulnerabilities, outdated, riskScore, riskRating) {
    def timestamp = new Date().format('yyyy-MM-dd HH:mm:ss', TimeZone.getTimeZone('UTC'))
    def jenkins = Jenkins.instance
    
    // Convert data to JSON for JavaScript
    def pluginsJson = groovy.json.JsonOutput.toJson(plugins)
    def vulnJson = groovy.json.JsonOutput.toJson(vulnerabilities)
    def outdatedJson = groovy.json.JsonOutput.toJson(outdated)
    
    return """
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Jenkins Plugin Validation Report</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            background: #f5f7fa;
            padding: 20px;
            line-height: 1.6;
        }
        
        .container { 
            max-width: 1400px; 
            margin: 0 auto; 
        }
        
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px;
            border-radius: 12px;
            margin-bottom: 30px;
            box-shadow: 0 4px 12px rgba(0,0,0,0.15);
        }
        
        .header h1 { 
            font-size: 36px; 
            margin-bottom: 10px;
            font-weight: 700;
        }
        
        .header p {
            font-size: 16px;
            opacity: 0.95;
            margin: 5px 0;
        }
        
        .stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .stat-card {
            background: white;
            padding: 30px;
            border-radius: 12px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
            transition: transform 0.2s, box-shadow 0.2s;
        }
        
        .stat-card:hover {
            transform: translateY(-4px);
            box-shadow: 0 4px 16px rgba(0,0,0,0.15);
        }
        
        .stat-card h3 {
            color: #666;
            font-size: 13px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-bottom: 12px;
            font-weight: 600;
        }
        
        .stat-card .value {
            font-size: 42px;
            font-weight: 700;
            color: #333;
            line-height: 1;
        }
        
        .risk-critical { color: #dc3545; }
        .risk-high { color: #fd7e14; }
        .risk-medium { color: #ffc107; }
        .risk-low { color: #28a745; }
        
        .section {
            background: white;
            padding: 30px;
            border-radius: 12px;
            margin-bottom: 25px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        }
        
        .section h2 {
            margin-bottom: 20px;
            color: #333;
            font-size: 24px;
            font-weight: 700;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        /* Table Styles */
        .table-container {
            overflow-x: auto;
            margin-top: 20px;
        }
        
        table {
            width: 100%;
            border-collapse: collapse;
            font-size: 14px;
        }
        
        thead {
            position: sticky;
            top: 0;
            z-index: 10;
        }
        
        th {
            background: #f8f9fa;
            padding: 14px 12px;
            text-align: left;
            font-weight: 600;
            border-bottom: 2px solid #dee2e6;
            color: #495057;
            font-size: 13px;
            text-transform: uppercase;
            letter-spacing: 0.3px;
            cursor: pointer;
            user-select: none;
        }
        
        th:hover {
            background: #e9ecef;
        }
        
        th.sortable::after {
            content: ' ⇅';
            opacity: 0.3;
        }
        
        th.sort-asc::after {
            content: ' ↑';
            opacity: 1;
        }
        
        th.sort-desc::after {
            content: ' ↓';
            opacity: 1;
        }
        
        td {
            padding: 14px 12px;
            border-bottom: 1px solid #e9ecef;
            color: #495057;
        }
        
        tr:hover {
            background: #f8f9fa;
        }
        
        tr:last-child td {
            border-bottom: none;
        }
        
        .badge {
            display: inline-block;
            padding: 5px 14px;
            border-radius: 14px;
            font-size: 11px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.3px;
        }
        
        .badge-critical { background: #dc3545; color: white; }
        .badge-high { background: #fd7e14; color: white; }
        .badge-medium { background: #ffc107; color: #212529; }
        .badge-low { background: #28a745; color: white; }
        .badge-enabled { background: #28a745; color: white; }
        .badge-disabled { background: #6c757d; color: white; }
        .badge-update { background: #17a2b8; color: white; }
        
        /* Search and Filter */
        .controls {
            display: flex;
            gap: 15px;
            margin-bottom: 20px;
            flex-wrap: wrap;
            align-items: center;
        }
        
        .search-box {
            flex: 1;
            min-width: 250px;
        }
        
        .search-box input {
            width: 100%;
            padding: 10px 15px;
            border: 2px solid #e9ecef;
            border-radius: 8px;
            font-size: 14px;
            transition: border-color 0.2s;
        }
        
        .search-box input:focus {
            outline: none;
            border-color: #667eea;
        }
        
        .filter-group {
            display: flex;
            gap: 10px;
            align-items: center;
        }
        
        .filter-group label {
            font-size: 14px;
            color: #666;
            font-weight: 500;
        }
        
        select {
            padding: 8px 12px;
            border: 2px solid #e9ecef;
            border-radius: 8px;
            font-size: 14px;
            background: white;
            cursor: pointer;
        }
        
        /* Pagination */
        .pagination {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-top: 20px;
            padding-top: 20px;
            border-top: 2px solid #e9ecef;
        }
        
        .pagination-info {
            color: #666;
            font-size: 14px;
        }
        
        .pagination-controls {
            display: flex;
            gap: 8px;
        }
        
        .pagination button {
            padding: 8px 16px;
            border: 2px solid #e9ecef;
            background: white;
            border-radius: 8px;
            cursor: pointer;
            font-size: 14px;
            font-weight: 500;
            transition: all 0.2s;
        }
        
        .pagination button:hover:not(:disabled) {
            background: #667eea;
            color: white;
            border-color: #667eea;
        }
        
        .pagination button:disabled {
            opacity: 0.4;
            cursor: not-allowed;
        }
        
        .pagination button.active {
            background: #667eea;
            color: white;
            border-color: #667eea;
        }
        
        /* Links */
        a {
            color: #667eea;
            text-decoration: none;
            font-weight: 500;
        }
        
        a:hover {
            text-decoration: underline;
        }
        
        /* Empty state */
        .empty-state {
            text-align: center;
            padding: 60px 20px;
            color: #6c757d;
        }
        
        .empty-state svg {
            width: 80px;
            height: 80px;
            margin-bottom: 20px;
            opacity: 0.3;
        }
        
        /* Responsive */
        @media (max-width: 768px) {
            .header h1 { font-size: 28px; }
            .stat-card .value { font-size: 32px; }
            .controls { flex-direction: column; }
            .search-box { width: 100%; }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔒 Jenkins Plugin Validation Report</h1>
            <p><strong>Generated:</strong> ${timestamp} UTC</p>
            <p><strong>Jenkins Version:</strong> ${jenkins.version}</p>
            <p><strong>Scan Source:</strong> Jenkins Update Center (Live)</p>
            <p><strong>Report By:</strong> duncanlester</p>
        </div>
        
        <div class="stats">
            <div class="stat-card">
                <h3>Total Plugins</h3>
                <div class="value">${plugins.size()}</div>
            </div>
            <div class="stat-card">
                <h3>Vulnerabilities</h3>
                <div class="value risk-${riskRating.toLowerCase()}">${vulnerabilities.size()}</div>
            </div>
            <div class="stat-card">
                <h3>Outdated</h3>
                <div class="value">${outdated.size()}</div>
            </div>
            <div class="stat-card">
                <h3>Risk Score</h3>
                <div class="value risk-${riskRating.toLowerCase()}">${riskScore}/100</div>
                <span class="badge badge-${riskRating.toLowerCase()}">${riskRating}</span>
            </div>
        </div>
        
        ${vulnerabilities.size() > 0 ? """
        <div class="section" id="vulnerabilities-section">
            <h2>🚨 Vulnerable Plugins</h2>
            <div class="table-container">
                <table id="vulnTable">
                    <thead>
                        <tr>
                            <th class="sortable" data-column="plugin">Plugin Name</th>
                            <th class="sortable" data-column="version">Version</th>
                            <th class="sortable" data-column="cve">CVE/Advisory</th>
                            <th class="sortable" data-column="severity">Severity</th>
                            <th>Description</th>
                            <th>Link</th>
                        </tr>
                    </thead>
                    <tbody id="vulnTableBody">
                    </tbody>
                </table>
            </div>
        </div>
        """ : '<div class="section"><h2>✅ No Vulnerabilities Detected</h2><p>All plugins are secure according to Jenkins Update Center.</p></div>'}
        
        ${outdated.size() > 0 ? """
        <div class="section" id="outdated-section">
            <h2>📦 Plugins With Available Updates</h2>
            <div class="controls">
                <div class="search-box">
                    <input type="text" id="outdatedSearch" placeholder="🔍 Search outdated plugins..." />
                </div>
            </div>
            <div class="table-container">
                <table id="outdatedTable">
                    <thead>
                        <tr>
                            <th class="sortable" data-column="longName">Plugin Name</th>
                            <th class="sortable" data-column="shortName">Short Name</th>
                            <th class="sortable" data-column="version">Current Version</th>
                            <th>Status</th>
                        </tr>
                    </thead>
                    <tbody id="outdatedTableBody">
                    </tbody>
                </table>
            </div>
            <div class="pagination" id="outdatedPagination"></div>
        </div>
        """ : ''}
        
        <div class="section" id="all-plugins-section">
            <h2>📋 All Installed Plugins (${plugins.size()})</h2>
            <div class="controls">
                <div class="search-box">
                    <input type="text" id="pluginSearch" placeholder="🔍 Search plugins by name or short name..." />
                </div>
                <div class="filter-group">
                    <label>Status:</label>
                    <select id="statusFilter">
                        <option value="all">All</option>
                        <option value="enabled">Enabled</option>
                        <option value="disabled">Disabled</option>
                    </select>
                </div>
                <div class="filter-group">
                    <label>Per Page:</label>
                    <select id="perPageSelect">
                        <option value="25">25</option>
                        <option value="50" selected>50</option>
                        <option value="100">100</option>
                        <option value="all">All</option>
                    </select>
                </div>
            </div>
            <div class="table-container">
                <table id="pluginTable">
                    <thead>
                        <tr>
                            <th class="sortable" data-column="longName">Plugin Name</th>
                            <th class="sortable" data-column="shortName">Short Name</th>
                            <th class="sortable" data-column="version">Version</th>
                            <th class="sortable" data-column="enabled">Status</th>
                            <th>Active</th>
                            <th>Dependencies</th>
                        </tr>
                    </thead>
                    <tbody id="pluginTableBody">
                    </tbody>
                </table>
            </div>
            <div class="pagination" id="pluginPagination"></div>
        </div>
    </div>

    <script>
        // Data from Jenkins
        const allPlugins = ${pluginsJson};
        const vulnerabilities = ${vulnJson};
        const outdatedPlugins = ${outdatedJson};
        
        // State
        let currentPage = 1;
        let perPage = 50;
        let filteredPlugins = [...allPlugins];
        let sortColumn = null;
        let sortDirection = 'asc';
        
        let outdatedCurrentPage = 1;
        let outdatedPerPage = 25;
        let filteredOutdated = [...outdatedPlugins];
        
        // Initialize
        document.addEventListener('DOMContentLoaded', function() {
            renderVulnerabilities();
            renderPlugins();
            renderOutdated();
            setupEventListeners();
        });
        
        function renderVulnerabilities() {
            const tbody = document.getElementById('vulnTableBody');
            if (!tbody) return;
            
            tbody.innerHTML = vulnerabilities.map(vuln => \`
                <tr>
                    <td><strong>\${escapeHtml(vuln.plugin)}</strong></td>
                    <td>\${escapeHtml(vuln.version)}</td>
                    <td>\${escapeHtml(vuln.cve)}</td>
                    <td><span class="badge badge-\${vuln.severity.toLowerCase()}">\${vuln.severity}</span></td>
                    <td>\${escapeHtml(vuln.description || 'N/A')}</td>
                    <td>\${vuln.url ? \`<a href="\${vuln.url}" target="_blank">View ↗</a>\` : 'N/A'}</td>
                </tr>
            \`).join('');
        }
        
        function renderOutdated() {
            if (!outdatedPlugins.length) return;
            
            const tbody = document.getElementById('outdatedTableBody');
            const start = (outdatedCurrentPage - 1) * outdatedPerPage;
            const end = start + outdatedPerPage;
            const pageData = filteredOutdated.slice(start, end);
            
            tbody.innerHTML = pageData.map(plugin => \`
                <tr>
                    <td><strong>\${escapeHtml(plugin.longName)}</strong></td>
                    <td><code>\${escapeHtml(plugin.shortName)}</code></td>
                    <td>\${escapeHtml(plugin.version)}</td>
                    <td><span class="badge badge-update">UPDATE AVAILABLE</span></td>
                </tr>
            \`).join('');
            
            renderOutdatedPagination();
        }
        
        function renderOutdatedPagination() {
            const container = document.getElementById('outdatedPagination');
            if (!container) return;
            
            const totalPages = Math.ceil(filteredOutdated.length / outdatedPerPage);
            const start = (outdatedCurrentPage - 1) * outdatedPerPage + 1;
            const end = Math.min(outdatedCurrentPage * outdatedPerPage, filteredOutdated.length);
            
            container.innerHTML = \`
                <div class="pagination-info">
                    Showing \${start}-\${end} of \${filteredOutdated.length} plugins
                </div>
                <div class="pagination-controls">
                    <button onclick="outdatedGoToPage(1)" \${outdatedCurrentPage === 1 ? 'disabled' : ''}>First</button>
                    <button onclick="outdatedGoToPage(\${outdatedCurrentPage - 1})" \${outdatedCurrentPage === 1 ? 'disabled' : ''}>Previous</button>
                    <span style="padding: 8px 16px;">Page \${outdatedCurrentPage} of \${totalPages}</span>
                    <button onclick="outdatedGoToPage(\${outdatedCurrentPage + 1})" \${outdatedCurrentPage === totalPages ? 'disabled' : ''}>Next</button>
                    <button onclick="outdatedGoToPage(\${totalPages})" \${outdatedCurrentPage === totalPages ? 'disabled' : ''}>Last</button>
                </div>
            \`;
        }
        
        function renderPlugins() {
            const tbody = document.getElementById('pluginTableBody');
            
            // Calculate pagination
            const totalItems = filteredPlugins.length;
            const totalPages = perPage === 'all' ? 1 : Math.ceil(totalItems / perPage);
            const start = perPage === 'all' ? 0 : (currentPage - 1) * perPage;
            const end = perPage === 'all' ? totalItems : start + parseInt(perPage);
            const pageData = filteredPlugins.slice(start, end);
            
            // Render rows
            tbody.innerHTML = pageData.map(plugin => \`
                <tr>
                    <td><strong>\${escapeHtml(plugin.longName)}</strong></td>
                    <td><code>\${escapeHtml(plugin.shortName)}</code></td>
                    <td>\${escapeHtml(plugin.version)}</td>
                    <td><span class="badge badge-\${plugin.enabled ? 'enabled' : 'disabled'}">\${plugin.enabled ? 'ENABLED' : 'DISABLED'}</span></td>
                    <td>\${plugin.active ? '✅' : '❌'}</td>
                    <td>\${plugin.dependencies.length || 0}</td>
                </tr>
            \`).join('');
            
            renderPagination();
        }
        
        function renderPagination() {
            const container = document.getElementById('pluginPagination');
            const totalItems = filteredPlugins.length;
            
            if (perPage === 'all') {
                container.innerHTML = \`
                    <div class="pagination-info">Showing all \${totalItems} plugins</div>
                \`;
                return;
            }
            
            const totalPages = Math.ceil(totalItems / perPage);
            const start = (currentPage - 1) * perPage + 1;
            const end = Math.min(currentPage * perPage, totalItems);
            
            container.innerHTML = \`
                <div class="pagination-info">
                    Showing \${start}-\${end} of \${totalItems} plugins
                </div>
                <div class="pagination-controls">
                    <button onclick="goToPage(1)" \${currentPage === 1 ? 'disabled' : ''}>First</button>
                    <button onclick="goToPage(\${currentPage - 1})" \${currentPage === 1 ? 'disabled' : ''}>Previous</button>
                    <span style="padding: 8px 16px;">Page \${currentPage} of \${totalPages}</span>
                    <button onclick="goToPage(\${currentPage + 1})" \${currentPage === totalPages ? 'disabled' : ''}>Next</button>
                    <button onclick="goToPage(\${totalPages})" \${currentPage === totalPages ? 'disabled' : ''}>Last</button>
                </div>
            \`;
        }
        
        function goToPage(page) {
            const totalPages = Math.ceil(filteredPlugins.length / perPage);
            currentPage = Math.max(1, Math.min(page, totalPages));
            renderPlugins();
        }
        
        function outdatedGoToPage(page) {
            const totalPages = Math.ceil(filteredOutdated.length / outdatedPerPage);
            outdatedCurrentPage = Math.max(1, Math.min(page, totalPages));
            renderOutdated();
        }
        
        function setupEventListeners() {
            // Plugin search
            const searchInput = document.getElementById('pluginSearch');
            if (searchInput) {
                searchInput.addEventListener('input', function(e) {
                    const query = e.target.value.toLowerCase();
                    filteredPlugins = allPlugins.filter(p => 
                        p.longName.toLowerCase().includes(query) || 
                        p.shortName.toLowerCase().includes(query)
                    );
                    currentPage = 1;
                    renderPlugins();
                });
            }
            
            // Status filter
            const statusFilter = document.getElementById('statusFilter');
            if (statusFilter) {
                statusFilter.addEventListener('change', function(e) {
                    const status = e.target.value;
                    const query = document.getElementById('pluginSearch').value.toLowerCase();
                    
                    filteredPlugins = allPlugins.filter(p => {
                        const matchesSearch = p.longName.toLowerCase().includes(query) || 
                                            p.shortName.toLowerCase().includes(query);
                        const matchesStatus = status === 'all' || 
                                            (status === 'enabled' && p.enabled) || 
                                            (status === 'disabled' && !p.enabled);
                        return matchesSearch && matchesStatus;
                    });
                    
                    currentPage = 1;
                    renderPlugins();
                });
            }
            
            // Per page selector
            const perPageSelect = document.getElementById('perPageSelect');
            if (perPageSelect) {
                perPageSelect.addEventListener('change', function(e) {
                    perPage = e.target.value === 'all' ? 'all' : parseInt(e.target.value);
                    currentPage = 1;
                    renderPlugins();
                });
            }
            
            // Outdated search
            const outdatedSearch = document.getElementById('outdatedSearch');
            if (outdatedSearch) {
                outdatedSearch.addEventListener('input', function(e) {
                    const query = e.target.value.toLowerCase();
                    filteredOutdated = outdatedPlugins.filter(p => 
                        p.longName.toLowerCase().includes(query) || 
                        p.shortName.toLowerCase().includes(query)
                    );
                    outdatedCurrentPage = 1;
                    renderOutdated();
                });
            }
            
            // Table sorting
            document.querySelectorAll('th.sortable').forEach(th => {
                th.addEventListener('click', function() {
                    const column = this.dataset.column;
                    const table = this.closest('table').id;
                    
                    if (table === 'pluginTable') {
                        sortPlugins(column);
                    }
                });
            });
        }
        
        function sortPlugins(column) {
            if (sortColumn === column) {
                sortDirection = sortDirection === 'asc' ? 'desc' : 'asc';
            } else {
                sortColumn = column;
                sortDirection = 'asc';
            }
            
            filteredPlugins.sort((a, b) => {
                let aVal = a[column];
                let bVal = b[column];
                
                if (typeof aVal === 'string') {
                    aVal = aVal.toLowerCase();
                    bVal = bVal.toLowerCase();
                }
                
                if (sortDirection === 'asc') {
                    return aVal > bVal ? 1 : -1;
                } else {
                    return aVal < bVal ? 1 : -1;
                }
            });
            
            // Update sort indicators
            document.querySelectorAll('#pluginTable th.sortable').forEach(th => {
                th.classList.remove('sort-asc', 'sort-desc');
                if (th.dataset.column === column) {
                    th.classList.add('sort-' + sortDirection);
                }
            });
            
            renderPlugins();
        }
        
        function escapeHtml(text) {
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        }
    </script>
</body>
</html>
    """
}
