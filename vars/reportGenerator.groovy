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
    
    // Escape the JSON properly for embedding in JavaScript
    def pluginsJson = groovy.json.JsonOutput.toJson(plugins)
    def vulnJson = groovy.json.JsonOutput.toJson(vulnerabilities)
    def outdatedJson = groovy.json.JsonOutput.toJson(outdated)
    
    return """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Jenkins Plugin Validation Report</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #f5f7fa;
            padding: 20px;
            line-height: 1.6;
        }
        .container { max-width: 1600px; margin: 0 auto; }
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px;
            border-radius: 12px;
            margin-bottom: 30px;
            box-shadow: 0 4px 12px rgba(0,0,0,0.15);
        }
        .header h1 { font-size: 36px; margin-bottom: 10px; font-weight: 700; }
        .header p { font-size: 16px; opacity: 0.95; margin: 5px 0; }
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
            transition: transform 0.2s;
        }
        .stat-card:hover { transform: translateY(-4px); }
        .stat-card h3 {
            color: #666;
            font-size: 13px;
            text-transform: uppercase;
            margin-bottom: 12px;
            font-weight: 600;
        }
        .stat-card .value { font-size: 42px; font-weight: 700; color: #333; }
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
        .section h2 { margin-bottom: 20px; color: #333; font-size: 24px; font-weight: 700; }
        .controls {
            display: flex;
            gap: 15px;
            margin-bottom: 20px;
            flex-wrap: wrap;
            align-items: center;
        }
        .search-box { flex: 1; min-width: 250px; }
        .search-box input {
            width: 100%;
            padding: 10px 15px;
            border: 2px solid #e9ecef;
            border-radius: 8px;
            font-size: 14px;
        }
        .search-box input:focus { outline: none; border-color: #667eea; }
        .filter-group { display: flex; gap: 10px; align-items: center; }
        .filter-group label { font-size: 14px; color: #666; font-weight: 500; }
        select {
            padding: 8px 12px;
            border: 2px solid #e9ecef;
            border-radius: 8px;
            font-size: 14px;
            background: white;
            cursor: pointer;
        }
        .table-container { overflow-x: auto; margin-top: 20px; }
        table { width: 100%; border-collapse: collapse; font-size: 14px; }
        th {
            background: #f8f9fa;
            padding: 14px 12px;
            text-align: left;
            font-weight: 600;
            border-bottom: 2px solid #dee2e6;
            color: #495057;
            font-size: 13px;
            text-transform: uppercase;
            cursor: pointer;
            user-select: none;
        }
        th:hover { background: #e9ecef; }
        th.sortable::after { content: ' ⇅'; opacity: 0.3; }
        th.sort-asc::after { content: ' ↑'; opacity: 1; }
        th.sort-desc::after { content: ' ↓'; opacity: 1; }
        td { padding: 14px 12px; border-bottom: 1px solid #e9ecef; color: #495057; }
        tr:hover { background: #f8f9fa; }
        .badge {
            display: inline-block;
            padding: 5px 14px;
            border-radius: 14px;
            font-size: 11px;
            font-weight: 600;
            text-transform: uppercase;
        }
        .badge-critical { background: #dc3545; color: white; }
        .badge-high { background: #fd7e14; color: white; }
        .badge-medium { background: #ffc107; color: #212529; }
        .badge-low { background: #28a745; color: white; }
        .badge-enabled { background: #28a745; color: white; }
        .badge-disabled { background: #6c757d; color: white; }
        .badge-update { background: #17a2b8; color: white; }
        .pagination {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-top: 20px;
            padding-top: 20px;
            border-top: 2px solid #e9ecef;
        }
        .pagination-info { color: #666; font-size: 14px; }
        .pagination-controls { display: flex; gap: 8px; }
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
        .pagination button:disabled { opacity: 0.4; cursor: not-allowed; }
        a { color: #667eea; text-decoration: none; font-weight: 500; }
        a:hover { text-decoration: underline; }
        code {
            background: #f8f9fa;
            padding: 2px 6px;
            border-radius: 4px;
            font-family: 'Courier New', monospace;
            font-size: 12px;
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
        <div class="section">
            <h2>🚨 Vulnerable Plugins</h2>
            <table>
                <thead>
                    <tr>
                        <th>Plugin</th>
                        <th>Version</th>
                        <th>CVE</th>
                        <th>Severity</th>
                        <th>Description</th>
                        <th>Link</th>
                    </tr>
                </thead>
                <tbody>
                    ${vulnerabilities.collect { v -> """
                    <tr>
                        <td><strong>${v.plugin}</strong></td>
                        <td>${v.version}</td>
                        <td>${v.cve}</td>
                        <td><span class="badge badge-${v.severity.toLowerCase()}">${v.severity}</span></td>
                        <td>${v.description ?: 'N/A'}</td>
                        <td>${v.url ? "<a href='${v.url}' target='_blank'>View ↗</a>" : 'N/A'}</td>
                    </tr>
                    """ }.join('')}
                </tbody>
            </table>
        </div>
        """ : '<div class="section"><h2>✅ No Vulnerabilities</h2><p>All plugins are secure.</p></div>'}
        
        ${outdated.size() > 0 ? """
        <div class="section">
            <h2>📦 Outdated Plugins (${outdated.size()})</h2>
            <div class="controls">
                <div class="search-box">
                    <input type="text" id="outdatedSearch" placeholder="🔍 Search outdated plugins...">
                </div>
            </div>
            <table>
                <thead>
                    <tr>
                        <th class="sortable" data-table="outdated" data-col="longName">Plugin Name</th>
                        <th class="sortable" data-table="outdated" data-col="shortName">Short Name</th>
                        <th class="sortable" data-table="outdated" data-col="version">Version</th>
                        <th>Status</th>
                    </tr>
                </thead>
                <tbody id="outdatedBody"></tbody>
            </table>
            <div class="pagination" id="outdatedPagination"></div>
        </div>
        """ : ''}
        
        <div class="section">
            <h2>📋 All Plugins (${plugins.size()})</h2>
            <div class="controls">
                <div class="search-box">
                    <input type="text" id="pluginSearch" placeholder="🔍 Search plugins...">
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
                    <select id="perPage">
                        <option value="25">25</option>
                        <option value="50" selected>50</option>
                        <option value="100">100</option>
                        <option value="9999">All</option>
                    </select>
                </div>
            </div>
            <table>
                <thead>
                    <tr>
                        <th class="sortable" data-table="plugins" data-col="longName">Plugin Name</th>
                        <th class="sortable" data-table="plugins" data-col="shortName">Short Name</th>
                        <th class="sortable" data-table="plugins" data-col="version">Version</th>
                        <th class="sortable" data-table="plugins" data-col="enabled">Status</th>
                        <th>Active</th>
                        <th>Dependencies</th>
                    </tr>
                </thead>
                <tbody id="pluginBody"></tbody>
            </table>
            <div class="pagination" id="pluginPagination"></div>
        </div>
    </div>

    <script>
        const allPlugins = JSON.parse('${pluginsJson.replaceAll("\\\\", "\\\\\\\\").replaceAll("'", "\\\\'")}');
        const outdatedPlugins = JSON.parse('${outdatedJson.replaceAll("\\\\", "\\\\\\\\").replaceAll("'", "\\\\'")}');
        
        let pluginPage = 1, pluginPerPage = 50, pluginFiltered = [...allPlugins];
        let outdatedPage = 1, outdatedPerPage = 25, outdatedFiltered = [...outdatedPlugins];
        let sortCol = null, sortDir = 'asc';
        
        function render() {
            renderPlugins();
            renderOutdated();
        }
        
        function renderPlugins() {
            const start = (pluginPage - 1) * pluginPerPage;
            const end = pluginPerPage === 9999 ? pluginFiltered.length : start + pluginPerPage;
            const page = pluginFiltered.slice(start, end);
            
            document.getElementById('pluginBody').innerHTML = page.map(p => 
                "<tr><td><strong>" + esc(p.longName) + "</strong></td>" +
                "<td><code>" + esc(p.shortName) + "</code></td>" +
                "<td>" + esc(p.version) + "</td>" +
                "<td><span class='badge badge-" + (p.enabled ? "enabled'>ENABLED" : "disabled'>DISABLED") + "</span></td>" +
                "<td>" + (p.active ? "✅" : "❌") + "</td>" +
                "<td>" + (p.dependencies ? p.dependencies.length : 0) + "</td></tr>"
            ).join('');
            
            const totalPages = Math.ceil(pluginFiltered.length / pluginPerPage);
            document.getElementById('pluginPagination').innerHTML = 
                "<div class='pagination-info'>Showing " + (start + 1) + "-" + Math.min(end, pluginFiltered.length) + " of " + pluginFiltered.length + "</div>" +
                "<div class='pagination-controls'>" +
                "<button onclick='pluginPage=1;render()' " + (pluginPage === 1 ? "disabled" : "") + ">First</button>" +
                "<button onclick='pluginPage--;render()' " + (pluginPage === 1 ? "disabled" : "") + ">Prev</button>" +
                "<span style='padding:8px 16px'>Page " + pluginPage + " of " + totalPages + "</span>" +
                "<button onclick='pluginPage++;render()' " + (pluginPage === totalPages ? "disabled" : "") + ">Next</button>" +
                "<button onclick='pluginPage=" + totalPages + ";render()' " + (pluginPage === totalPages ? "disabled" : "") + ">Last</button>" +
                "</div>";
        }
        
        function renderOutdated() {
            if (!outdatedPlugins.length) return;
            const start = (outdatedPage - 1) * outdatedPerPage;
            const end = start + outdatedPerPage;
            const page = outdatedFiltered.slice(start, end);
            
            document.getElementById('outdatedBody').innerHTML = page.map(p => 
                "<tr><td><strong>" + esc(p.longName) + "</strong></td>" +
                "<td><code>" + esc(p.shortName) + "</code></td>" +
                "<td>" + esc(p.version) + "</td>" +
                "<td><span class='badge badge-update'>UPDATE AVAILABLE</span></td></tr>"
            ).join('');
            
            const totalPages = Math.ceil(outdatedFiltered.length / outdatedPerPage);
            document.getElementById('outdatedPagination').innerHTML = 
                "<div class='pagination-info'>Showing " + (start + 1) + "-" + Math.min(end, outdatedFiltered.length) + " of " + outdatedFiltered.length + "</div>" +
                "<div class='pagination-controls'>" +
                "<button onclick='outdatedPage=1;render()' " + (outdatedPage === 1 ? "disabled" : "") + ">First</button>" +
                "<button onclick='outdatedPage--;render()' " + (outdatedPage === 1 ? "disabled" : "") + ">Prev</button>" +
                "<span style='padding:8px 16px'>Page " + outdatedPage + " of " + totalPages + "</span>" +
                "<button onclick='outdatedPage++;render()' " + (outdatedPage === totalPages ? "disabled" : "") + ">Next</button>" +
                "<button onclick='outdatedPage=" + totalPages + ";render()' " + (outdatedPage === totalPages ? "disabled" : "") + ">Last</button>" +
                "</div>";
        }
        
        function esc(str) {
            const div = document.createElement('div');
            div.textContent = str || '';
            return div.innerHTML;
        }
        
        document.getElementById('pluginSearch').addEventListener('input', e => {
            const q = e.target.value.toLowerCase();
            const status = document.getElementById('statusFilter').value;
            pluginFiltered = allPlugins.filter(p => {
                const match = p.longName.toLowerCase().includes(q) || p.shortName.toLowerCase().includes(q);
                const statusMatch = status === 'all' || (status === 'enabled' && p.enabled) || (status === 'disabled' && !p.enabled);
                return match && statusMatch;
            });
            pluginPage = 1;
            render();
        });
        
        document.getElementById('statusFilter').addEventListener('change', () => {
            document.getElementById('pluginSearch').dispatchEvent(new Event('input'));
        });
        
        document.getElementById('perPage').addEventListener('change', e => {
            pluginPerPage = parseInt(e.target.value);
            pluginPage = 1;
            render();
        });
        
        if (document.getElementById('outdatedSearch')) {
            document.getElementById('outdatedSearch').addEventListener('input', e => {
                const q = e.target.value.toLowerCase();
                outdatedFiltered = outdatedPlugins.filter(p => 
                    p.longName.toLowerCase().includes(q) || p.shortName.toLowerCase().includes(q)
                );
                outdatedPage = 1;
                render();
            });
        }
        
        document.querySelectorAll('th.sortable').forEach(th => {
            th.addEventListener('click', () => {
                const table = th.dataset.table;
                const col = th.dataset.col;
                
                if (sortCol === col) {
                    sortDir = sortDir === 'asc' ? 'desc' : 'asc';
                } else {
                    sortCol = col;
                    sortDir = 'asc';
                }
                
                const arr = table === 'plugins' ? pluginFiltered : outdatedFiltered;
                arr.sort((a, b) => {
                    const aVal = (a[col] || '').toString().toLowerCase();
                    const bVal = (b[col] || '').toString().toLowerCase();
                    return sortDir === 'asc' ? (aVal > bVal ? 1 : -1) : (aVal < bVal ? 1 : -1);
                });
                
                document.querySelectorAll('th.sortable').forEach(t => {
                    t.classList.remove('sort-asc', 'sort-desc');
                });
                th.classList.add('sort-' + sortDir);
                
                render();
            });
        });
        
        render();
    </script>
</body>
</html>"""
}
