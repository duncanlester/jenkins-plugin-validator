#!/usr/bin/env groovy

def generateReports() {
    echo "📝 Generating validation reports..."
    
    def pluginJson = readFile(file: 'plugins.json')
    def plugins = readJSON text: pluginJson
    def vulns = readJSON text: (env.VULNERABILITIES ?: '[]')
    
    def pluginCount = plugins.size()
    echo "📊 Generating report for ${pluginCount} plugins"
    
    def timestamp = new Date().format('yyyy-MM-dd HH:mm:ss', TimeZone.getTimeZone('UTC'))
    def jenkinsVersion = Jenkins.instance.version.toString()
    def currentUser = getCurrentUser()
    
    // Generate pages (50 plugins per page)
    def pageSize = 50
    def totalPages = Math.ceil(pluginCount / pageSize).toInteger()
    
    // Generate main report with page 1
    def html = generatePage(plugins, vulns, 1, pageSize, totalPages, timestamp, jenkinsVersion, currentUser)
    writeFile file: 'plugin-validation-report.html', text: html
    
    // Generate additional pages
    for (int i = 2; i <= totalPages; i++) {
        def pageHtml = generatePage(plugins, vulns, i, pageSize, totalPages, timestamp, jenkinsVersion, currentUser)
        writeFile file: "plugin-validation-report-page${i}.html", text: pageHtml
    }
    
    archiveArtifacts artifacts: '*.html,plugins.json'
    
    try {
        publishHTML([
            allowMissing: false,
            alwaysLinkToLastBuild: true,
            keepAll: true,
            reportDir: '.',
            reportFiles: 'plugin-validation-report.html',
            reportName: 'Plugin Validation Report'
        ])
    } catch (Exception e) {
        echo "⚠️ HTML Publisher not available"
    }
    
    echo "✅ Reports generated successfully!"
}

def generatePage(plugins, vulns, currentPage, pageSize, totalPages, timestamp, jenkinsVersion, currentUser) {
    def pluginCount = plugins.size()
    def startIdx = (currentPage - 1) * pageSize
    def endIdx = Math.min(startIdx + pageSize, pluginCount)
    def pagePlugins = plugins[startIdx..<endIdx]
    
    def vulnCount = env.VULN_COUNT?.toInteger() ?: 0
    def outdatedCount = env.OUTDATED_COUNT?.toInteger() ?: 0
    def riskScore = env.RISK_SCORE?.toInteger() ?: 0
    
    def html = new StringBuilder()
    html << """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Jenkins Plugin Validation Report - Page ${currentPage}</title>
    <style>
        :root {
            --primary: #335eea;
            --primary-dark: #2948c8;
            --success: #00c48c;
            --warning: #ffa726;
            --danger: #f44336;
            --critical: #c62828;
            --bg: #f8f9fc;
            --card-bg: #ffffff;
            --text: #1e2130;
            --text-muted: #6c757d;
            --border: #e1e4e8;
            --shadow: 0 2px 12px rgba(0,0,0,0.08);
            --shadow-lg: 0 8px 24px rgba(0,0,0,0.12);
        }
        
        * { margin: 0; padding: 0; box-sizing: border-box; }
        
        body { 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Helvetica Neue', Arial, sans-serif;
            background: var(--bg);
            color: var(--text);
            line-height: 1.6;
            padding: 30px 20px;
        }
        
        .container { max-width: 1600px; margin: 0 auto; }
        
        .header { 
            background: linear-gradient(135deg, var(--primary) 0%, var(--primary-dark) 100%);
            color: white;
            padding: 50px 40px;
            border-radius: 16px;
            margin-bottom: 40px;
            box-shadow: var(--shadow-lg);
        }
        
        .header h1 { 
            font-size: 42px;
            font-weight: 700;
            margin-bottom: 16px;
            letter-spacing: -0.5px;
        }
        
        .header-meta {
            display: flex;
            gap: 30px;
            font-size: 15px;
            opacity: 0.95;
        }
        
        .header-meta strong { font-weight: 600; opacity: 1; }
        
        .stats { 
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 24px;
            margin-bottom: 40px;
        }
        
        .stat-card { 
            background: var(--card-bg);
            padding: 32px;
            border-radius: 12px;
            box-shadow: var(--shadow);
            border: 1px solid var(--border);
        }
        
        .stat-card h3 { 
            color: var(--text-muted);
            font-size: 12px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-bottom: 12px;
        }
        
        .stat-card .value { 
            font-size: 48px;
            font-weight: 700;
            color: var(--primary);
            line-height: 1;
        }
        
        .section { 
            background: var(--card-bg);
            padding: 36px;
            border-radius: 12px;
            margin-bottom: 32px;
            box-shadow: var(--shadow);
            border: 1px solid var(--border);
        }
        
        .section h2 { 
            font-size: 28px;
            font-weight: 700;
            margin-bottom: 24px;
            color: var(--text);
            padding-bottom: 16px;
            border-bottom: 3px solid var(--primary);
        }
        
        table { 
            width: 100%;
            border-collapse: separate;
            border-spacing: 0;
            font-size: 13px;
            border: 1px solid var(--border);
            border-radius: 8px;
            overflow: hidden;
        }
        
        thead { background: linear-gradient(180deg, #f8f9fc 0%, #f1f3f9 100%); }
        
        th { 
            padding: 16px 14px;
            text-align: left;
            font-weight: 700;
            font-size: 11px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            color: var(--text);
            border-bottom: 2px solid var(--border);
            border-right: 1px solid var(--border);
        }
        
        th:last-child { border-right: none; }
        
        td { 
            padding: 14px;
            border-bottom: 1px solid var(--border);
            border-right: 1px solid var(--border);
            vertical-align: middle;
        }
        
        td:last-child { border-right: none; }
        
        tbody tr { background: white; }
        tbody tr:hover { background: #f8f9fc; }
        tbody tr:last-child td { border-bottom: none; }
        
        .badge { 
            display: inline-block;
            padding: 6px 12px;
            border-radius: 6px;
            font-size: 10px;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.3px;
        }
        
        .badge-critical { background: var(--critical); color: white; }
        .badge-high { background: var(--danger); color: white; }
        .badge-medium { background: var(--warning); color: white; }
        .badge-low { background: #90caf9; color: #0d47a1; }
        .badge-enabled { background: var(--success); color: white; }
        .badge-disabled { background: var(--text-muted); color: white; }
        
        .pagination { 
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-top: 28px;
            padding-top: 24px;
            border-top: 2px solid var(--border);
        }
        
        .pagination-info { font-size: 14px; color: var(--text-muted); font-weight: 500; }
        
        .pagination-buttons { display: flex; gap: 12px; }
        
        .pagination a { 
            padding: 12px 24px;
            border: 2px solid var(--primary);
            background: white;
            color: var(--primary);
            border-radius: 8px;
            font-weight: 600;
            font-size: 13px;
            text-decoration: none;
            transition: all 0.2s;
        }
        
        .pagination a:hover { background: var(--primary); color: white; }
        .pagination a.disabled { opacity: 0.3; pointer-events: none; border-color: var(--border); color: var(--text-muted); }
        
        code { 
            background: #f4f5f7;
            padding: 4px 8px;
            border-radius: 4px;
            font-family: 'SF Mono', 'Monaco', 'Courier New', monospace;
            font-size: 12px;
            color: #e83e8c;
            border: 1px solid #e1e4e8;
        }
        
        strong { font-weight: 600; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔒 Jenkins Plugin Validation Report</h1>
            <div class="header-meta">
                <div><strong>Generated:</strong> ${timestamp} UTC</div>
                <div><strong>Jenkins:</strong> ${jenkinsVersion}</div>
                <div><strong>User:</strong> ${currentUser}</div>
            </div>
        </div>
"""

    if (currentPage == 1) {
        def vulnColor = vulnCount > 0 ? 'var(--danger)' : 'var(--success)'
        def riskColor = riskScore < 30 ? 'var(--success)' : (riskScore < 70 ? 'var(--warning)' : 'var(--danger)')
        
        html << """
        <div class="stats">
            <div class="stat-card">
                <h3>Total Plugins</h3>
                <div class="value">${pluginCount}</div>
            </div>
            <div class="stat-card">
                <h3>Vulnerabilities</h3>
                <div class="value" style="color: ${vulnColor};">${vulnCount}</div>
            </div>
            <div class="stat-card">
                <h3>Outdated</h3>
                <div class="value" style="color: var(--warning);">${outdatedCount}</div>
            </div>
            <div class="stat-card">
                <h3>Risk Score</h3>
                <div class="value" style="color: ${riskColor};">${riskScore}<span style="font-size:24px;color:var(--text-muted);">/100</span></div>
            </div>
        </div>
"""

        if (vulns.size() > 0) {
            html << """
        <div class="section">
            <h2>🚨 Security Vulnerabilities</h2>
            <table>
                <thead>
                    <tr>
                        <th style="width: 20%;">Plugin</th>
                        <th style="width: 12%;">Version</th>
                        <th style="width: 15%;">CVE</th>
                        <th style="width: 10%;">Severity</th>
                        <th style="width: 43%;">Description</th>
                    </tr>
                </thead>
                <tbody>
"""
            vulns.each { v ->
                html << """
                    <tr>
                        <td><strong>${escapeHtml(v.plugin)}</strong></td>
                        <td>${escapeHtml(v.version)}</td>
                        <td><code>${escapeHtml(v.cve)}</code></td>
                        <td><span class="badge badge-${v.severity.toLowerCase()}">${escapeHtml(v.severity)}</span></td>
                        <td>${escapeHtml(v.description)}</td>
                    </tr>
"""
            }
            html << """
                </tbody>
            </table>
        </div>
"""
        }
    }

    html << """
        <div class="section">
            <h2>📦 Installed Plugins</h2>
            <table>
                <thead>
                    <tr>
                        <th style="width: 25%;">Plugin Name</th>
                        <th style="width: 15%;">Short Name</th>
                        <th style="width: 12%;">Version</th>
                        <th style="width: 10%;">Status</th>
                        <th style="width: 20%;">Developers</th>
                        <th style="width: 10%;">Jenkins Ver</th>
                        <th style="width: 8%;">Dependencies</th>
                    </tr>
                </thead>
                <tbody>
"""

    pagePlugins.each { p ->
        def devName = (p.developerNames ?: 'Unknown').toString().split(':')[0]
        def statusBadge = p.enabled ? 'enabled">ENABLED' : 'disabled">DISABLED'
        
        html << """
                    <tr>
                        <td><strong>${escapeHtml(p.longName)}</strong></td>
                        <td><code>${escapeHtml(p.shortName)}</code></td>
                        <td>${escapeHtml(p.version)}</td>
                        <td><span class="badge badge-${statusBadge}</span></td>
                        <td>${escapeHtml(devName)}</td>
                        <td>${escapeHtml(p.jenkinsVersion ?: '-')}</td>
                        <td style="text-align:center;">${p.dependencyCount ?: 0}</td>
                    </tr>
"""
    }

    html << """
                </tbody>
            </table>
            <div class="pagination">
                <div class="pagination-info">Showing ${startIdx + 1}-${endIdx} of ${pluginCount} plugins (Page ${currentPage} of ${totalPages})</div>
                <div class="pagination-buttons">
"""

    // Pagination links
    def prevPage = currentPage - 1
    def nextPage = currentPage + 1
    def firstClass = currentPage == 1 ? ' disabled' : ''
    def lastClass = currentPage == totalPages ? ' disabled' : ''
    def firstLink = currentPage == 1 ? '#' : 'plugin-validation-report.html'
    def prevLink = currentPage == 1 ? '#' : (prevPage == 1 ? 'plugin-validation-report.html' : "plugin-validation-report-page${prevPage}.html")
    def nextLink = currentPage == totalPages ? '#' : "plugin-validation-report-page${nextPage}.html"
    def lastLink = currentPage == totalPages ? '#' : "plugin-validation-report-page${totalPages}.html"

    html << """
                    <a href="${firstLink}" class="${firstClass}">First</a>
                    <a href="${prevLink}" class="${firstClass}">Previous</a>
                    <a href="${nextLink}" class="${lastClass}">Next</a>
                    <a href="${lastLink}" class="${lastClass}">Last</a>
                </div>
            </div>
        </div>
    </div>
</body>
</html>
"""

    return html.toString()
}

@NonCPS
def escapeHtml(str) {
    if (!str) return ''
    return str.toString()
        .replace('&', '&amp;')
        .replace('<', '&lt;')
        .replace('>', '&gt;')
        .replace('"', '&quot;')
        .replace("'", '&#39;')
}

@NonCPS
def getCurrentUser() {
    try {
        def user = hudson.model.User.current()
        return user?.getId() ?: 'System'
    } catch (Exception e) {
        return 'Unknown'
    }
}

def sendSuccessNotification() {
    echo "✅ Plugin validation completed"
}

def sendSecurityAlert() {
    if (currentBuild.result == 'UNSTABLE') {
        echo "⚠️ Vulnerabilities detected"
    }
}

@NonCPS
def checkPluginInstalled(String pluginName) {
    def jenkins = Jenkins.instance
    def plugin = jenkins.pluginManager.getPlugin(pluginName)
    return plugin != null && plugin.isEnabled()
}
