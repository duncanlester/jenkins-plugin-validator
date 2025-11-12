#!/usr/bin/env groovy

def generateReports() {
    echo "📝 Generating validation reports..."
    
    def pluginJson = readFile(file: 'plugins.json')
    def plugins = readJSON text: pluginJson
    def vulns = readJSON text: (env.VULNERABILITIES ?: '[]')
    def outdated = readJSON text: (env.OUTDATED_PLUGINS ?: '[]')
    
    def pluginCount = plugins.size()
    echo "📊 Generating report for ${pluginCount} plugins"
    
    def timestamp = new Date().format('yyyy-MM-dd HH:mm:ss', TimeZone.getTimeZone('UTC'))
    def jenkinsVersion = Jenkins.instance.version.toString()
    def currentUser = getCurrentUser()
    
    def vulnCount = vulns.size()
    def outdatedCount = outdated.size()
    def riskScore = env.RISK_SCORE?.toInteger() ?: 0
    
    def vulnColorClass = vulnCount > 0 ? 'color-danger' : 'color-success'
    def riskColorClass = riskScore < 30 ? 'color-success' : (riskScore < 70 ? 'color-warning' : 'color-danger')
    
    def jenkinsUrl = env.JENKINS_URL ?: 'http://localhost:8080/'
    def buildUrl = env.BUILD_URL ?: "${jenkinsUrl}job/${env.JOB_NAME}/${env.BUILD_NUMBER}/"
    
    def html = new StringBuilder()
    html << """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Jenkins Plugin Validation Report</title>
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
            text-align: left;
        }
        
        .header-meta {
            display: flex;
            gap: 30px;
            font-size: 15px;
            opacity: 0.95;
        }
        
        .header-meta strong { font-weight: 600; opacity: 1; }
        
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
            text-align: left;
        }
        
        .section-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 24px;
        }
        
        .section-header h2 {
            margin-bottom: 0;
            border-bottom: none;
            padding-bottom: 0;
            text-align: left;
        }
        
        .summary-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin-bottom: 24px;
        }
        
        .summary-item {
            padding: 16px;
            background: #f8f9fc;
            border-radius: 8px;
            border-left: 4px solid var(--primary);
        }
        
        .summary-item-success {
            padding: 16px;
            background: #f8f9fc;
            border-radius: 8px;
            border-left: 4px solid var(--success);
        }
        
        .summary-item h4 {
            font-size: 13px;
            text-transform: uppercase;
            color: var(--text-muted);
            margin-bottom: 8px;
            font-weight: 600;
            letter-spacing: 0.5px;
            text-align: left;
        }
        
        .summary-item .summary-value {
            font-size: 20px;
            font-weight: 700;
            color: var(--text);
            text-align: left;
        }
        
        .summary-item-success h4 {
            font-size: 13px;
            text-transform: uppercase;
            color: var(--text-muted);
            margin-bottom: 8px;
            font-weight: 600;
            letter-spacing: 0.5px;
            text-align: left;
        }
        
        .summary-item-success .summary-value {
            font-size: 20px;
            font-weight: 700;
            color: var(--text);
            text-align: left;
        }
        
        .color-success { color: var(--success); }
        .color-warning { color: var(--warning); }
        .color-danger { color: var(--danger); }
        
        .issue-link {
            display: inline-block;
            padding: 10px 20px;
            background: var(--primary);
            color: white;
            text-decoration: none;
            border-radius: 8px;
            font-weight: 600;
            font-size: 14px;
            transition: background 0.2s;
        }
        
        .issue-link:hover {
            background: var(--primary-dark);
        }
        
        .issue-link-small {
            padding: 8px 16px;
            font-size: 13px;
        }
        
        .links-group {
            display: flex;
            gap: 12px;
            margin-top: 16px;
        }
        
        table { 
            width: 100%;
            border-collapse: collapse;
            font-size: 13px;
            border: 2px solid var(--border);
            border-radius: 8px;
        }
        
        thead { 
            background: linear-gradient(180deg, #f8f9fc 0%, #f1f3f9 100%);
        }
        
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
            text-align: left;
        }
        
        td:last-child { border-right: none; }
        
        tbody tr { background: white; }
        tbody tr:hover { background: #f8f9fc; }
        tbody tr:last-child td { border-bottom: none; }
        
        .td-center { text-align: center; }
        
        .col-18 { width: 18%; }
        .col-25 { width: 25%; }
        .col-20 { width: 20%; }
        .col-15 { width: 15%; }
        .col-12 { width: 12%; }
        .col-10 { width: 10%; }
        .col-8 { width: 8%; }
        .col-38 { width: 38%; }
        
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
        
        code { 
            background: #f4f5f7;
            padding: 4px 8px;
            border-radius: 4px;
            font-family: 'SF Mono', 'Monaco', 'Courier New', monospace;
            font-size: 12px;
            color: #e83e8c;
            border: 1px solid #e1e4e8;
        }
        
        a.cve-link {
            color: #e83e8c;
            text-decoration: none;
            font-weight: 600;
        }
        
        a.cve-link:hover {
            text-decoration: underline;
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

    // Summary section at the top
    html << """
        <div class="section">
            <h2>📊 Executive Summary</h2>
            <div class="summary-grid">
                <div class="summary-item">
                    <h4>Total Plugins Installed</h4>
                    <div class="summary-value">${pluginCount} plugins</div>
                </div>
                <div class="summary-item">
                    <h4>Security Vulnerabilities</h4>
                    <div class="summary-value ${vulnColorClass}">${vulnCount} found</div>
                </div>
                <div class="summary-item">
                    <h4>Outdated Plugins</h4>
                    <div class="summary-value color-warning">${outdatedCount} need updates</div>
                </div>
                <div class="summary-item">
                    <h4>Overall Risk Level</h4>
                    <div class="summary-value ${riskColorClass}">${riskScore < 30 ? 'Low' : (riskScore < 70 ? 'Medium' : 'High')}</div>
                </div>
            </div>
            <div class="links-group">
                <a href="${buildUrl}" class="issue-link">📋 View Build Details</a>
                <a href="${buildUrl}console" class="issue-link">📄 View Console Output</a>
            </div>
        </div>
"""

    // Vulnerabilities section
    if (vulns.size() > 0) {
        html << """
        <div class="section">
            <div class="section-header">
                <h2>🚨 Security Vulnerabilities (${vulnCount} found)</h2>
                <a href="${buildUrl}artifact/plugins.json" class="issue-link issue-link-small">📥 Download JSON</a>
            </div>
            <table>
                <thead>
                    <tr>
                        <th class="col-18">Plugin</th>
                        <th class="col-12">Version</th>
                        <th class="col-12">CVE</th>
                        <th class="col-10">Severity</th>
                        <th class="col-38">Description</th>
                        <th class="col-10">Reference</th>
                    </tr>
                </thead>
                <tbody>
"""
        vulns.each { v ->
            def cveId = escapeHtml(v.cve)
            def cveUrl = v.url ?: "https://nvd.nist.gov/vuln/detail/${cveId}"
            
            html << """
                    <tr>
                        <td><strong>${escapeHtml(v.plugin)}</strong></td>
                        <td>${escapeHtml(v.version)}</td>
                        <td><code><a href="${cveUrl}" class="cve-link" target="_blank" rel="noopener">${cveId}</a></code></td>
                        <td><span class="badge badge-${v.severity.toLowerCase()}">${escapeHtml(v.severity)}</span></td>
                        <td>${escapeHtml(v.description)}</td>
                        <td><a href="${cveUrl}" class="issue-link issue-link-small" target="_blank" rel="noopener">View CVE</a></td>
                    </tr>
"""
        }
        html << """
                </tbody>
            </table>
        </div>
"""
    } else {
        html << """
        <div class="section">
            <h2>✅ Security Status</h2>
            <div class="summary-item-success">
                <h4>No Vulnerabilities Detected</h4>
                <div class="summary-value color-success">All plugins are secure</div>
            </div>
        </div>
"""
    }

    // Outdated plugins section
    if (outdatedCount > 0) {
        html << """
        <div class="section">
            <h2>⚠️ Outdated Plugins (${outdatedCount} need updates)</h2>
            <table>
                <thead>
                    <tr>
                        <th class="col-25">Plugin Name</th>
                        <th class="col-15">Short Name</th>
                        <th class="col-15">Current Version</th>
                        <th class="col-20">Developers</th>
                        <th class="col-15">Jenkins Version</th>
                        <th class="col-10">Dependencies</th>
                    </tr>
                </thead>
                <tbody>
"""
        outdated.each { p ->
            def devName = (p.developerNames ?: 'Unknown').toString().split(':')[0]
            html << """
                    <tr>
                        <td><strong>${escapeHtml(p.longName)}</strong></td>
                        <td><code>${escapeHtml(p.shortName)}</code></td>
                        <td>${escapeHtml(p.version)}</td>
                        <td>${escapeHtml(devName)}</td>
                        <td>${escapeHtml(p.jenkinsVersion ?: '-')}</td>
                        <td class="td-center">${p.dependencyCount ?: 0}</td>
                    </tr>
"""
        }
        html << """
                </tbody>
            </table>
        </div>
"""
    }

    // All plugins section
    html << """
        <div class="section">
            <h2>📦 All Installed Plugins (${pluginCount} total)</h2>
            <table>
                <thead>
                    <tr>
                        <th class="col-25">Plugin Name</th>
                        <th class="col-15">Short Name</th>
                        <th class="col-12">Version</th>
                        <th class="col-10">Status</th>
                        <th class="col-20">Developers</th>
                        <th class="col-10">Jenkins Ver</th>
                        <th class="col-8">Dependencies</th>
                    </tr>
                </thead>
                <tbody>
"""

    plugins.each { p ->
        def devName = (p.developerNames ?: 'Unknown').toString().split(':')[0]
        def statusBadge = p.enabled ? 'enabled' : 'disabled'
        def statusText = p.enabled ? 'ENABLED' : 'DISABLED'
        
        html << """
                    <tr>
                        <td><strong>${escapeHtml(p.longName)}</strong></td>
                        <td><code>${escapeHtml(p.shortName)}</code></td>
                        <td>${escapeHtml(p.version)}</td>
                        <td><span class="badge badge-${statusBadge}">${statusText}</span></td>
                        <td>${escapeHtml(devName)}</td>
                        <td>${escapeHtml(p.jenkinsVersion ?: '-')}</td>
                        <td class="td-center">${p.dependencyCount ?: 0}</td>
                    </tr>
"""
    }

    html << """
                </tbody>
            </table>
        </div>
    </div>
</body>
</html>
"""

    writeFile file: 'plugin-validation-report.html', text: html.toString()
    archiveArtifacts artifacts: 'plugin-validation-report.html,plugins.json'
    
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
        echo "⚠️ HTML Publisher not available: ${e.message}"
    }
    
    echo "✅ Report generated: ${pluginCount} plugins, ${vulnCount} vulnerabilities, ${outdatedCount} outdated"
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
