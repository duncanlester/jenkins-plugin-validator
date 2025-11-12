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
    
    // Copy CSS file to workspace
    def cssContent = libraryResource('report-style.css')
    writeFile file: 'report-style.css', text: cssContent
    
    def html = new StringBuilder()
    html << """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Jenkins Plugin Validation Report</title>
    <link rel="stylesheet" href="report-style.css">
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

    // Summary section
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

    // Vulnerabilities
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

    // Outdated plugins
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

    // All plugins
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
    archiveArtifacts artifacts: 'plugin-validation-report.html,report-style.css,plugins.json'
    
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
