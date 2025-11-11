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
    
    archiveArtifacts artifacts: '*.html,*.json,*.pdf'
    
    publishHTML([
        allowMissing: false,
        alwaysLinkToLastBuild: true,
        keepAll: true,
        reportDir: '.',
        reportFiles: 'plugin-validation-report.html',
        reportName: 'Plugin Validation Report',
        reportTitles: 'Jenkins Plugin Security Report'
    ])
}

def sendSuccessNotification() {
    echo "✅ Plugin validation completed successfully!"
    
    try {
        slackSend(
            color: env.RISK_RATING == 'LOW' ? 'good' : env.RISK_RATING == 'CRITICAL' ? 'danger' : 'warning',
            message: """
                🔒 Jenkins Plugin Validation Report
                
                *Status:* ${currentBuild.result}
                *Total Plugins:* ${readJSON(text: env.PLUGIN_DATA).size()}
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
    }
}

def sendSecurityAlert() {
    if (currentBuild.result != 'UNSTABLE') {
        return
    }
    
    echo "⚠️ Vulnerabilities detected!"
    
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
        echo "⚠️ Slack notification failed: ${e.message}"
    }
}

@NonCPS
private String generateHTMLReport(plugins, vulnerabilities, outdated, riskScore, riskRating) {
    def timestamp = new Date().format('yyyy-MM-dd HH:mm:ss', TimeZone.getTimeZone('UTC'))
    def jenkins = Jenkins.instance
    
    return """
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Jenkins Plugin Validation Report</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #f5f7fa;
            padding: 20px;
        }
        .container { max-width: 1200px; margin: 0 auto; }
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px;
            border-radius: 10px;
            margin-bottom: 30px;
        }
        .header h1 { font-size: 32px; margin-bottom: 10px; }
        .stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        .stat-card {
            background: white;
            padding: 25px;
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        }
        .stat-card h3 {
            color: #666;
            font-size: 14px;
            text-transform: uppercase;
            margin-bottom: 10px;
        }
        .stat-card .value {
            font-size: 36px;
            font-weight: bold;
            color: #333;
        }
        .risk-critical { color: #dc3545; }
        .risk-high { color: #fd7e14; }
        .risk-medium { color: #ffc107; }
        .risk-low { color: #28a745; }
        .section {
            background: white;
            padding: 30px;
            border-radius: 8px;
            margin-bottom: 20px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        }
        .section h2 {
            margin-bottom: 20px;
            color: #333;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 15px;
        }
        th {
            background: #f8f9fa;
            padding: 12px;
            text-align: left;
            font-weight: 600;
            border-bottom: 2px solid #dee2e6;
        }
        td {
            padding: 12px;
            border-bottom: 1px solid #dee2e6;
        }
        .badge {
            display: inline-block;
            padding: 4px 12px;
            border-radius: 12px;
            font-size: 12px;
            font-weight: bold;
        }
        .badge-critical { background: #dc3545; color: white; }
        .badge-high { background: #fd7e14; color: white; }
        .badge-medium { background: #ffc107; color: #333; }
        .badge-low { background: #28a745; color: white; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔒 Jenkins Plugin Validation Report</h1>
            <p>Generated: ${timestamp} UTC</p>
            <p>Jenkins Version: ${jenkins.version}</p>
            <p>Scan Source: <strong>Jenkins Update Center (Live)</strong></p>
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
                    </tr>
                </thead>
                <tbody>
                    ${vulnerabilities.collect { vuln -> """
                    <tr>
                        <td><strong>${vuln.plugin}</strong></td>
                        <td>${vuln.version}</td>
                        <td><a href="${vuln.url ?: '#'}" target="_blank">${vuln.cve}</a></td>
                        <td><span class="badge badge-${vuln.severity.toLowerCase()}">${vuln.severity}</span></td>
                        <td>${vuln.description?.take(100) ?: 'N/A'}...</td>
                    </tr>
                    """ }.join('')}
                </tbody>
            </table>
        </div>
        """ : '<div class="section"><h2>✅ No Vulnerabilities Detected</h2><p>All plugins are secure according to Jenkins Update Center.</p></div>'}
        
        ${outdated.size() > 0 ? """
        <div class="section">
            <h2>📦 Plugins With Available Updates</h2>
            <table>
                <thead>
                    <tr>
                        <th>Plugin</th>
                        <th>Current Version</th>
                        <th>Status</th>
                    </tr>
                </thead>
                <tbody>
                    ${outdated.collect { plugin -> """
                    <tr>
                        <td><strong>${plugin.longName}</strong></td>
                        <td>${plugin.version}</td>
                        <td><span class="badge badge-medium">UPDATE AVAILABLE</span></td>
                    </tr>
                    """ }.join('')}
                </tbody>
            </table>
        </div>
        """ : ''}
        
        <div class="section">
            <h2>📋 All Installed Plugins (${plugins.size()})</h2>
            <table>
                <thead>
                    <tr>
                        <th>Plugin</th>
                        <th>Version</th>
                        <th>Status</th>
                    </tr>
                </thead>
                <tbody>
                    ${plugins.collect { plugin -> """
                    <tr>
                        <td><strong>${plugin.longName}</strong></td>
                        <td>${plugin.version}</td>
                        <td>
                            ${plugin.enabled ? '<span class="badge badge-low">ENABLED</span>' : '<span class="badge">DISABLED</span>'}
                        </td>
                    </tr>
                    """ }.join('')}
                </tbody>
            </table>
        </div>
    </div>
</body>
</html>
    """
}
