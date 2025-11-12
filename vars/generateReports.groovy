#!/usr/bin/env groovy

def call() {
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
    
    def cssContent = libraryResource('report-style.css')
    writeFile file: 'report-style.css', text: cssContent
    
    def html = buildReportHTML(plugins, vulns, outdated, pluginCount, vulnCount, outdatedCount, 
                                riskScore, vulnColorClass, riskColorClass, timestamp, 
                                jenkinsVersion, currentUser, buildUrl)
    
    writeFile file: 'plugin-validation-report.html', text: html
    archiveArtifacts artifacts: 'plugin-validation-report.html,report-style.css,plugins.json'
    
    try {
        publishHTML([
            allowMissing: false,
            alwaysLinkToLastBuild: true,
            keepAll: true,
            reportDir: '.',
            reportFiles: 'plugin-validation-report.html',
            reportName: 'Plugin Validation Report',
            reportTitles: 'Jenkins Plugin Validation Report',
            allowScripting: false,
            escapeUnderscores: true,
            includes: '**/*'
        ])
    } catch (Exception e) {
        echo "⚠️ HTML Publisher not available: ${e.message}"
    }
    
    echo "✅ Report generated: ${pluginCount} plugins, ${vulnCount} vulnerabilities, ${outdatedCount} outdated"
}

@NonCPS
def buildReportHTML(plugins, vulns, outdated, pluginCount, vulnCount, outdatedCount, 
                    riskScore, vulnColorClass, riskColorClass, timestamp, 
                    jenkinsVersion, currentUser, buildUrl) {
    def html = new StringBuilder()
    html << '<!DOCTYPE html>\n'
    html << '<html lang="en">\n'
    html << '<head>\n'
    html << '    <meta charset="UTF-8">\n'
    html << '    <meta name="viewport" content="width=device-width, initial-scale=1.0">\n'
    html << '    <title>Jenkins Plugin Validation Report</title>\n'
    html << '    <link rel="stylesheet" href="report-style.css">\n'
    html << '</head>\n'
    html << '<body>\n'
    html << '    <div class="container">\n'
    html << '        <div class="header">\n'
    html << '            <h1>🔒 Jenkins Plugin Validation Report</h1>\n'
    html << '            <div class="header-meta">\n'
    html << "                <div><strong>Generated:</strong> ${timestamp} UTC</div>\n"
    html << "                <div><strong>Jenkins:</strong> ${jenkinsVersion}</div>\n"
    html << "                <div><strong>User:</strong> ${currentUser}</div>\n"
    html << '            </div>\n'
    html << '        </div>\n'
    html << '        \n'
    html << '        <div class="section">\n'
    html << '            <h2>📊 Jenkins Plugin Vulnerability Summary</h2>\n'
    html << '            <div class="summary-grid">\n'
    html << '                <div class="summary-item">\n'
    html << '                    <h4>Total Plugins Installed</h4>\n'
    html << "                    <div class=\"summary-value\">${pluginCount} plugins</div>\n"
    html << '                </div>\n'
    html << '                <div class="summary-item">\n'
    html << '                    <h4>Security Vulnerabilities</h4>\n'
    html << "                    <div class=\"summary-value ${vulnColorClass}\">${vulnCount} found</div>\n"
    html << '                </div>\n'
    html << '                <div class="summary-item">\n'
    html << '                    <h4>Outdated Plugins</h4>\n'
    html << "                    <div class=\"summary-value color-warning\">${outdatedCount} need updates</div>\n"
    html << '                </div>\n'
    html << '                <div class="summary-item">\n'
    html << '                    <h4>Overall Risk Level</h4>\n'
    def riskLevel = riskScore < 30 ? 'Low' : (riskScore < 70 ? 'Medium' : 'High')
    html << "                    <div class=\"summary-value ${riskColorClass}\">${riskLevel}</div>\n"
    html << '                </div>\n'
    html << '            </div>\n'
    html << '            <div class="links-group">\n'
    html << "                <a href=\"${buildUrl}\">📋 View Build Details</a>\n"
    html << "                <a href=\"${buildUrl}console\">📄 View Console Output</a>\n"
    html << '            </div>\n'
    html << '        </div>\n'

    // Vulnerabilities section
    if (vulns.size() > 0) {
        html << '        <div class="section">\n'
        html << '            <div class="section-header">\n'
        html << "                <h2>🚨 Security Vulnerabilities (${vulnCount} found)</h2>\n"
        html << "                <a href=\"${buildUrl}artifact/plugins.json\" class=\"issue-link issue-link-small\">📥 Download JSON</a>\n"
        html << '            </div>\n'
        html << '            <table>\n'
        html << '                <thead>\n'
        html << '                    <tr>\n'
        html << '                        <th class="col-18">Plugin</th>\n'
        html << '                        <th class="col-12">Version</th>\n'
        html << '                        <th class="col-20">CVE / Security Advisory</th>\n'
        html << '                        <th class="col-10">Severity</th>\n'
        html << '                        <th class="col-30">Description</th>\n'
        html << '                        <th class="col-10">Reference</th>\n'
        html << '                    </tr>\n'
        html << '                </thead>\n'
        html << '                <tbody>\n'
        
        vulns.each { v ->
            def cveUrl = escapeHtml(v.url ?: "https://www.jenkins.io/security/advisories/")
            def cveText = v.cve ?: ''
            def cveIds = cveText.split(',')
            
            // Create clickable links for each CVE ID
            def cveLinks = cveIds.collect { cve ->
                def trimmedCve = escapeHtml(cve.trim())
                "<a href=\"${cveUrl}\" class=\"cve-link\">${trimmedCve}</a>"
            }.join(', ')
            
            html << '                    <tr>\n'
            html << "                        <td><strong>${escapeHtml(v.plugin)}</strong></td>\n"
            html << "                        <td>${escapeHtml(v.version)}</td>\n"
            html << "                        <td>${cveLinks}</td>\n"
            html << "                        <td><span class=\"badge badge-${v.severity.toLowerCase()}\">${escapeHtml(v.severity)}</span></td>\n"
            html << "                        <td>${escapeHtml(v.description)}</td>\n"
            html << "                        <td><a href=\"${cveUrl}\">View Details</a></td>\n"
            html << '                    </tr>\n'
        }
        
        html << '                </tbody>\n'
        html << '            </table>\n'
        html << '        </div>\n'
    } else {
        html << '        <div class="section">\n'
        html << '            <h2>✅ Security Status</h2>\n'
        html << '            <div class="summary-item-success">\n'
        html << '                <h4>No Vulnerabilities Detected</h4>\n'
        html << '                <div class="summary-value color-success">All plugins are secure</div>\n'
        html << '            </div>\n'
        html << '        </div>\n'
    }

    // Outdated plugins section
    if (outdatedCount > 0) {
        html << '        <div class="section">\n'
        html << "            <h2>⚠️ Outdated Plugins (${outdatedCount} need updates)</h2>\n"
        html << '            <table>\n'
        html << '                <thead>\n'
        html << '                    <tr>\n'
        html << '                        <th class="col-25">Plugin Name</th>\n'
        html << '                        <th class="col-15">Short Name</th>\n'
        html << '                        <th class="col-15">Current Version</th>\n'
        html << '                        <th class="col-20">Developers</th>\n'
        html << '                        <th class="col-15">Jenkins Version</th>\n'
        html << '                        <th class="col-10">Dependencies</th>\n'
        html << '                    </tr>\n'
        html << '                </thead>\n'
        html << '                <tbody>\n'
        
        outdated.each { p ->
            def devName = (p.developerNames ?: 'Unknown').toString().split(':')[0]
            html << '                    <tr>\n'
            html << "                        <td><strong>${escapeHtml(p.longName)}</strong></td>\n"
            html << "                        <td><code>${escapeHtml(p.shortName)}</code></td>\n"
            html << "                        <td>${escapeHtml(p.version)}</td>\n"
            html << "                        <td>${escapeHtml(devName)}</td>\n"
            html << "                        <td>${escapeHtml(p.jenkinsVersion ?: '-')}</td>\n"
            html << "                        <td class=\"td-center\">${p.dependencyCount ?: 0}</td>\n"
            html << '                    </tr>\n'
        }
        
        html << '                </tbody>\n'
        html << '            </table>\n'
        html << '        </div>\n'
    }

    // All plugins section
    html << '        <div class="section">\n'
    html << "            <h2>📦 All Installed Plugins (${pluginCount} total)</h2>\n"
    html << '            <table>\n'
    html << '                <thead>\n'
    html << '                    <tr>\n'
    html << '                        <th class="col-25">Plugin Name</th>\n'
    html << '                        <th class="col-15">Short Name</th>\n'
    html << '                        <th class="col-12">Version</th>\n'
    html << '                        <th class="col-10">Status</th>\n'
    html << '                        <th class="col-20">Developers</th>\n'
    html << '                        <th class="col-10">Jenkins Ver</th>\n'
    html << '                        <th class="col-8">Dependencies</th>\n'
    html << '                    </tr>\n'
    html << '                </thead>\n'
    html << '                <tbody>\n'
    
    plugins.each { p ->
        def devName = (p.developerNames ?: 'Unknown').toString().split(':')[0]
        def statusBadge = p.enabled ? 'enabled' : 'disabled'
        def statusText = p.enabled ? 'ENABLED' : 'DISABLED'
        html << '                    <tr>\n'
        html << "                        <td><strong>${escapeHtml(p.longName)}</strong></td>\n"
        html << "                        <td><code>${escapeHtml(p.shortName)}</code></td>\n"
        html << "                        <td>${escapeHtml(p.version)}</td>\n"
        html << "                        <td><span class=\"badge badge-${statusBadge}\">${statusText}</span></td>\n"
        html << "                        <td>${escapeHtml(devName)}</td>\n"
        html << "                        <td>${escapeHtml(p.jenkinsVersion ?: '-')}</td>\n"
        html << "                        <td class=\"td-center\">${p.dependencyCount ?: 0}</td>\n"
        html << '                    </tr>\n'
    }

    html << '                </tbody>\n'
    html << '            </table>\n'
    html << '        </div>\n'
    html << '    </div>\n'
    html << '</body>\n'
    html << '</html>\n'

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
