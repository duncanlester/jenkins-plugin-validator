#!/usr/bin/env groovy

def call() {
    echo "📦 Generating Software Bill of Materials (SBOM)..."

    def plugins = readJSON text: env.PLUGIN_DATA
    def vulns = readJSON text: (env.VULNERABILITIES ?: '[]')

    echo "Building CycloneDX SBOM with ${plugins.size()} components and ${vulns.size()} vulnerabilities"

    def timestamp = new Date().format("yyyy-MM-dd'T'HH:mm:ss'Z'", TimeZone.getTimeZone('UTC'))
    def jenkinsVersion = Jenkins.instance.version.toString()

    def sbom = buildSBOM(plugins, vulns, timestamp, jenkinsVersion)

    def sbomJson = groovy.json.JsonOutput.prettyPrint(groovy.json.JsonOutput.toJson(sbom))
    writeFile file: 'sbom.json', text: sbomJson

    echo "✅ CycloneDX SBOM generated: ${sbom.components.size()} components, ${sbom.vulnerabilities.size()} vulnerabilities"

    generateSBOMReport(sbom, plugins.size(), vulns)

    archiveArtifacts artifacts: 'sbom.json,sbom-report.html,sbom-style.css'

    echo "✅ SBOM files generated:"
    echo "   - sbom.json (CycloneDX 1.5 - includes ${vulns.size()} vulnerabilities)"
    echo "   - sbom-report.html (interactive report)"
}

@NonCPS
def buildSBOM(plugins, vulns, timestamp, jenkinsVersion) {
    def sbom = [:]
    sbom.bomFormat = "CycloneDX"
    sbom.specVersion = "1.5"
    sbom.serialNumber = "urn:uuid:${UUID.randomUUID()}"
    sbom.version = 1
    sbom.metadata = [:]
    sbom.metadata.timestamp = timestamp
    sbom.metadata.tools = []

    def tool = [:]
    tool.vendor = "Jenkins"
    tool.name = "plugin-validator"
    tool.version = "1.0.0"
    sbom.metadata.tools << tool

    sbom.metadata.component = [:]
    sbom.metadata.component.type = "application"
    sbom.metadata.component.name = "Jenkins"
    sbom.metadata.component.version = jenkinsVersion
    sbom.metadata.component.description = "Jenkins Automation Server"

    sbom.components = []
    sbom.vulnerabilities = []

    plugins.each { p ->
        def component = [:]
        component.type = "library"
        component.name = p.shortName
        component.version = p.version
        component.description = p.longName
        component.purl = "pkg:jenkins/plugin/${p.shortName}@${p.version}"
        component.properties = []

        def enabledProp = [:]
        enabledProp.name = "enabled"
        enabledProp.value = p.enabled.toString()
        component.properties << enabledProp

        def bundledProp = [:]
        bundledProp.name = "bundled"
        bundledProp.value = (p.bundled ?: false).toString()
        component.properties << bundledProp

        if (p.url) {
            component.externalReferences = []
            def ref = [:]
            ref.type = "website"
            ref.url = p.url
            component.externalReferences << ref
        }

        sbom.components << component
    }

    vulns.each { v ->
        def vuln = [:]
        vuln.id = v.cve ?: 'UNKNOWN'

        vuln.source = [:]
        vuln.source.name = "Jenkins Security Advisory"
        vuln.source.url = v.url ?: "https://www.jenkins.io/security/advisories/"

        vuln.ratings = []
        def rating = [:]
        rating.severity = (v.severity ?: 'MEDIUM').toLowerCase()  // Convert to lowercase
        rating.score = v.cvss ?: 5.0
        rating.method = "CVSSv3"
        vuln.ratings << rating

        vuln.description = v.description ?: 'Security vulnerability detected'

        vuln.affects = []
        def affect = [:]
        affect.ref = "pkg:jenkins/plugin/${v.plugin}@${v.version}"
        vuln.affects << affect

        sbom.vulnerabilities << vuln
    }

    return sbom
}

def generateSBOMReport(sbom, componentCount, vulns) {
    def cssContent = libraryResource('report-style.css')
    writeFile file: 'sbom-style.css', text: cssContent

    def serialNum = sbom.serialNumber.replaceAll('urn:uuid:', '')
    def vulnCount = vulns.size()
    def vulnColorClass = vulnCount > 0 ? 'color-danger' : 'color-success'

    def html = buildReportHtml(sbom, serialNum, vulnColorClass, componentCount, vulns)

    writeFile file: 'sbom-report.html', text: html
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
def buildReportHtml(sbom, serialNum, vulnColorClass, componentCount, vulns) {
    def html = new StringBuilder()
    def vulnCount = vulns.size()

    html << '<!DOCTYPE html>\n'
    html << '<html lang="en">\n'
    html << '<head>\n'
    html << '    <meta charset="UTF-8">\n'
    html << '    <meta name="viewport" content="width=device-width, initial-scale=1.0">\n'
    html << '    <title>CycloneDX SBOM Report</title>\n'
    html << '    <link rel="stylesheet" href="sbom-style.css">\n'
    html << '</head>\n'
    html << '<body>\n'
    html << '    <div class="container">\n'
    html << '        <div class="header">\n'
    html << '            <h1>📦 Software Bill of Materials (SBOM)</h1>\n'
    html << '            <div class="header-meta">\n'
    html << "                <div><strong>Format:</strong> CycloneDX 1.5</div>\n"
    html << "                <div><strong>Generated:</strong> ${sbom.metadata.timestamp}</div>\n"
    html << "                <div><strong>Components:</strong> ${componentCount}</div>\n"
    html << '            </div>\n'
    html << '        </div>\n'
    html << '        \n'
    html << '        <div class="section">\n'
    html << '            <h2>📊 SBOM Summary</h2>\n'
    html << '            <div class="summary-grid">\n'
    html << '                <div class="summary-item">\n'
    html << '                    <h4>Total Components</h4>\n'
    html << "                    <div class=\"summary-value\">${componentCount}</div>\n"
    html << '                </div>\n'
    html << '                <div class="summary-item">\n'
    html << '                    <h4>Vulnerabilities</h4>\n'
    html << "                    <div class=\"summary-value ${vulnColorClass}\">${vulnCount}</div>\n"
    html << '                </div>\n'
    html << '                <div class="summary-item">\n'
    html << '                    <h4>SBOM Format</h4>\n'
    html << '                    <div class="summary-value">CycloneDX 1.5</div>\n'
    html << '                </div>\n'
    html << '                <div class="summary-item">\n'
    html << '                    <h4>Serial Number</h4>\n'
    html << "                    <div class=\"summary-value serial-number\">${serialNum}</div>\n"
    html << '                </div>\n'
    html << '            </div>\n'
    html << '            \n'
    html << '            <div class="links-group">\n'
    html << '                <a href="sbom.json" class="issue-link" download>📥 Download CycloneDX JSON</a>\n'
    html << '                <a href="https://cyclonedx.org/" class="issue-link">📖 CycloneDX Documentation</a>\n'
    html << '                <a href="https://dependencytrack.org/" class="issue-link">🔍 Dependency-Track</a>\n'
    html << '            </div>\n'
    html << '        </div>\n'
    html << '        \n'
    html << '        <div class="section">\n'
    html << '            <h2>🔷 About CycloneDX</h2>\n'
    html << '            <p class="sbom-intro">CycloneDX is a lightweight SBOM standard designed for security use cases. It provides:</p>\n'
    html << '            <ul class="sbom-list">\n'
    html << '                <li><strong>Native Vulnerability Support</strong> - CVE tracking with CVSS scores</li>\n'
    html << '                <li><strong>Package URLs (PURL)</strong> - Unique identifiers for each component</li>\n'
    html << '                <li><strong>Security Tool Integration</strong> - Works with Dependency-Track, Grype, Trivy</li>\n'
    html << '                <li><strong>Machine-Readable JSON</strong> - Easy to parse and automate</li>\n'
    html << '                <li><strong>OWASP Standard</strong> - Maintained by the security community</li>\n'
    html << '            </ul>\n'
    html << '        </div>\n'
    html << '        \n'

    if (vulnCount > 0) {
        html << '        <div class="section">\n'
        html << "            <h2>🚨 Vulnerabilities (${vulnCount})</h2>\n"
        html << '            <p class="sbom-intro">The following vulnerabilities are included in the sbom.json file:</p>\n'
        html << '            <table>\n'
        html << '                <thead>\n'
        html << '                    <tr>\n'
        html << '                        <th class="col-20">Plugin</th>\n'
        html << '                        <th class="col-12">Version</th>\n'
        html << '                        <th class="col-18">CVE ID</th>\n'
        html << '                        <th class="col-10">Severity</th>\n'
        html << '                        <th class="col-10">CVSS</th>\n'
        html << '                        <th class="col-30">Package URL (PURL)</th>\n'
        html << '                    </tr>\n'
        html << '                </thead>\n'
        html << '                <tbody>\n'

        vulns.each { v ->
            def purl = "pkg:jenkins/plugin/${v.plugin}@${v.version}"
            def cveUrl = escapeHtml(v.url ?: "https://www.jenkins.io/security/advisories/")

            html << '                    <tr>\n'
            html << "                        <td><strong>${escapeHtml(v.plugin)}</strong></td>\n"
            html << "                        <td>${escapeHtml(v.version)}</td>\n"
            html << "                        <td><a href=\"${cveUrl}\" class=\"cve-link\">${escapeHtml(v.cve)}</a></td>\n"
            html << "                        <td><span class=\"badge badge-${v.severity.toLowerCase()}\">${escapeHtml(v.severity)}</span></td>\n"
            html << "                        <td>${v.cvss ?: 'N/A'}</td>\n"
            html << "                        <td><code>${escapeHtml(purl)}</code></td>\n"
            html << '                    </tr>\n'
        }

        html << '                </tbody>\n'
        html << '            </table>\n'
        html << '            <p class="sbom-intro" style="margin-top: 16px;"><strong>In sbom.json:</strong> Find these in the <code>"vulnerabilities": []</code> array at the bottom of the file.</p>\n'
        html << '        </div>\n'
    } else {
        html << '        <div class="section">\n'
        html << '            <h2>✅ No Vulnerabilities</h2>\n'
        html << '            <div class="summary-item-success">\n'
        html << '                <h4>All Components Secure</h4>\n'
        html << '                <div class="summary-value color-success">0 vulnerabilities detected</div>\n'
        html << '            </div>\n'
        html << '        </div>\n'
    }

    html << '        <div class="section">\n'
    html << '            <h2>📚 Resources</h2>\n'
    html << '            <ul class="sbom-list">\n'
    html << '                <li><a href="https://cyclonedx.org/">CycloneDX Official Website</a></li>\n'
    html << '                <li><a href="https://dependencytrack.org/">Dependency-Track (SBOM Analysis Platform)</a></li>\n'
    html << '                <li><a href="https://github.com/anchore/grype">Grype (Vulnerability Scanner)</a></li>\n'
    html << '                <li><a href="https://www.cisa.gov/sbom">CISA SBOM Resources</a></li>\n'
    html << '                <li><a href="https://owasp.org/www-project-cyclonedx/">OWASP CycloneDX Project</a></li>\n'
    html << '            </ul>\n'
    html << '        </div>\n'
    html << '    </div>\n'
    html << '</body>\n'
    html << '</html>\n'

    return html.toString()
}
