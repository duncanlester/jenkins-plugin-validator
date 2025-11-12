#!/usr/bin/env groovy

def call() {
    echo "📦 Generating Software Bill of Materials (SBOM)..."
    
    def plugins = readJSON text: env.PLUGIN_DATA
    def vulns = readJSON text: (env.VULNERABILITIES ?: '[]')
    
    echo "DEBUG: Found ${vulns.size()} vulnerabilities to add to SBOM"
    if (vulns.size() > 0) {
        echo "DEBUG: Vulnerability data:"
        vulns.each { v ->
            echo "  - Plugin: ${v.plugin}, CVE: ${v.cve}, Severity: ${v.severity}"
        }
    }
    
    def timestamp = new Date().format("yyyy-MM-dd'T'HH:mm:ss'Z'", TimeZone.getTimeZone('UTC'))
    def jenkinsVersion = Jenkins.instance.version.toString()
    
    echo "Building SBOM with ${plugins.size()} components and ${vulns.size()} vulnerabilities"
    
    def sbom = buildSBOM(plugins, vulns, timestamp, jenkinsVersion)
    
    echo "DEBUG: SBOM built with ${sbom.components.size()} components and ${sbom.vulnerabilities.size()} vulnerabilities"
    
    def sbomJson = groovy.json.JsonOutput.prettyPrint(groovy.json.JsonOutput.toJson(sbom))
    writeFile file: 'sbom.json', text: sbomJson
    
    echo "✅ CycloneDX SBOM: ${sbom.components.size()} components, ${sbom.vulnerabilities.size()} vulnerabilities"
    
    def spdxContent = generateSPDX(plugins, jenkinsVersion, timestamp)
    echo "✅ SPDX SBOM: ${plugins.size()} packages"
    
    generateSBOMReport(sbom, spdxContent, plugins.size(), vulns)
    
    archiveArtifacts artifacts: 'sbom.json,sbom.spdx,sbom-report.html,sbom-style.css'
    
    echo "✅ SBOM generated: ${plugins.size()} components, ${vulns.size()} vulnerabilities"
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
    
    // Add vulnerabilities to SBOM
    vulns.each { v ->
        def vuln = [:]
        vuln.id = v.cve ?: 'UNKNOWN'
        
        vuln.source = [:]
        vuln.source.name = "Jenkins Security Advisory"
        vuln.source.url = v.url ?: "https://www.jenkins.io/security/advisories/"
        
        vuln.ratings = []
        def rating = [:]
        rating.severity = v.severity ?: 'MEDIUM'
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

def generateSPDX(plugins, jenkinsVersion, timestamp) {
    def spdx = buildSPDXContent(plugins, jenkinsVersion)
    writeFile file: 'sbom.spdx', text: spdx
    return spdx
}

@NonCPS
def buildSPDXContent(plugins, jenkinsVersion) {
    def spdx = new StringBuilder()
    def docId = UUID.randomUUID().toString()
    
    spdx << "SPDXVersion: SPDX-2.3\n"
    spdx << "DataLicense: CC0-1.0\n"
    spdx << "SPDXID: SPDDocument\n"
    spdx << "DocumentName: Jenkins-Plugin-SBOM\n"
    spdx << "DocumentNamespace: https://jenkins.io/sbom/${docId}\n"
    spdx << "Creator: Tool: plugin-validator-1.0.0\n"
    spdx << "\n"
    spdx << "PackageName: Jenkins\n"
    spdx << "SPDXID: SPDPackage-Jenkins\n"
    spdx << "PackageVersion: ${jenkinsVersion}\n"
    spdx << "PackageDownloadLocation: https://www.jenkins.io/\n"
    spdx << "FilesAnalyzed: false\n"
    spdx << "\n"
    
    plugins.each { p ->
        def pkgId = "SPDPackage-${p.shortName.replaceAll('[^a-zA-Z0-9]', '-')}"
        spdx << "PackageName: ${p.shortName}\n"
        spdx << "SPDXID: ${pkgId}\n"
        spdx << "PackageVersion: ${p.version}\n"
        spdx << "PackageDownloadLocation: ${p.url ?: 'NOASSERTION'}\n"
        spdx << "FilesAnalyzed: false\n"
        spdx << "\n"
        spdx << "Relationship: SPDPackage-Jenkins DEPENDS_ON ${pkgId}\n"
        spdx << "\n"
    }
    
    return spdx.toString()
}

def generateSBOMReport(sbom, spdxContent, componentCount, vulns) {
    def cssContent = libraryResource('report-style.css')
    writeFile file: 'sbom-style.css', text: cssContent
    
    def serialNum = sbom.serialNumber.replaceAll('urn:uuid:', '')
    def vulnCount = vulns.size()
    def vulnColorClass = vulnCount > 0 ? 'color-danger' : 'color-success'
    
    def spdxHtml = escapeHtml(spdxContent.toString())
    
    def html = buildReportHtml(sbom, spdxHtml, serialNum, vulnColorClass, componentCount, vulns)
    
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
def buildReportHtml(sbom, spdxHtml, serialNum, vulnColorClass, componentCount, vulns) {
    def html = new StringBuilder()
    def vulnCount = vulns.size()
    
    html << '<!DOCTYPE html>\n'
    html << '<html lang="en">\n'
    html << '<head>\n'
    html << '    <meta charset="UTF-8">\n'
    html << '    <meta name="viewport" content="width=device-width, initial-scale=1.0">\n'
    html << '    <title>SBOM Report</title>\n'
    html << '    <link rel="stylesheet" href="sbom-style.css">\n'
    html << '</head>\n'
    html << '<body>\n'
    html << '    <div class="container">\n'
    html << '        <div class="header">\n'
    html << '            <h1>📦 Software Bill of Materials (SBOM)</h1>\n'
    html << '            <div class="header-meta">\n'
    html << "                <div><strong>Format:</strong> CycloneDX 1.5 / SPDX 2.3</div>\n"
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
    html << '                <a href="sbom.spdx" class="issue-link" download>📥 Download SPDX</a>\n'
    html << '                <a href="plugins.json" class="issue-link" download>📥 Download Raw Data</a>\n'
    html << '            </div>\n'
    html << '        </div>\n'
    html << '        \n'
    
    if (vulnCount > 0) {
        html << '        <div class="section">\n'
        html << "            <h2>🚨 Vulnerabilities in CycloneDX SBOM (${vulnCount})</h2>\n"
        html << '            <p class="sbom-intro">The following vulnerabilities are included in the sbom.json file:</p>\n'
        html << '            <table>\n'
        html << '                <thead>\n'
        html << '                    <tr>\n'
        html << '                        <th class="col-20">Plugin</th>\n'
        html << '                        <th class="col-15">Version</th>\n'
        html << '                        <th class="col-20">CVE ID</th>\n'
        html << '                        <th class="col-10">Severity</th>\n'
        html << '                        <th class="col-10">CVSS Score</th>\n'
        html << '                        <th class="col-25">PURL Reference</th>\n'
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
        html << '            <p class="sbom-intro" style="margin-top: 16px;"><strong>Note:</strong> These vulnerabilities are included in the <code>sbom.json</code> file under the <code>vulnerabilities</code> array, mapped to their corresponding components via Package URL (PURL).</p>\n'
        html << '        </div>\n'
    }
    
    html << '        <div class="section">\n'
    html << '            <h2>📋 Format Comparison: CycloneDX vs SPDX</h2>\n'
    html << '            <div class="summary-grid">\n'
    html << '                <div class="summary-item">\n'
    html << '                    <h4>CycloneDX 1.5</h4>\n'
    html << '                    <div class="summary-value color-success">✅ Vulnerabilities</div>\n'
    html << '                    <p style="font-size: 12px; margin-top: 8px;">Security-focused SBOM format with native CVE support</p>\n'
    html << '                </div>\n'
    html << '                <div class="summary-item">\n'
    html << '                    <h4>SPDX 2.3</h4>\n'
    html << '                    <div class="summary-value color-warning">⚠️  Limited</div>\n'
    html << '                    <p style="font-size: 12px; margin-top: 8px;">ISO standard focused on licensing and compliance</p>\n'
    html << '                </div>\n'
    html << '            </div>\n'
    html << '        </div>\n'
    html << '        \n'
    html << '        <div class="section">\n'
    html << '            <h2>📋 SPDX Document (ISO/IEC 5962:2021)</h2>\n'
    html << '            <p class="sbom-intro">Software Package Data eXchange (SPDX) standard for SBOM. Note: SPDX 2.3 has limited vulnerability support.</p>\n'
    html << '            <pre class="spdx-viewer"><code>' + spdxHtml + '</code></pre>\n'
    html << '        </div>\n'
    html << '    </div>\n'
    html << '</body>\n'
    html << '</html>\n'
    
    return html.toString()
}
