#!/usr/bin/env groovy

def call() {
    echo "📦 Generating Software Bill of Materials (SBOM)..."
    
    def plugins = readJSON text: env.PLUGIN_DATA
    def vulns = readJSON text: (env.VULNERABILITIES ?: '[]')
    
    def timestamp = new Date().format("yyyy-MM-dd'T'HH:mm:ss'Z'", TimeZone.getTimeZone('UTC'))
    def jenkinsVersion = Jenkins.instance.version.toString()
    
    def sbom = buildSBOM(plugins, vulns, timestamp, jenkinsVersion)
    
    def sbomJson = groovy.json.JsonOutput.prettyPrint(groovy.json.JsonOutput.toJson(sbom))
    writeFile file: 'sbom.json', text: sbomJson
    
    def spdxContent = generateSPDX(plugins, jenkinsVersion, timestamp)
    generateSBOMReport(sbom, spdxContent, plugins.size(), vulns.size())
    
    archiveArtifacts artifacts: 'sbom.json,sbom.spdx,sbom-report.html,sbom-style.css'
    
    echo "✅ SBOM generated: ${plugins.size()} components, ${vulns.size()} vulnerabilities"
}

@NonCPS
def buildSBOM(plugins, vulns, timestamp, jenkinsVersion) {
    def sbom = [
        bomFormat: "CycloneDX",
        specVersion: "1.5",
        serialNumber: "urn:uuid:${UUID.randomUUID()}",
        version: 1,
        metadata: [
            timestamp: timestamp,
            tools: [
                [
                    vendor: "Jenkins",
                    name: "plugin-validator",
                    version: "1.0.0"
                ]
            ],
            component: [
                type: "application",
                name: "Jenkins",
                version: jenkinsVersion,
                description: "Jenkins Automation Server"
            ]
        ],
        components: [],
        vulnerabilities: []
    ]
    
    plugins.each { p ->
        def component = [
            type: "library",
            name: p.shortName,
            version: p.version,
            description: p.longName,
            purl: "pkg:jenkins/plugin/${p.shortName}@${p.version}",
            properties: [
                [name: "enabled", value: p.enabled.toString()],
                [name: "bundled", value: (p.bundled ?: false).toString()]
            ]
        ]
        
        if (p.url) {
            component.externalReferences = [[type: "website", url: p.url]]
        }
        
        sbom.components << component
    }
    
    vulns.each { v ->
        sbom.vulnerabilities << [
            id: v.cve,
            source: [
                name: "Jenkins Security Advisory",
                url: v.url ?: "https://www.jenkins.io/security/advisories/"
            ],
            ratings: [[severity: v.severity, score: v.cvss, method: "CVSSv3"]],
            description: v.description,
            affects: [[ref: "pkg:jenkins/plugin/${v.plugin}@${v.version}"]]
        ]
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
    
    spdx << """SPDXVersion: SPDX-2.3
DataLicense: CC0-1.0
SPDXID: SPDDocument
DocumentName: Jenkins-Plugin-SBOM
DocumentNamespace: https://jenkins.io/sbom/${docId}
Creator: Tool: plugin-validator-1.0.0

PackageName: Jenkins
SPDXID: SPDPackage-Jenkins
PackageVersion: ${jenkinsVersion}
PackageDownloadLocation: https://www.jenkins.io/
FilesAnalyzed: false

"""
    plugins.each { p ->
        def pkgId = "SPDPackage-${p.shortName.replaceAll('[^a-zA-Z0-9]', '-')}"
        spdx << """PackageName: ${p.shortName}
SPDXID: ${pkgId}
PackageVersion: ${p.version}
PackageDownloadLocation: ${p.url ?: 'NOASSERTION'}
FilesAnalyzed: false

Relationship: SPDPackage-Jenkins DEPENDS_ON ${pkgId}

"""
    }
    
    return spdx.toString()
}

def generateSBOMReport(sbom, spdxContent, componentCount, vulnCount) {
    def cssContent = libraryResource('report-style.css')
    writeFile file: 'sbom-style.css', text: cssContent
    
    def serialNum = sbom.serialNumber.replaceAll('urn:uuid:', '')
    def vulnColorClass = vulnCount > 0 ? 'color-danger' : 'color-success'
    
    // Escape HTML in SPDX content
    def spdxHtml = spdxContent.toString()
        .replace('&', '&amp;')
        .replace('<', '&lt;')
        .replace('>', '&gt;')
    
    def html = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SBOM Report</title>
    <link rel="stylesheet" href="sbom-style.css">
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>📦 Software Bill of Materials (SBOM)</h1>
            <div class="header-meta">
                <div><strong>Format:</strong> CycloneDX 1.5 / SPDX 2.3</div>
                <div><strong>Generated:</strong> ${sbom.metadata.timestamp}</div>
                <div><strong>Components:</strong> ${componentCount}</div>
            </div>
        </div>
        
        <div class="section">
            <h2>📊 SBOM Summary</h2>
            <div class="summary-grid">
                <div class="summary-item">
                    <h4>Total Components</h4>
                    <div class="summary-value">${componentCount}</div>
                </div>
                <div class="summary-item">
                    <h4>Vulnerabilities</h4>
                    <div class="summary-value ${vulnColorClass}">${vulnCount}</div>
                </div>
                <div class="summary-item">
                    <h4>SBOM Format</h4>
                    <div class="summary-value">CycloneDX 1.5</div>
                </div>
                <div class="summary-item">
                    <h4>Serial Number</h4>
                    <div class="summary-value serial-number">${serialNum}</div>
                </div>
            </div>
            
            <div class="links-group">
                <a href="sbom.json" class="issue-link" download>📥 Download CycloneDX JSON</a>
                <a href="sbom.spdx" class="issue-link" download>📥 Download SPDX</a>
                <a href="plugins.json" class="issue-link" download>📥 Download Raw Data</a>
            </div>
        </div>
        
        <div class="section">
            <h2>📋 SPDX Document (ISO/IEC 5962:2021)</h2>
            <p class="sbom-intro">Software Package Data eXchange (SPDX) is an open standard for communicating software bill of material information.</p>
            <pre class="spdx-viewer"><code>${spdxHtml}</code></pre>
        </div>
        
        <div class="section">
            <h2>📋 About SBOM</h2>
            <p class="sbom-intro"><strong>Software Bill of Materials (SBOM)</strong> is a comprehensive inventory of all software components, dependencies, and metadata.</p>
            
            <h4 class="sbom-subheading">Standards Included:</h4>
            <ul class="sbom-list">
                <li><strong>CycloneDX 1.5:</strong> Modern SBOM format designed for security use cases, includes vulnerability data</li>
                <li><strong>SPDX 2.3:</strong> ISO/IEC standard for software package data exchange</li>
            </ul>
            
            <h4 class="sbom-subheading">Use Cases:</h4>
            <ul class="sbom-list">
                <li>Supply chain security and transparency</li>
                <li>License compliance and auditing</li>
                <li>Vulnerability tracking and remediation</li>
                <li>Software composition analysis (SCA)</li>
                <li>Regulatory compliance (e.g., Executive Order 14028)</li>
            </ul>
        </div>
    </div>
</body>
</html>
"""
    
    writeFile file: 'sbom-report.html', text: html
}
