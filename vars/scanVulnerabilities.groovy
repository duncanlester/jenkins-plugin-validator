#!/usr/bin/env groovy

def call() {
    echo "============================================"
    echo "Starting Vulnerability Scan"
    echo "============================================"
    
    def plugins = readJSON text: env.PLUGIN_DATA
    def warnings = readJSON text: (env.SECURITY_WARNINGS ?: '[]')
    
    echo "Scanning ${plugins.size()} plugins against ${warnings.size()} security warnings"
    
    def vulnerabilities = findVulnerabilities(plugins, warnings)
    
    echo "============================================"
    echo "Vulnerability Scan Results"
    echo "============================================"
    echo "Total vulnerabilities found: ${vulnerabilities.size()}"
    
    if (vulnerabilities.size() > 0) {
        echo ""
        echo "Vulnerabilities detected:"
        vulnerabilities.each { v ->
            echo "  - ${v.plugin} v${v.version}"
            echo "    CVE: ${v.cve}"
            echo "    Severity: ${v.severity}"
            echo "    Description: ${v.description}"
            echo ""
        }
    } else {
        echo "No vulnerabilities detected"
    }
    
    echo "============================================"
    
    env.VULNERABILITIES = groovy.json.JsonOutput.toJson(vulnerabilities)
    env.VULN_COUNT = vulnerabilities.size().toString()
    
    if (vulnerabilities.size() > 0) {
        currentBuild.result = 'UNSTABLE'
        echo "Build marked as UNSTABLE due to security vulnerabilities"
    }
    
    return vulnerabilities
}

@NonCPS
def findVulnerabilities(plugins, warnings) {
    def vulnerabilities = []
    
    plugins.each { plugin ->
        warnings.each { warning ->
            def pluginMatches = (warning.name == plugin.shortName) || 
                                (warning.name == plugin.shortName + '-plugin') ||
                                (warning.name + '-plugin' == plugin.shortName) ||
                                (warning.id == plugin.shortName)
            
            if (pluginMatches) {
                if (warning.versions && warning.versions.size() > 0) {
                    warning.versions.each { vulnVersion ->
                        def isAffected = false
                        
                        if (vulnVersion.lastVersion) {
                            if (compareVersions(plugin.version, vulnVersion.lastVersion) <= 0) {
                                isAffected = true
                            }
                        } else if (vulnVersion.firstVersion) {
                            if (compareVersions(plugin.version, vulnVersion.firstVersion) >= 0) {
                                isAffected = true
                            }
                        } else {
                            isAffected = true
                        }
                        
                        if (isAffected) {
                            vulnerabilities << [
                                plugin: plugin.shortName,
                                version: plugin.version,
                                cve: vulnVersion.pattern ?: warning.id ?: 'SECURITY-ADVISORY',
                                severity: determineSeverity(vulnVersion),
                                description: warning.message ?: 'Security vulnerability detected',
                                url: warning.url ?: "https://www.jenkins.io/security/plugins/#${plugin.shortName}",
                                cvss: vulnVersion.cvss ?: 0.0
                            ]
                        }
                    }
                } else {
                    vulnerabilities << [
                        plugin: plugin.shortName,
                        version: plugin.version,
                        cve: warning.id ?: 'SECURITY-ADVISORY',
                        severity: 'HIGH',
                        description: warning.message ?: 'Security vulnerability detected',
                        url: warning.url ?: "https://www.jenkins.io/security/plugins/#${plugin.shortName}",
                        cvss: 5.0
                    ]
                }
            }
        }
    }
    
    return vulnerabilities
}

@NonCPS
def compareVersions(String v1, String v2) {
    if (!v1 || !v2) return 0
    
    def parts1 = v1.tokenize('.-_')
    def parts2 = v2.tokenize('.-_')
    
    def maxLen = Math.max(parts1.size(), parts2.size())
    
    for (int i = 0; i < maxLen; i++) {
        def p1 = i < parts1.size() ? parts1[i] : '0'
        def p2 = i < parts2.size() ? parts2[i] : '0'
        
        try {
            def n1 = p1.replaceAll(/[^0-9]/, '')
            def n2 = p2.replaceAll(/[^0-9]/, '')
            
            if (n1 && n2) {
                def num1 = n1.toInteger()
                def num2 = n2.toInteger()
                
                if (num1 < num2) return -1
                if (num1 > num2) return 1
            }
        } catch (Exception e) {
            if (p1 < p2) return -1
            if (p1 > p2) return 1
        }
    }
    
    return 0
}

@NonCPS
def determineSeverity(vulnVersion) {
    def cvss = vulnVersion.cvss ?: 0.0
    
    if (cvss >= 9.0) return 'CRITICAL'
    if (cvss >= 7.0) return 'HIGH'
    if (cvss >= 4.0) return 'MEDIUM'
    return 'LOW'
}
