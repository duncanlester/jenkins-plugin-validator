#!/usr/bin/env groovy

def call() {
    echo "============================================"
    echo "Starting Vulnerability Scan"
    echo "============================================"
    
    def plugins = readJSON text: env.PLUGIN_DATA
    def warnings = readJSON text: (env.SECURITY_WARNINGS ?: '[]')
    
    echo "Scanning ${plugins.size()} plugins against ${warnings.size()} security warnings"
    
    def vulnerabilities = findVulnerabilities(plugins, warnings)
    
    echo "Found ${vulnerabilities.size()} raw vulnerability entries"
    
    // Deduplicate vulnerabilities by plugin name
    def deduped = deduplicateVulnerabilities(vulnerabilities)
    
    echo "============================================"
    echo "Vulnerability Scan Results"
    echo "============================================"
    echo "Total unique plugins with vulnerabilities: ${deduped.size()}"
    
    if (deduped.size() > 0) {
        echo ""
        echo "Vulnerabilities detected:"
        deduped.each { v ->
            echo "  - ${v.plugin} v${v.version}"
            echo "    CVEs: ${v.cve}"
            echo "    Severity: ${v.severity}"
            echo "    Count: ${v.count} vulnerabilities"
            echo ""
        }
    } else {
        echo "No vulnerabilities detected"
    }
    
    echo "============================================"
    
    env.VULNERABILITIES = groovy.json.JsonOutput.toJson(deduped)
    env.VULN_COUNT = deduped.size().toString()
    
    if (deduped.size() > 0) {
        currentBuild.result = 'UNSTABLE'
        echo "Build marked as UNSTABLE due to security vulnerabilities"
    }
    
    return deduped
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
def deduplicateVulnerabilities(vulnerabilities) {
    def grouped = [:]
    
    vulnerabilities.each { v ->
        def key = v.plugin + ':' + v.version
        
        if (!grouped.containsKey(key)) {
            grouped[key] = [
                plugin: v.plugin,
                version: v.version,
                cve: v.cve,
                severity: v.severity,
                description: v.description,
                url: v.url,
                cvss: v.cvss,
                count: 1,
                allCves: [v.cve],
                allDescriptions: [v.description]
            ]
        } else {
            // Add this CVE to the list
            grouped[key].allCves << v.cve
            grouped[key].allDescriptions << v.description
            grouped[key].count++
            
            // Keep the highest severity
            if (compareSeverity(v.severity, grouped[key].severity) > 0) {
                grouped[key].severity = v.severity
            }
            
            // Keep the highest CVSS score
            if (v.cvss > grouped[key].cvss) {
                grouped[key].cvss = v.cvss
            }
        }
    }
    
    // Convert back to list and combine CVEs and descriptions
    def deduped = []
    grouped.each { key, value ->
        // Make CVE list unique and join
        def uniqueCves = value.allCves.unique()
        value.cve = uniqueCves.join(', ')
        
        // Combine descriptions
        if (value.count > 1) {
            def allDescs = value.allDescriptions.collect { it.take(100) }.join(' | ')
            value.description = "Multiple vulnerabilities (${value.count}): ${uniqueCves.join(', ')}. ${allDescs}"
        }
        
        // Clean up temporary fields
        value.remove('allCves')
        value.remove('allDescriptions')
        
        deduped << value
    }
    
    return deduped
}

@NonCPS
def compareSeverity(String sev1, String sev2) {
    def severityOrder = ['LOW': 1, 'MEDIUM': 2, 'HIGH': 3, 'CRITICAL': 4]
    def level1 = severityOrder[sev1] ?: 0
    def level2 = severityOrder[sev2] ?: 0
    return level1 - level2
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
