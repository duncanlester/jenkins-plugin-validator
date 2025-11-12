#!/usr/bin/env groovy

def call() {
    echo "🛡️ Scanning for vulnerabilities..."
    
    def plugins = readJSON text: env.PLUGIN_DATA
    def warnings = readJSON text: (env.SECURITY_WARNINGS ?: '[]')
    
    def vulnerabilities = []
    
    plugins.each { plugin ->
        warnings.each { warning ->
            if (warning.name == plugin.shortName) {
                warning.versions.each { vulnVersion ->
                    if (compareVersions(plugin.version, vulnVersion.lastVersion) <= 0) {
                        vulnerabilities << [
                            plugin: plugin.shortName,
                            version: plugin.version,
                            cve: vulnVersion.pattern ?: 'SECURITY-ADVISORY',
                            severity: determineSeverity(vulnVersion),
                            description: warning.message ?: 'Security vulnerability detected',
                            url: warning.url ?: "https://www.jenkins.io/security/plugins/#${plugin.shortName}",
                            cvss: vulnVersion.cvss ?: 0.0
                        ]
                    }
                }
            }
        }
    }
    
    echo "🚨 Found ${vulnerabilities.size()} vulnerabilities"
    env.VULNERABILITIES = groovy.json.JsonOutput.toJson(vulnerabilities)
    env.VULN_COUNT = vulnerabilities.size().toString()
    
    if (vulnerabilities.size() > 0) {
        currentBuild.result = 'UNSTABLE'
    }
    
    return vulnerabilities
}

@NonCPS
def compareVersions(String v1, String v2) {
    def parts1 = v1.tokenize('.')
    def parts2 = v2.tokenize('.')
    
    def maxLen = Math.max(parts1.size(), parts2.size())
    
    for (int i = 0; i < maxLen; i++) {
        def p1 = i < parts1.size() ? parts1[i].replaceAll(/[^0-9]/, '').toInteger() : 0
        def p2 = i < parts2.size() ? parts2[i].replaceAll(/[^0-9]/, '').toInteger() : 0
        
        if (p1 < p2) return -1
        if (p1 > p2) return 1
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
