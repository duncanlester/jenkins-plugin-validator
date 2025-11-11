#!/usr/bin/env groovy

def fetchInstalledPlugins() {
    echo "📦 Fetching installed Jenkins plugins..."
    
    def pluginData = getPluginData()
    
    env.PLUGIN_DATA = groovy.json.JsonOutput.toJson(pluginData)
    
    writeFile file: 'plugins.json', text: env.PLUGIN_DATA
    archiveArtifacts artifacts: 'plugins.json'
    
    echo "✅ Found ${pluginData.size()} plugins"
}

@NonCPS
def getPluginData() {
    def jenkins = Jenkins.instance
    def pluginManager = jenkins.pluginManager
    def plugins = pluginManager.plugins
    
    return plugins.collect { plugin ->
        [
            shortName: plugin.shortName,
            longName: plugin.longName,
            version: plugin.version,
            enabled: plugin.enabled,
            active: plugin.active,
            hasUpdate: plugin.hasUpdate(),
            url: plugin.url,
            dependencies: plugin.dependencies.collect { dep ->
                [
                    shortName: dep.shortName,
                    version: dep.version,
                    optional: dep.optional
                ]
            }
        ]
    }
}

def fetchSecurityWarnings() {
    echo "🔍 Fetching security warnings from Jenkins Update Center..."
    
    def allWarnings = getSecurityWarnings()
    
    env.SECURITY_WARNINGS = groovy.json.JsonOutput.toJson(allWarnings)
    echo "⚠️ Found ${allWarnings.size()} security warnings"
}

@NonCPS
def getSecurityWarnings() {
    def jenkins = Jenkins.instance
    def updateCenter = jenkins.updateCenter
    def allWarnings = []
    
    // Force update of Update Center data
    updateCenter.sites.each { site ->
        try {
            // This is what Jenkins UI uses - force a fresh check
            site.updateDirectlyNow()
            Thread.sleep(2000) // Wait for update to complete
            
            def data = site.getData()
            
            if (data != null) {
                // Get warnings the same way Jenkins UI does
                def warnings = data.getWarnings()
                
                if (warnings != null && !warnings.isEmpty()) {
                    warnings.each { warning ->
                        // warning is a hudson.model.UpdateSite.Warning object
                        if (warning.type == 'plugin') {
                            allWarnings << [
                                type: warning.type,
                                id: warning.id,
                                name: warning.name,
                                message: warning.message,
                                url: warning.url,
                                versions: warning.versions?.collect { v -> 
                                    [pattern: v.pattern ?: v.toString()]
                                }
                            ]
                        }
                    }
                }
            }
        } catch (Exception e) {
            echo "⚠️ Error checking site ${site.url}: ${e.message}"
        }
    }
    
    return allWarnings
}

def checkForUpdates() {
    def pluginData = readJSON text: env.PLUGIN_DATA
    def outdatedPlugins = findOutdatedPlugins(pluginData)
    
    echo "📊 ${outdatedPlugins.size()} plugins have updates available"
    
    env.OUTDATED_COUNT = outdatedPlugins.size().toString()
    env.OUTDATED_PLUGINS = groovy.json.JsonOutput.toJson(outdatedPlugins)
}

@NonCPS
def findOutdatedPlugins(pluginData) {
    return pluginData.findAll { it.hasUpdate }
}

def scanVulnerabilities() {
    echo "🔍 Scanning for vulnerabilities using Jenkins' security data..."
    
    def pluginData = readJSON text: env.PLUGIN_DATA
    def securityWarnings = readJSON text: env.SECURITY_WARNINGS
    def vulnerabilities = []
    
    echo "📋 Checking ${pluginData.size()} plugins against ${securityWarnings.size()} security warnings"
    
    // Match installed plugins against security warnings
    pluginData.each { plugin ->
        securityWarnings.each { warning ->
            // Check if warning applies to this plugin
            if (warning.name == plugin.shortName) {
                
                // Check if the installed version is affected
                def isAffected = false
                
                if (warning.versions && warning.versions.size() > 0) {
                    // Check version patterns
                    warning.versions.each { versionInfo ->
                        def pattern = versionInfo.pattern
                        if (pattern) {
                            // Pattern matching logic (Jenkins uses this internally)
                            isAffected = isAffected || versionMatches(plugin.version.toString(), pattern)
                        } else {
                            // No version restriction means all versions affected
                            isAffected = true
                        }
                    }
                } else {
                    // No version info means all versions are affected
                    isAffected = true
                }
                
                if (isAffected) {
                    def cveMatch = (warning.id =~ /CVE-\d{4}-\d+/)
                    def cve = cveMatch ? cveMatch[0] : warning.id
                    
                    def severity = determineSeverity(warning.message)
                    def cvssScore = getCvssScore(severity)
                    
                    vulnerabilities << [
                        plugin: plugin.shortName,
                        version: plugin.version.toString(),
                        cve: cve,
                        severity: severity,
                        cvss: cvssScore,
                        description: warning.message,
                        url: warning.url,
                        installed: plugin.version.toString()
                    ]
                    
                    echo "⚠️ Found vulnerability: ${plugin.shortName} ${plugin.version} - ${cve}"
                }
            }
        }
    }
    
    // Remove duplicates
    vulnerabilities = vulnerabilities.unique { [it.plugin, it.cve] }
    
    env.VULNERABILITIES = groovy.json.JsonOutput.toJson(vulnerabilities)
    env.VULN_COUNT = vulnerabilities.size().toString()
    
    if (vulnerabilities.size() > 0) {
        currentBuild.result = 'UNSTABLE'
        echo "⚠️ Found ${vulnerabilities.size()} vulnerable plugins!"
        
        vulnerabilities.each { vuln ->
            echo "  ❌ ${vuln.plugin} ${vuln.version}: ${vuln.cve} (${vuln.severity})"
        }
    } else {
        echo "✅ No known vulnerabilities detected"
    }
}

@NonCPS
def versionMatches(String installedVersion, String pattern) {
    // Jenkins version pattern matching
    // Patterns like "2.0.2", "1.0", etc. mean "this version and earlier"
    
    try {
        if (pattern.contains('*')) {
            // Wildcard pattern
            def regex = pattern.replace('.', '\\.').replace('*', '.*')
            return installedVersion.matches(regex)
        } else {
            // Exact version or "up to and including" pattern
            // Jenkins treats this as "this version and all earlier versions are affected"
            def installedParts = installedVersion.split('\\.')
            def patternParts = pattern.split('\\.')
            
            // Compare version parts
            for (int i = 0; i < Math.min(installedParts.length, patternParts.length); i++) {
                def installedNum = installedParts[i].replaceAll('[^0-9]', '') as Integer
                def patternNum = patternParts[i].replaceAll('[^0-9]', '') as Integer
                
                if (installedNum < patternNum) {
                    return true  // Installed version is older, affected
                } else if (installedNum > patternNum) {
                    return false  // Installed version is newer, not affected
                }
            }
            
            // If all parts match, this version is affected
            return installedParts.length <= patternParts.length
        }
    } catch (Exception e) {
        // If parsing fails, assume affected to be safe
        return true
    }
}

@NonCPS
def determineSeverity(String message) {
    if (!message) return 'MEDIUM'
    
    def lowerMsg = message.toLowerCase()
    
    if (lowerMsg.contains('critical')) return 'CRITICAL'
    if (lowerMsg.contains('high')) return 'HIGH'
    if (lowerMsg.contains('low')) return 'LOW'
    
    return 'MEDIUM'
}

@NonCPS
def getCvssScore(String severity) {
    switch(severity) {
        case 'CRITICAL': return 9.0
        case 'HIGH': return 7.5
        case 'MEDIUM': return 5.0
        case 'LOW': return 3.0
        default: return 5.0
    }
}
