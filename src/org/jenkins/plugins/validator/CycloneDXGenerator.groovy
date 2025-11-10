package org.jenkins.plugins.validator

import java.security.MessageDigest
import jenkins.model.Jenkins

class CycloneDXGenerator implements Serializable {
    
    private boolean enhanced = true
    
    void setEnhanced(boolean enhanced) {
        this.enhanced = enhanced
    }
    
    String generate(List plugins, List vulnerabilities) {
        def timestamp = new Date().format("yyyy-MM-dd'T'HH:mm:ss'Z'")
        def jenkins = Jenkins.instance
        
        return groovy.json.JsonOutput.toJson([
            bomFormat: "CycloneDX",
            specVersion: "1.5",
            serialNumber: "urn:uuid:${UUID.randomUUID()}",
            version: 1,
            metadata: generateMetadata(timestamp, jenkins.version),
            components: generateComponents(plugins, jenkins),
            dependencies: generateDependencies(plugins),
            vulnerabilities: generateVulnerabilities(vulnerabilities)
        ])
    }
    
    private def generateMetadata(String timestamp, String jenkinsVersion) {
        return [
            timestamp: timestamp,
            tools: [
                components: [
                    [
                        type: "application",
                        name: "Jenkins Plugin Validator",
                        version: "1.0.0",
                        author: "duncanlester"
                    ]
                ]
            ],
            component: [
                type: "application",
                name: "Jenkins",
                version: jenkinsVersion,
                description: "Jenkins Automation Server"
            ]
        ]
    }
    
    private def generateComponents(List plugins, jenkins) {
        return plugins.collect { plugin ->
            def component = [
                type: "library",
                "bom-ref": "pkg:jenkins/plugin/${plugin.shortName}@${plugin.version}",
                name: plugin.shortName,
                version: plugin.version,
                description: plugin.longName,
                purl: "pkg:jenkins/plugin/${plugin.shortName}@${plugin.version}"
            ]
            
            // Add enhanced features if enabled
            if (enhanced) {
                // Add hashes
                def hashes = getPluginHashes(plugin, jenkins)
                if (hashes) {
                    component.hashes = hashes
                }
                
                // Add licenses
                def licenses = getPluginLicenses(plugin, jenkins)
                if (licenses) {
                    component.licenses = licenses
                }
                
                // Add supplier
                component.supplier = [
                    name: "Jenkins Community",
                    url: ["https://github.com/jenkinsci/${plugin.shortName}-plugin"]
                ]
                
                // Add external references
                component.externalReferences = [
                    [
                        type: "website",
                        url: "https://plugins.jenkins.io/${plugin.shortName}"
                    ],
                    [
                        type: "vcs",
                        url: "https://github.com/jenkinsci/${plugin.shortName}-plugin"
                    ],
                    [
                        type: "issue-tracker",
                        url: "https://github.com/jenkinsci/${plugin.shortName}-plugin/issues"
                    ],
                    [
                        type: "distribution",
                        url: plugin.url ?: "https://updates.jenkins.io/download/plugins/${plugin.shortName}/${plugin.version}/${plugin.shortName}.hpi"
                    ]
                ]
                
                // Add properties
                component.properties = [
                    [name: "jenkins:enabled", value: plugin.enabled.toString()],
                    [name: "jenkins:active", value: plugin.active.toString()],
                    [name: "jenkins:hasUpdate", value: plugin.hasUpdate.toString()],
                    [name: "jenkins:bundled", value: isBundled(plugin, jenkins).toString()],
                    [name: "jenkins:pinned", value: isPinned(plugin, jenkins).toString()],
                    [name: "sbom:enhanced", value: "true"]
                ]
            } else {
                // Basic properties only
                component.properties = [
                    [name: "jenkins:enabled", value: plugin.enabled.toString()],
                    [name: "jenkins:active", value: plugin.active.toString()],
                    [name: "jenkins:hasUpdate", value: plugin.hasUpdate.toString()]
                ]
            }
            
            return component
        }
    }
    
    private def getPluginHashes(plugin, jenkins) {
        try {
            // Try to find the plugin file
            def pluginDir = jenkins.pluginManager.rootDir
            def pluginFile = new File(pluginDir, "${plugin.shortName}.jpi")
            
            // Try .hpi extension if .jpi not found
            if (!pluginFile.exists()) {
                pluginFile = new File(pluginDir, "${plugin.shortName}.hpi")
            }
            
            if (pluginFile.exists() && pluginFile.canRead()) {
                def sha256 = calculateSHA256(pluginFile)
                def md5 = calculateMD5(pluginFile)
                
                return [
                    [
                        alg: "SHA-256",
                        content: sha256
                    ],
                    [
                        alg: "MD5",
                        content: md5
                    ]
                ]
            }
        } catch (Exception e) {
            // Silently fail - hashes are optional
        }
        return null
    }
    
    private String calculateSHA256(File file) {
        def digest = MessageDigest.getInstance("SHA-256")
        file.withInputStream { is ->
            byte[] buffer = new byte[8192]
            int read
            while ((read = is.read(buffer)) != -1) {
                digest.update(buffer, 0, read)
            }
        }
        return digest.digest().encodeHex().toString()
    }
    
    private String calculateMD5(File file) {
        def digest = MessageDigest.getInstance("MD5")
        file.withInputStream { is ->
            byte[] buffer = new byte[8192]
            int read
            while ((read = is.read(buffer)) != -1) {
                digest.update(buffer, 0, read)
            }
        }
        return digest.digest().encodeHex().toString()
    }
    
    private def getPluginLicenses(plugin, jenkins) {
        try {
            // Try to extract license from plugin manifest
            def pluginWrapper = jenkins.pluginManager.getPlugin(plugin.shortName)
            if (pluginWrapper) {
                def manifest = pluginWrapper.manifest
                def licenseName = manifest?.mainAttributes?.getValue('Plugin-License')
                
                if (licenseName) {
                    return [
                        [
                            license: [
                                name: licenseName,
                                url: getLicenseUrl(licenseName)
                            ]
                        ]
                    ]
                }
            }
        } catch (Exception e) {
            // Silently fail
        }
        
        // Default to MIT (common for Jenkins plugins)
        return [
            [
                license: [
                    id: "MIT",
                    name: "MIT License"
                ]
            ]
        ]
    }
    
    private String getLicenseUrl(String licenseName) {
        def licenseMap = [
            "MIT": "https://opensource.org/licenses/MIT",
            "Apache-2.0": "https://opensource.org/licenses/Apache-2.0",
            "GPL-3.0": "https://opensource.org/licenses/GPL-3.0",
            "BSD-3-Clause": "https://opensource.org/licenses/BSD-3-Clause"
        ]
        return licenseMap[licenseName] ?: "https://opensource.org/licenses"
    }
    
    private boolean isBundled(plugin, jenkins) {
        try {
            def pluginWrapper = jenkins.pluginManager.getPlugin(plugin.shortName)
            return pluginWrapper?.isBundled() ?: false
        } catch (Exception e) {
            return false
        }
    }
    
    private boolean isPinned(plugin, jenkins) {
        try {
            def pluginWrapper = jenkins.pluginManager.getPlugin(plugin.shortName)
            return pluginWrapper?.isPinned() ?: false
        } catch (Exception e) {
            return false
        }
    }
    
    private def generateDependencies(List plugins) {
        return plugins.collect { plugin ->
            [
                ref: "pkg:jenkins/plugin/${plugin.shortName}@${plugin.version}",
                dependsOn: plugin.dependencies.collect { dep ->
                    "pkg:jenkins/plugin/${dep.shortName}@${dep.version}"
                }
            ]
        }
    }
    
    private def generateVulnerabilities(List vulnerabilities) {
        return vulnerabilities.collect { vuln ->
            [
                id: vuln.cve,
                source: [
                    name: "Jenkins Update Center",
                    url: vuln.url ?: "https://www.jenkins.io/security/advisories/"
                ],
                ratings: [
                    [
                        severity: vuln.severity,
                        score: vuln.cvss,
                        method: "CVSSv3"
                    ]
                ],
                description: vuln.description,
                recommendation: getRecommendation(vuln.severity),
                affects: [
                    [
                        ref: "pkg:jenkins/plugin/${vuln.plugin}@${vuln.version}",
                        versions: [
                            [
                                version: vuln.version,
                                status: "affected"
                            ]
                        ]
                    ]
                ]
            ]
        }
    }
    
    private String getRecommendation(String severity) {
        switch(severity) {
            case 'CRITICAL':
                return "Update immediately. Disable plugin if update is not available."
            case 'HIGH':
                return "Update within 24-48 hours."
            case 'MEDIUM':
                return "Update in next maintenance window."
            case 'LOW':
                return "Update when convenient."
            default:
                return "Follow security best practices."
        }
    }
}
