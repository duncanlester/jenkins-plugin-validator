package org.jenkins.plugins.validator

import java.security.MessageDigest
import java.text.SimpleDateFormat

class CycloneDXGenerator implements Serializable {
    private static final long serialVersionUID = 1L
    
    private boolean enhanced = true
    
    void setEnhanced(boolean enhanced) {
        this.enhanced = enhanced
    }
    
    String generate(List plugins, List vulnerabilities) {
        def sdf = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'")
        sdf.setTimeZone(TimeZone.getTimeZone('UTC'))
        def timestamp = sdf.format(new Date())
        
        def jenkinsVersion = Jenkins.instance.version.toString()
        
        def sbom = [
            bomFormat: "CycloneDX",
            specVersion: "1.5",
            serialNumber: "urn:uuid:${UUID.randomUUID()}",
            version: 1,
            metadata: generateMetadata(timestamp, jenkinsVersion),
            components: generateComponents(plugins),
            dependencies: generateDependencies(plugins),
            vulnerabilities: generateVulnerabilities(vulnerabilities)
        ]
        
        return groovy.json.JsonOutput.toJson(sbom)
    }
    
    private Map generateMetadata(String timestamp, String jenkinsVersion) {
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
    
    private List generateComponents(List plugins) {
        return plugins.collect { plugin ->
            def component = [
                type: "library",
                "bom-ref": "pkg:jenkins/plugin/${plugin.shortName}@${plugin.version}",
                name: plugin.shortName,
                version: plugin.version.toString(),
                description: plugin.longName,
                purl: "pkg:jenkins/plugin/${plugin.shortName}@${plugin.version}"
            ]
            
            if (enhanced) {
                component.properties = [
                    [name: "jenkins:enabled", value: plugin.enabled.toString()],
                    [name: "jenkins:active", value: plugin.active.toString()],
                    [name: "jenkins:hasUpdate", value: plugin.hasUpdate.toString()],
                    [name: "sbom:enhanced", value: "true"]
                ]
                
                component.externalReferences = [
                    [
                        type: "website",
                        url: "https://plugins.jenkins.io/${plugin.shortName}"
                    ],
                    [
                        type: "vcs",
                        url: "https://github.com/jenkinsci/${plugin.shortName}-plugin"
                    ]
                ]
            } else {
                component.properties = [
                    [name: "jenkins:enabled", value: plugin.enabled.toString()]
                ]
            }
            
            return component
        }
    }
    
    private List generateDependencies(List plugins) {
        return plugins.collect { plugin ->
            [
                ref: "pkg:jenkins/plugin/${plugin.shortName}@${plugin.version}",
                dependsOn: plugin.dependencies.collect { dep ->
                    "pkg:jenkins/plugin/${dep.shortName}@${dep.version}"
                }
            ]
        }
    }
    
    private List generateVulnerabilities(List vulnerabilities) {
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
                description: vuln.description ?: "Security vulnerability in ${vuln.plugin}",
                affects: [
                    [
                        ref: "pkg:jenkins/plugin/${vuln.plugin}@${vuln.version}",
                        versions: [
                            [
                                version: vuln.version.toString(),
                                status: "affected"
                            ]
                        ]
                    ]
                ]
            ]
        }
    }
}
