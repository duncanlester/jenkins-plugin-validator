package org.jenkins.plugins.validator

import java.security.MessageDigest
import jenkins.model.Jenkins

class SPDXGenerator implements Serializable {
    
    private boolean enhanced = true
    
    void setEnhanced(boolean enhanced) {
        this.enhanced = enhanced
    }
    
    String generate(List plugins, List vulnerabilities) {
        def timestamp = new Date().format("yyyy-MM-dd'T'HH:mm:ss'Z'")
        def jenkins = Jenkins.instance
        
        return groovy.json.JsonOutput.toJson([
            spdxVersion: "SPDX-2.3",
            dataLicense: "CC0-1.0",
            SPDXID: "SPDXRef-DOCUMENT",
            name: "Jenkins Plugin SBOM",
            documentNamespace: "https://jenkins.io/sbom/${UUID.randomUUID()}",
            creationInfo: [
                created: timestamp,
                creators: [
                    "Tool: Jenkins Plugin Validator-1.0.0",
                    "Organization: duncanlester"
                ],
                licenseListVersion: "3.21"
            ],
            packages: generatePackages(jenkins, plugins),
            relationships: generateRelationships(plugins)
        ])
    }
    
    private def generatePackages(jenkins, List plugins) {
        def packages = [
            [
                SPDXID: "SPDXRef-Jenkins",
                name: "Jenkins",
                versionInfo: jenkins.version,
                downloadLocation: "https://www.jenkins.io/",
                filesAnalyzed: false,
                licenseConcluded: "MIT",
                copyrightText: "NOASSERTION"
            ]
        ]
        
        packages.addAll(plugins.collect { plugin ->
            def pkg = [
                SPDXID: "SPDXRef-Package-${plugin.shortName}",
                name: plugin.shortName,
                versionInfo: plugin.version,
                downloadLocation: plugin.url ?: "https://updates.jenkins.io/download/plugins/${plugin.shortName}/${plugin.version}/${plugin.shortName}.hpi",
                filesAnalyzed: enhanced,
                licenseConcluded: "NOASSERTION",
                licenseDeclared: "NOASSERTION",
                copyrightText: "NOASSERTION",
                externalRefs: [
                    [
                        referenceCategory: "PACKAGE-MANAGER",
                        referenceType: "purl",
                        referenceLocator: "pkg:jenkins/plugin/${plugin.shortName}@${plugin.version}"
                    ]
                ]
            ]
            
            // Add enhanced checksums if enabled
            if (enhanced) {
                def checksums = getPluginChecksums(plugin, jenkins)
                if (checksums) {
                    pkg.checksums = checksums
                }
                
                // Add source info
                pkg.sourceInfo = "https://github.com/jenkinsci/${plugin.shortName}-plugin"
                
                // Add homepage
                pkg.homepage = "https://plugins.jenkins.io/${plugin.shortName}"
            }
            
            return pkg
        })
        
        return packages
    }
    
    private def getPluginChecksums(plugin, jenkins) {
        try {
            def pluginDir = jenkins.pluginManager.rootDir
            def pluginFile = new File(pluginDir, "${plugin.shortName}.jpi")
            
            if (!pluginFile.exists()) {
                pluginFile = new File(pluginDir, "${plugin.shortName}.hpi")
            }
            
            if (pluginFile.exists() && pluginFile.canRead()) {
                return [
                    [
                        algorithm: "SHA256",
                        checksumValue: calculateSHA256(pluginFile)
                    ],
                    [
                        algorithm: "SHA1",
                        checksumValue: calculateSHA1(pluginFile)
                    ]
                ]
            }
        } catch (Exception e) {
            // Silently fail
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
    
    private String calculateSHA1(File file) {
        def digest = MessageDigest.getInstance("SHA-1")
        file.withInputStream { is ->
            byte[] buffer = new byte[8192]
            int read
            while ((read = is.read(buffer)) != -1) {
                digest.update(buffer, 0, read)
            }
        }
        return digest.digest().encodeHex().toString()
    }
    
    private def generateRelationships(List plugins) {
        def relationships = [
            [
                spdxElementId: "SPDXRef-DOCUMENT",
                relationshipType: "DESCRIBES",
                relatedSpdxElement: "SPDXRef-Jenkins"
            ]
        ]
        
        relationships.addAll(plugins.collect { plugin ->
            [
                spdxElementId: "SPDXRef-Jenkins",
                relationshipType: "DEPENDS_ON",
                relatedSpdxElement: "SPDXRef-Package-${plugin.shortName}"
            ]
        })
        
        relationships.addAll(plugins.collectMany { plugin ->
            plugin.dependencies.collect { dep ->
                [
                    spdxElementId: "SPDXRef-Package-${plugin.shortName}",
                    relationshipType: "DEPENDS_ON",
                    relatedSpdxElement: "SPDXRef-Package-${dep.shortName}"
                ]
            }
        })
        
        return relationships
    }
}
