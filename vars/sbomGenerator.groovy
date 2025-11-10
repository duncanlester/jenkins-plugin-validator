#!/usr/bin/env groovy

import org.jenkins.plugins.validator.CycloneDXGenerator
import org.jenkins.plugins.validator.SPDXGenerator

def generateSBOM(boolean enhanced = true) {
    echo "📋 Generating Software Bill of Materials (SBOM)..."
    echo "🔧 Enhanced mode: ${enhanced}"
    
    def pluginData = readJSON text: env.PLUGIN_DATA
    def vulnData = readJSON text: env.VULNERABILITIES
    
    // Generate CycloneDX SBOM
    def cycloneDX = new CycloneDXGenerator()
    cycloneDX.setEnhanced(enhanced)
    def cycloneDxSbom = cycloneDX.generate(pluginData, vulnData)
    writeFile file: 'sbom-cyclonedx.json', text: groovy.json.JsonOutput.prettyPrint(cycloneDxSbom)
    
    // Generate SPDX SBOM
    def spdx = new SPDXGenerator()
    spdx.setEnhanced(enhanced)
    def spdxSbom = spdx.generate(pluginData, vulnData)
    writeFile file: 'sbom-spdx.json', text: groovy.json.JsonOutput.prettyPrint(spdxSbom)
    
    archiveArtifacts artifacts: 'sbom-*.json'
    
    env.SBOM_GENERATED = 'true'
    env.SBOM_ENHANCED = enhanced.toString()
    
    if (enhanced) {
        echo "✅ Enhanced SBOM generated with:"
        echo "   • SHA-256 file hashes"
        echo "   • License detection"
        echo "   • Extended metadata"
        echo "   • External references"
        echo "   • Security scores"
    } else {
        echo "✅ Basic SBOM generated in CycloneDX and SPDX formats"
    }
}
