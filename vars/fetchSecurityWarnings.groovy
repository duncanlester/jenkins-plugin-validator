#!/usr/bin/env groovy

def call() {
    echo "Fetching security warnings from Jenkins..."
    
    try {
        def warningsUrl = 'https://www.jenkins.io/security/plugins/warnings.json'
        echo "Downloading from: ${warningsUrl}"
        
        def warnings = fetchUrl(warningsUrl)
        
        echo "Downloaded ${warnings.length()} bytes"
        
        writeFile file: 'security-warnings.json', text: warnings
        archiveArtifacts artifacts: 'security-warnings.json'
        
        try {
            def warningsList = readJSON text: warnings
            echo "Parsed ${warningsList.size()} security warnings"
            
            echo "Sample warnings for plugins:"
            warningsList.take(5).each { w ->
                echo "  - ${w.name}"
            }
            
            def buildPipelineWarnings = warningsList.findAll { 
                it.name == 'build-pipeline-plugin' || 
                it.name == 'build-pipeline' 
            }
            if (buildPipelineWarnings) {
                echo "Found ${buildPipelineWarnings.size()} warnings for build-pipeline-plugin"
                buildPipelineWarnings.each { w ->
                    echo "  Name: ${w.name}"
                    echo "  Message: ${w.message}"
                    echo "  URL: ${w.url}"
                    if (w.versions) {
                        echo "  Versions: ${w.versions.size()} version ranges"
                    }
                }
            } else {
                echo "No warnings found for build-pipeline-plugin"
            }
            
        } catch (Exception e) {
            echo "Could not parse warnings: ${e.message}"
        }
        
        env.SECURITY_WARNINGS = warnings
        echo "Security warnings fetched and saved"
        
    } catch (Exception e) {
        echo "Could not fetch security warnings: ${e.message}"
        echo "Stack trace: ${e}"
        env.SECURITY_WARNINGS = '[]'
    }
}

@NonCPS
def fetchUrl(String url) {
    return new URL(url).text
}
