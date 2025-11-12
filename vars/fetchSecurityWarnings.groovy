#!/usr/bin/env groovy

def call() {
    echo "🔒 Fetching security warnings..."
    
    try {
        def warningsUrl = 'https://www.jenkins.io/security/plugins/warnings.json'
        def warnings = fetchUrl(warningsUrl)
        writeFile file: 'security-warnings.json', text: warnings
        env.SECURITY_WARNINGS = warnings
        echo "✅ Security warnings fetched"
    } catch (Exception e) {
        echo "⚠️ Could not fetch security warnings: ${e.message}"
        env.SECURITY_WARNINGS = '[]'
    }
}

@NonCPS
def fetchUrl(String url) {
    return new URL(url).text
}
