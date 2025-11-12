#!/usr/bin/env groovy

def call() {
    echo "📈 Calculating risk score..."
    
    def vulnCount = env.VULN_COUNT?.toInteger() ?: 0
    def outdatedCount = env.OUTDATED_COUNT?.toInteger() ?: 0
    def plugins = readJSON text: env.PLUGIN_DATA
    def totalPlugins = plugins.size()
    
    def totalScore = computeRiskScore(vulnCount, outdatedCount, totalPlugins)
    
    env.RISK_SCORE = totalScore.toString()
    
    echo "📊 Risk Score: ${totalScore}/100"
    
    return totalScore
}

@NonCPS
def computeRiskScore(int vulnCount, int outdatedCount, int totalPlugins) {
    def vulnScore = Math.min(vulnCount * 15, 60)
    def outdatedScore = Math.min((outdatedCount / totalPlugins) * 100 * 0.3, 30)
    def baselineScore = 10
    
    def totalScore = (vulnScore + outdatedScore + baselineScore).toInteger()
    
    return totalScore
}
