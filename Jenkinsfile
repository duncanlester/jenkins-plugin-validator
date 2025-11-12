@Library('plugin-validator') _

pipeline {
    agent any
    
    options {
        buildDiscarder(logRotator(numToKeepStr: '30'))
        timestamps()
        timeout(time: 30, unit: 'MINUTES')
    }
    
    stages {
        stage('Scan Plugins') {
            steps {
                script {
                    pluginScanner.fetchInstalledPlugins()
                    pluginScanner.fetchSecurityWarnings()
                }
            }
        }
        
        stage('Check for Updates') {
            steps {
                script {
                    pluginScanner.checkForUpdates()
                }
            }
        }
        
        stage('Scan Vulnerabilities') {
            steps {
                script {
                    pluginScanner.scanVulnerabilities()
                }
            }
        }
        
        stage('Calculate Risk Score') {
            steps {
                script {
                    riskCalculator.calculateRiskScore()
                }
            }
        }
        
        stage('Generate SBOM') {
            steps {
                script {
                    sbomGenerator.generateSBOM()
                }
            }
        }
        
        stage('Generate Reports') {
            steps {
                script {
                    reportGenerator.generateReports()
                }
            }
        }
        
        stage('Send Notifications') {
            steps {
                script {
                    reportGenerator.sendSuccessNotification()
                    reportGenerator.sendSecurityAlert()
                }
            }
        }
    }
    
    post {
        always {
            echo "🏁 Plugin validation complete"
            echo "📊 Build Status: ${currentBuild.result ?: 'SUCCESS'}"
        }
        unstable {
            echo "⚠️  UNSTABLE: Security vulnerabilities detected - review required"
        }
        success {
            echo "✅ SUCCESS: All plugins validated, no security issues"
        }
    }
}
