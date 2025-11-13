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
                    fetchInstalledPlugins()
                    fetchSecurityWarnings()
                }
            }
        }

        stage('Check for Updates') {
            steps {
                script {
                    checkForUpdates()
                }
            }
        }

        stage('Scan Vulnerabilities') {
            steps {
                script {
                    scanVulnerabilities()
                }
            }
        }

        stage('Calculate Risk Score') {
            steps {
                script {
                    calculateRiskScore()
                }
            }
        }

        stage('Generate SBOM') {
            steps {
                script {
                    generateSBOM()
                }
            }
        }

        stage('Generate Reports') {
            steps {
                script {
                    generateReports()
                }
            }
        }

        stage('Upload SBOM to Dependency-Track') {
            steps {
                script {
                    withCredentials([string(credentialsId: 'dependency-track-api-key', variable: 'DEPENDENCY_TRACK_API_KEY')]) {

                        // Change this based on your setup
                        def dtUrl = env.JENKINS_IN_DOCKER ? 'http://host.docker.internal:8081' : 'http://localhost:8081'

                        try {
                            if (fileExists('sbom.json')) {
                                echo "📤 Uploading SBOM to Dependency-Track..."
                                echo "Using URL: ${dtUrl}"

                                // Rest of the code, but replace http://localhost:8081 with ${dtUrl}
                                def pingResult = sh(
                                    script: "curl -s -o /dev/null -w '%{http_code}' ${dtUrl}/api/version 2>&1 || echo 'CONNECTION_FAILED'",
                                    returnStdout: true
                                ).trim()

                                // ... rest of code
                            }
                        } catch (Exception e) {
                            echo "❌ Error: ${e.message}"
                            currentBuild.result = 'UNSTABLE'
                        } finally {
                            sh 'rm -f dt-payload.json dt-response.json .dt-api-key || true'
                        }
                    }
                }
            }
        }

        stage('Send Notifications') {
            steps {
                script {
                    sendSuccessNotification()
                    sendSecurityAlert()
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
