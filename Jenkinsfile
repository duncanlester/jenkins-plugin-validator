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

                        try {
                            if (fileExists('sbom.json')) {
                                echo "📤 Uploading SBOM to Dependency-Track..."

                                // Simple connectivity test
                                sh 'curl -f http://localhost:8081/api/version'
                                echo "✅ Dependency-Track is reachable"

                                def sbomContent = readFile('sbom.json')
                                def sbomBase64 = sbomContent.bytes.encodeBase64().toString()

                                echo "SBOM size: ${sbomContent.length()} bytes"

                                def payload = groovy.json.JsonOutput.toJson([
                                    projectName: 'Jenkins-Plugins',
                                    projectVersion: env.BUILD_NUMBER ?: '1.0.0',
                                    autoCreate: true,
                                    bom: sbomBase64
                                ])

                                writeFile file: 'dt-payload.json', text: payload
                                writeFile file: '.dt-api-key', text: env.DEPENDENCY_TRACK_API_KEY

                                echo "Uploading SBOM..."

                                // Simplified curl command
                                sh '''
                                    HTTP_CODE=$(curl -X PUT "http://localhost:8081/api/v1/bom" \
                                    -H "Content-Type: application/json" \
                                    -H "X-Api-Key: $(cat .dt-api-key)" \
                                    --data @dt-payload.json \
                                    -w "%{http_code}" \
                                    -o dt-response.json \
                                    -s)

                                    echo "HTTP Status: ${HTTP_CODE}"

                                    if [ "${HTTP_CODE}" = "200" ] || [ "${HTTP_CODE}" = "201" ]; then
                                        echo "✅ SBOM uploaded successfully"
                                    else
                                        echo "⚠️  Upload returned status ${HTTP_CODE}"
                                        cat dt-response.json
                                    fi
                                '''

                                echo "View results at: http://localhost:8081/projects"

                            } else {
                                echo "⚠️  sbom.json not found in workspace"
                                sh 'ls -la'
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
