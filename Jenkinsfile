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
                        def dtUrl = 'http://localhost:8081'
                        def apiKey = env.DEPENDENCY_TRACK_API_KEY

                        if (fileExists('sbom.json')) {
                            echo "📤 Uploading SBOM to Dependency-Track..."

                            def sbomContent = readFile('sbom.json')
                            def sbomBase64 = sbomContent.bytes.encodeBase64().toString()

                            def payload = groovy.json.JsonOutput.toJson([
                                projectName: 'Jenkins-Plugins',
                                projectVersion: env.BUILD_NUMBER,
                                autoCreate: true,
                                bom: sbomBase64
                            ])

                            writeFile file: 'dt-payload.json', text: payload

                            def response = sh(
                                script: """
                                    curl -X PUT '${dtUrl}/api/v1/bom' \\
                                    -H 'Content-Type: application/json' \\
                                    -H 'X-Api-Key: ${apiKey}' \\
                                    --data @dt-payload.json \\
                                    -w '%{http_code}' \\
                                    -o dt-response.json \\
                                    -s
                                """,
                                returnStdout: true
                            ).trim()

                            echo "HTTP Status: ${response}"

                            if (response == '200' || response == '201') {
                                echo "✅ SBOM uploaded successfully to Dependency-Track"
                                echo "   View at: ${dtUrl}/projects"
                            } else {
                                echo "⚠️  Upload failed with status ${response}"
                                def responseContent = readFile('dt-response.json')
                                echo "Response: ${responseContent}"
                            }

                            sh 'rm -f dt-payload.json dt-response.json'
                        } else {
                            echo "⚠️  sbom.json not found - skipping upload"
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
