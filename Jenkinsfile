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
                    withCredentials([string(credentialsId: 'dependency-track-api-key', variable: 'DT_API_KEY')]) {
                        if (fileExists('sbom.json')) {
                            echo "📤 Uploading SBOM to Dependency-Track..."

                            // Debug: Test basic curl first
                            echo "=== Debug: Testing curl to Dependency-Track ==="
                            sh '''
                                echo "Test 1: Basic curl to version endpoint"
                                curl http://localhost:8081/api/version || true

                                echo ""
                                echo "Test 2: Check if curl can resolve localhost"
                                ping -c 1 localhost || true

                                echo ""
                                echo "Test 3: Check network connectivity"
                                netstat -an | grep 8081 || true

                                echo ""
                                echo "Test 4: Current user"
                                whoami

                                echo ""
                                echo "Test 5: Working directory"
                                pwd
                                ls -la
                            '''

                            def sbomContent = readFile('sbom.json')
                            def sbomBase64 = sbomContent.bytes.encodeBase64().toString()

                            echo "SBOM file size: ${sbomContent.length()} bytes"
                            echo "Base64 size: ${sbomBase64.length()} characters"

                            def payload = groovy.json.JsonOutput.toJson([
                                projectName: 'Jenkins-Plugins',
                                projectVersion: env.BUILD_NUMBER ?: '1.0.0',
                                autoCreate: true,
                                bom: sbomBase64
                            ])

                            writeFile file: 'dt-payload.json', text: payload

                            echo "Payload file created, size: ${payload.length()} bytes"

                            // Verify files exist
                            sh '''
                                echo "=== Verifying files ==="
                                ls -lh dt-payload.json
                                echo "API Key length: ${#DT_API_KEY}"
                            '''

                            echo "=== Attempting upload ==="
                            sh '''
                                set -x  # Enable command echoing for debugging

                                curl -X PUT "http://localhost:8081/api/v1/bom" \
                                -H "Content-Type: application/json" \
                                -H "X-Api-Key: ${DT_API_KEY}" \
                                --data @dt-payload.json \
                                -w "\\nHTTP_STATUS:%{http_code}\\n" \
                                -v \
                                2>&1 | tee curl-output.log

                                CURL_EXIT=$?
                                echo "Curl exit code: ${CURL_EXIT}"

                                if [ ${CURL_EXIT} -ne 0 ]; then
                                    echo "❌ Curl failed with exit code ${CURL_EXIT}"
                                    echo "Exit code 7 = Failed to connect to host"
                                    echo "Exit code 6 = Couldn't resolve host"
                                    echo "Exit code 28 = Timeout"
                                fi
                            '''

                            echo "✅ Upload stage complete"
                            echo "View results at: http://localhost:8081/projects"

                            sh 'rm -f dt-payload.json || true'
                        } else {
                            echo "⚠️  sbom.json not found in workspace"
                            sh 'ls -la'
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
