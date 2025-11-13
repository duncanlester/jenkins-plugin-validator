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

                            def sbomContent = readFile('sbom.json')
                            def sbomBase64 = sbomContent.bytes.encodeBase64().toString()

                            def payload = groovy.json.JsonOutput.toJson([
                                projectName: 'Jenkins-Plugins',
                                projectVersion: env.BUILD_NUMBER ?: '1.0.0',
                                autoCreate: true,
                                bom: sbomBase64
                            ])

                            writeFile file: 'dt-payload.json', text: payload

                            sh '''
                                # FIXED: Use port 8080 for container name, 8081 for host
                                URLS="http://dtrack-apiserver:8080 http://host.docker.internal:8081 http://localhost:8081"
                                WORKING_URL=""

                                echo "=== Testing Dependency-Track connectivity ==="

                                for URL in $URLS; do
                                    echo "Testing: $URL"
                                    if curl -s -f -m 5 "$URL/api/version" > /dev/null 2>&1; then
                                        WORKING_URL="$URL"
                                        echo "✅ SUCCESS: Connected to $URL"
                                        break
                                    else
                                        echo "❌ FAILED: Could not connect to $URL"
                                    fi
                                done

                                if [ -z "$WORKING_URL" ]; then
                                    echo "❌ Cannot connect to Dependency-Track on any URL"
                                    echo ""
                                    echo "Debug info:"
                                    echo "Networks:"
                                    ip addr show 2>/dev/null || echo "Cannot show network info"
                                    exit 1
                                fi

                                echo ""
                                echo "=== Uploading SBOM to $WORKING_URL ==="

                                HTTP_CODE=$(curl -X PUT "$WORKING_URL/api/v1/bom" \
                                -H "Content-Type: application/json" \
                                -H "X-Api-Key: ${DT_API_KEY}" \
                                --data @dt-payload.json \
                                -w "%{http_code}" \
                                -o dt-response.json \
                                -s \
                                -m 30)

                                echo "HTTP Status: ${HTTP_CODE}"

                                if [ "${HTTP_CODE}" = "200" ] || [ "${HTTP_CODE}" = "201" ]; then
                                    echo "✅ SBOM uploaded successfully"
                                    echo "   View at: http://localhost:8082/projects"
                                else
                                    echo "⚠️ Upload failed with status ${HTTP_CODE}"
                                    cat dt-response.json
                                    exit 1
                                fi
                            '''

                            sh 'rm -f dt-payload.json dt-response.json || true'
                        } else {
                            echo "⚠️  sbom.json not found"
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
