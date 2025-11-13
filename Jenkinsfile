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

                            echo "SBOM file size: ${sbomContent.length()} bytes"

                            def payload = groovy.json.JsonOutput.toJson([
                                projectName: 'Jenkins-Plugins',
                                projectVersion: env.BUILD_NUMBER ?: '1.0.0',
                                autoCreate: true,
                                bom: sbomBase64
                            ])

                            writeFile file: 'dt-payload.json', text: payload

                            echo "=== Testing Dependency-Track connectivity ==="
                            sh '''
                                # Try different URLs to find working connection
                                URLS="http://localhost:8081 http://host.docker.internal:8081 http://dependency-track:8080"
                                WORKING_URL=""

                                for URL in $URLS; do
                                    echo "Testing: $URL/api/version"
                                    if curl -s -f -m 5 "$URL/api/version" > /dev/null 2>&1; then
                                        echo "✅ SUCCESS: $URL is reachable"
                                        WORKING_URL="$URL"
                                        break
                                    else
                                        echo "❌ FAILED: $URL not reachable"
                                    fi
                                done

                                if [ -z "$WORKING_URL" ]; then
                                    echo "❌ Could not connect to Dependency-Track on any URL"
                                    echo "Tried: $URLS"
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
                                    echo "✅ SBOM uploaded successfully to Dependency-Track"
                                    echo "   Using URL: $WORKING_URL"
                                    echo "   View at: http://localhost:8081/projects (or host machine)"
                                else
                                    echo "⚠️ Upload returned status ${HTTP_CODE}"
                                    if [ -f dt-response.json ]; then
                                        echo "Response:"
                                        cat dt-response.json
                                    fi
                                    exit 1
                                fi
                            '''

                            sh 'rm -f dt-payload.json dt-response.json curl-output.log || true'
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
