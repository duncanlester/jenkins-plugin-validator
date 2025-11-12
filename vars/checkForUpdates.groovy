#!/usr/bin/env groovy

def call() {
    echo "🔄 Checking for plugin updates..."
    
    def plugins = readJSON text: env.PLUGIN_DATA
    def outdated = []
    
    plugins.each { p ->
        if (p.hasUpdate) {
            outdated << p
        }
    }
    
    echo "📦 Found ${outdated.size()} plugins with updates available"
    env.OUTDATED_PLUGINS = groovy.json.JsonOutput.toJson(outdated)
    env.OUTDATED_COUNT = outdated.size().toString()
    
    return outdated
}
