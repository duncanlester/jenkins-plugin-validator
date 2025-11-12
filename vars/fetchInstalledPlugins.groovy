#!/usr/bin/env groovy

def call() {
    echo "🔍 Fetching installed plugins..."
    
    def pluginList = getPluginList()
    
    echo "📊 Found ${pluginList.size()} installed plugins"
    
    def pluginJson = groovy.json.JsonOutput.toJson(pluginList)
    writeFile file: 'plugins.json', text: pluginJson
    env.PLUGIN_DATA = pluginJson
    
    return pluginList
}

@NonCPS
def getPluginList() {
    def jenkins = Jenkins.instance
    def pluginManager = jenkins.pluginManager
    def plugins = pluginManager.plugins
    
    def pluginList = []
    
    plugins.each { plugin ->
        def pluginInfo = [
            shortName: plugin.shortName,
            longName: plugin.longName ?: plugin.shortName,
            version: plugin.version,
            enabled: plugin.enabled,
            active: plugin.active,
            bundled: plugin.bundled,
            url: plugin.url ?: '',
            hasUpdate: plugin.hasUpdate(),
            pinned: plugin.pinned,
            jenkinsVersion: plugin.requiredCoreVersion ?: '',
            dependencies: plugin.dependencies.collect { it.shortName },
            dependencyCount: plugin.dependencies.size(),
            developerNames: plugin.manifest?.mainAttributes?.getValue('Plugin-Developers') ?: 'Unknown'
        ]
        pluginList << pluginInfo
    }
    
    return pluginList
}
