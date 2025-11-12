#!/usr/bin/env groovy

def call() {
    echo "Fetching installed plugins from Jenkins..."
    
    def pluginList = getPluginList()
    
    echo "Found ${pluginList.size()} installed plugins"
    
    def buildPipeline = pluginList.find { 
        it.shortName == 'build-pipeline-plugin' || 
        it.shortName == 'build-pipeline' 
    }
    
    if (buildPipeline) {
        echo "Build Pipeline Plugin found:"
        echo "  Short Name: ${buildPipeline.shortName}"
        echo "  Version: ${buildPipeline.version}"
        echo "  Enabled: ${buildPipeline.enabled}"
        echo "  Has Update: ${buildPipeline.hasUpdate}"
    } else {
        echo "Build Pipeline Plugin not found - checking all plugin names containing 'pipeline':"
        pluginList.findAll { it.shortName.contains('pipeline') }.each { p ->
            echo "  - ${p.shortName} (${p.version})"
        }
    }
    
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
