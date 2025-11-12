#!/usr/bin/env groovy

def generateReports() {
    echo "📝 Generating validation reports..."
    
    // DEBUG - check what we actually have
    echo "DEBUG: env.PLUGIN_DATA length: ${env.PLUGIN_DATA?.length() ?: 0}"
    echo "DEBUG: env.VULN_COUNT: ${env.VULN_COUNT}"
    echo "DEBUG: env.OUTDATED_COUNT: ${env.OUTDATED_COUNT}"
    echo "DEBUG: env.RISK_SCORE: ${env.RISK_SCORE}"
    
    // Read from files instead since env vars might be too big
    def pluginJson = readFile(file: 'plugins.json')
    def vulnJson = env.VULNERABILITIES ?: '[]'
    def outdatedJson = env.OUTDATED_PLUGINS ?: '[]'
    
    echo "DEBUG: pluginJson length: ${pluginJson.length()}"
    
    def timestamp = new Date().format('yyyy-MM-dd HH:mm:ss', TimeZone.getTimeZone('UTC'))
    def jenkinsVersion = Jenkins.instance.version.toString()
    def currentUser = getCurrentUser()
    
    // Count plugins from actual JSON
    def plugins = readJSON text: pluginJson
    def pluginCount = plugins.size()
    
    echo "📊 Generating report for ${pluginCount} plugins"
    
    def html = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Jenkins Plugin Validation Report</title>
    <style>
        :root {
            --primary: #335eea;
            --primary-dark: #2948c8;
            --success: #00c48c;
            --warning: #ffa726;
            --danger: #f44336;
            --critical: #c62828;
            --bg: #f8f9fc;
            --card-bg: #ffffff;
            --text: #1e2130;
            --text-muted: #6c757d;
            --border: #e1e4e8;
            --shadow: 0 2px 12px rgba(0,0,0,0.08);
            --shadow-lg: 0 8px 24px rgba(0,0,0,0.12);
        }
        
        * { margin: 0; padding: 0; box-sizing: border-box; }
        
        body { 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Helvetica Neue', Arial, sans-serif;
            background: var(--bg);
            color: var(--text);
            line-height: 1.6;
            padding: 30px 20px;
        }
        
        .container { 
            max-width: 1600px; 
            margin: 0 auto; 
        }
        
        .header { 
            background: linear-gradient(135deg, var(--primary) 0%, var(--primary-dark) 100%);
            color: white;
            padding: 50px 40px;
            border-radius: 16px;
            margin-bottom: 40px;
            box-shadow: var(--shadow-lg);
        }
        
        .header h1 { 
            font-size: 42px;
            font-weight: 700;
            margin-bottom: 16px;
            letter-spacing: -0.5px;
        }
        
        .header-meta {
            display: flex;
            gap: 30px;
            font-size: 15px;
            opacity: 0.95;
        }
        
        .header-meta strong { 
            font-weight: 600;
            opacity: 1;
        }
        
        .stats { 
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 24px;
            margin-bottom: 40px;
        }
        
        .stat-card { 
            background: var(--card-bg);
            padding: 32px;
            border-radius: 12px;
            box-shadow: var(--shadow);
            border: 1px solid var(--border);
            transition: transform 0.2s, box-shadow 0.2s;
        }
        
        .stat-card:hover {
            transform: translateY(-4px);
            box-shadow: var(--shadow-lg);
        }
        
        .stat-card h3 { 
            color: var(--text-muted);
            font-size: 12px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-bottom: 12px;
        }
        
        .stat-card .value { 
            font-size: 48px;
            font-weight: 700;
            color: var(--primary);
            line-height: 1;
        }
        
        .section { 
            background: var(--card-bg);
            padding: 36px;
            border-radius: 12px;
            margin-bottom: 32px;
            box-shadow: var(--shadow);
            border: 1px solid var(--border);
        }
        
        .section h2 { 
            font-size: 28px;
            font-weight: 700;
            margin-bottom: 24px;
            color: var(--text);
            padding-bottom: 16px;
            border-bottom: 3px solid var(--primary);
        }
        
        table { 
            width: 100%;
            border-collapse: separate;
            border-spacing: 0;
            font-size: 13px;
            border: 1px solid var(--border);
            border-radius: 8px;
            overflow: hidden;
        }
        
        thead { 
            background: linear-gradient(180deg, #f8f9fc 0%, #f1f3f9 100%);
        }
        
        th { 
            padding: 16px 14px;
            text-align: left;
            font-weight: 700;
            font-size: 11px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            color: var(--text);
            border-bottom: 2px solid var(--border);
            border-right: 1px solid var(--border);
        }
        
        th:last-child { border-right: none; }
        
        td { 
            padding: 14px;
            border-bottom: 1px solid var(--border);
            border-right: 1px solid var(--border);
            vertical-align: middle;
        }
        
        td:last-child { border-right: none; }
        
        tbody tr { 
            background: white;
            transition: background-color 0.15s;
        }
        
        tbody tr:hover { 
            background: #f8f9fc;
        }
        
        tbody tr:last-child td { 
            border-bottom: none;
        }
        
        .badge { 
            display: inline-block;
            padding: 6px 12px;
            border-radius: 6px;
            font-size: 10px;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.3px;
        }
        
        .badge-critical { background: var(--critical); color: white; }
        .badge-high { background: var(--danger); color: white; }
        .badge-medium { background: var(--warning); color: white; }
        .badge-low { background: #90caf9; color: #0d47a1; }
        .badge-enabled { background: var(--success); color: white; }
        .badge-disabled { background: var(--text-muted); color: white; }
        
        .pagination { 
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-top: 28px;
            padding-top: 24px;
            border-top: 2px solid var(--border);
        }
        
        .pagination-info {
            font-size: 14px;
            color: var(--text-muted);
            font-weight: 500;
        }
        
        .pagination-buttons {
            display: flex;
            gap: 12px;
        }
        
        .pagination button { 
            padding: 12px 24px;
            border: 2px solid var(--primary);
            background: white;
            color: var(--primary);
            border-radius: 8px;
            cursor: pointer;
            font-weight: 600;
            font-size: 13px;
            transition: all 0.2s;
        }
        
        .pagination button:hover:not(:disabled) { 
            background: var(--primary);
            color: white;
            transform: translateY(-2px);
            box-shadow: var(--shadow);
        }
        
        .pagination button:disabled { 
            opacity: 0.3;
            cursor: not-allowed;
            border-color: var(--border);
            color: var(--text-muted);
        }
        
        code { 
            background: #f4f5f7;
            padding: 4px 8px;
            border-radius: 4px;
            font-family: 'SF Mono', 'Monaco', 'Courier New', monospace;
            font-size: 12px;
            color: #e83e8c;
            border: 1px solid #e1e4e8;
        }
        
        strong { font-weight: 600; }
        
        .debug { 
            background: #fff3cd; 
            padding: 20px; 
            margin: 20px 0; 
            border-radius: 8px; 
            border: 2px solid #ffc107;
            font-family: monospace;
            font-size: 12px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔒 Jenkins Plugin Validation Report</h1>
            <div class="header-meta">
                <div><strong>Generated:</strong> ${timestamp} UTC</div>
                <div><strong>Jenkins:</strong> ${jenkinsVersion}</div>
                <div><strong>User:</strong> ${currentUser}</div>
            </div>
        </div>
        
        <div class="stats">
            <div class="stat-card">
                <h3>Total Plugins</h3>
                <div class="value" id="totalCount">${pluginCount}</div>
            </div>
            <div class="stat-card">
                <h3>Vulnerabilities</h3>
                <div class="value" style="color: ${env.VULN_COUNT?.toInteger() > 0 ? 'var(--danger)' : 'var(--success)'};">${env.VULN_COUNT ?: 0}</div>
            </div>
            <div class="stat-card">
                <h3>Outdated</h3>
                <div class="value" style="color: var(--warning);">${env.OUTDATED_COUNT ?: 0}</div>
            </div>
            <div class="stat-card">
                <h3>Risk Score</h3>
                <div class="value" style="color: ${(env.RISK_SCORE?.toInteger() ?: 0) < 30 ? 'var(--success)' : (env.RISK_SCORE?.toInteger() ?: 0) < 70 ? 'var(--warning)' : 'var(--danger)'};">${env.RISK_SCORE ?: 0}<span style="font-size:24px;color:var(--text-muted);">/100</span></div>
            </div>
        </div>
        
        <div class="debug">
            DEBUG INFO:<br>
            Plugin JSON length: ${pluginJson.length()}<br>
            Plugin count: ${pluginCount}<br>
            Vuln JSON length: ${vulnJson.length()}<br>
        </div>
        
        <div class="section" id="vulnSection" style="display:none;">
            <h2>🚨 Security Vulnerabilities</h2>
            <table id="vulnTable">
                <thead>
                    <tr>
                        <th style="width: 20%;">Plugin</th>
                        <th style="width: 12%;">Version</th>
                        <th style="width: 15%;">CVE</th>
                        <th style="width: 10%;">Severity</th>
                        <th style="width: 43%;">Description</th>
                    </tr>
                </thead>
                <tbody></tbody>
            </table>
        </div>
        
        <div class="section">
            <h2>📦 Installed Plugins</h2>
            <table>
                <thead>
                    <tr>
                        <th style="width: 25%;">Plugin Name</th>
                        <th style="width: 15%;">Short Name</th>
                        <th style="width: 12%;">Version</th>
                        <th style="width: 10%;">Status</th>
                        <th style="width: 20%;">Developers</th>
                        <th style="width: 10%;">Jenkins Ver</th>
                        <th style="width: 8%;">Dependencies</th>
                    </tr>
                </thead>
                <tbody id="tbody"></tbody>
            </table>
            <div class="pagination">
                <div class="pagination-info" id="info"></div>
                <div class="pagination-buttons">
                    <button onclick="p=1;r()" id="btnFirst">First</button>
                    <button onclick="p--;r()" id="btnPrev">Previous</button>
                    <button onclick="p++;r()" id="btnNext">Next</button>
                    <button onclick="p=tp;r()" id="btnLast">Last</button>
                </div>
            </div>
        </div>
    </div>
    <script>
        console.log('Starting script...');
        const data = ${pluginJson};
        const vulns = ${vulnJson};
        
        console.log('Data loaded:', data.length, 'plugins');
        console.log('Vulns loaded:', vulns.length, 'vulnerabilities');
        
        let p=1, pp=50, tp=Math.ceil(data.length/pp);
        
        document.getElementById('totalCount').textContent = data.length;
        
        if(vulns.length > 0) {
            document.getElementById('vulnSection').style.display = 'block';
            const tbody = document.getElementById('vulnTable').querySelector('tbody');
            tbody.innerHTML = vulns.map(v => 
                '<tr><td><strong>'+e(v.plugin)+'</strong></td><td>'+e(v.version)+'</td><td><code>'+e(v.cve)+'</code></td>'+
                '<td><span class="badge badge-'+v.severity.toLowerCase()+'">'+e(v.severity)+'</span></td>'+
                '<td>'+e(v.description)+'</td></tr>'
            ).join('');
        }
        
        function r(){
            console.log('Rendering page', p);
            if(p<1) p=1; 
            if(p>tp) p=tp;
            
            const s=(p-1)*pp, e1=s+pp, pg=data.slice(s,e1);
            console.log('Showing plugins', s, 'to', e1, '=', pg.length, 'plugins');
            
            document.getElementById('tbody').innerHTML = pg.map(x =>
                '<tr>'+
                '<td><strong>'+e(x.longName)+'</strong></td>'+
                '<td><code>'+e(x.shortName)+'</code></td>'+
                '<td>'+e(x.version)+'</td>'+
                '<td><span class="badge badge-'+(x.enabled?'enabled">ENABLED':'disabled">DISABLED')+'</span></td>'+
                '<td>'+e((x.developerNames||'Unknown').split(':')[0])+'</td>'+
                '<td>'+e(x.jenkinsVersion||'-')+'</td>'+
                '<td style="text-align:center;">'+(x.dependencyCount||0)+'</td>'+
                '</tr>'
            ).join('');
            
            document.getElementById('info').textContent = 'Showing '+(s+1)+'-'+Math.min(e1,data.length)+' of '+data.length+' plugins (Page '+p+' of '+tp+')';
            
            document.getElementById('btnFirst').disabled = (p === 1);
            document.getElementById('btnPrev').disabled = (p === 1);
            document.getElementById('btnNext').disabled = (p === tp);
            document.getElementById('btnLast').disabled = (p === tp);
        }
        
        function e(s){ 
            const d=document.createElement('div'); 
            d.textContent=s||''; 
            return d.innerHTML; 
        }
        
        console.log('Calling r()...');
        r();
        console.log('Done!');
    </script>
</body>
</html>"""
    
    writeFile file: 'plugin-validation-report.html', text: html
    
    archiveArtifacts artifacts: '*.html,plugins.json'
    
    try {
        publishHTML([
            allowMissing: false,
            alwaysLinkToLastBuild: true,
            keepAll: true,
            reportDir: '.',
            reportFiles: 'plugin-validation-report.html',
            reportName: 'Plugin Validation Report'
        ])
    } catch (Exception e) {
        echo "⚠️ HTML Publisher not available"
    }
    
    echo "✅ Reports generated successfully!"
}

@NonCPS
def getCurrentUser() {
    try {
        def user = hudson.model.User.current()
        return user?.getId() ?: 'System'
    } catch (Exception e) {
        return 'Unknown'
    }
}

def sendSuccessNotification() {
    echo "✅ Plugin validation completed"
}

def sendSecurityAlert() {
    if (currentBuild.result == 'UNSTABLE') {
        echo "⚠️ Vulnerabilities detected"
    }
}

@NonCPS
def checkPluginInstalled(String pluginName) {
    def jenkins = Jenkins.instance
    def plugin = jenkins.pluginManager.getPlugin(pluginName)
    return plugin != null && plugin.isEnabled()
}
