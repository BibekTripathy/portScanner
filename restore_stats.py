import re

with open('frontend/src/pages/Stats.jsx', 'r') as f:
    content = f.read()

# Add imports for SplitPane, useTheme
if 'SplitPane' not in content:
    content = content.replace("import '../index.css';", "import '../index.css';\nimport SplitPane from '../components/SplitPane';\nimport { useTheme } from '../hooks/useTheme';")

# Replace manual theme toggle and state
content = re.sub(r'const \[darkMode, setDarkMode\] = useState\(true\);.*?const toggleTheme =.*?};', 'const { darkMode, toggleTheme } = useTheme();', content, flags=re.DOTALL)

# Update wrapper
content = re.sub(r'<div className=\{`app-container min-h-screen p-4 md:p-8 transition-colors duration-300 \$\{darkMode \? \'\' : \'light\'\}`\}>', '<div className="min-h-screen p-4 md:p-8 transition-colors duration-300 bg-[#87CEEB] dark:bg-[#040d1a] text-black dark:text-white">', content)

# Update header and buttons
content = content.replace('<header className="mb-8 flex justify-between items-start">', '<header className="mb-8 flex justify-between items-start text-white">')
content = content.replace('<button \n            onClick={() => navigate(\'/\')} \n            className="flex items-center gap-2 text-sm text-[var(--text-muted)] hover:text-[var(--text-primary)] transition-colors w-fit mb-2"\n          >', '<button onClick={() => navigate(\'/\')} className="flex items-center gap-2 text-sm text-white/80 hover:text-white transition-colors w-fit mb-2">')
content = content.replace('<div className={`w-4 h-4 rounded-full ${pollingInterval ? \'bg-teal-400 animate-pulse shadow-[0_0_8px_rgba(45,212,191,0.8)]\' : \'bg-red-500 shadow-[0_0_8px_rgba(239,68,68,0.8)]\'}`} />', '')
content = content.replace('<h1 className="text-4xl font-bold tracking-tight" style={{ color: \'var(--text-primary)\' }}>', '<h1 className="text-4xl font-bold tracking-tight text-white">')

content = content.replace('className="p-2 rounded-full shadow-sm transition-colors"\n            style={{ backgroundColor: \'var(--bg-card)\', color: \'var(--text-primary)\', border: \'1px solid var(--border-card)\' }}', 'className="p-2 rounded-full shadow-sm transition-colors text-slate-800 dark:text-slate-200 bg-white dark:bg-slate-800/50 hover:bg-slate-100 dark:hover:bg-slate-700 border border-slate-200 dark:border-slate-700"')

content = content.replace('<span className="text-xs font-semibold" style={{ color: \'var(--text-muted)\' }}>REFRESH:</span>', '<span className="text-xs font-semibold text-white/90">REFRESH:</span>')

content = re.sub(r'<select.*?style=\{\{\s*backgroundColor.*?\}\}', '<select\n              value={pollingInterval === null ? \'paused\' : pollingInterval.toString()}\n              onChange={(e) => setPollingInterval(e.target.value === \'paused\' ? null : parseInt(e.target.value))}\n              className="text-xs rounded px-2 py-1 border cursor-pointer outline-none transition-colors bg-white/20 dark:bg-black/20 text-white border-white/30 hover:bg-white/30 dark:hover:bg-black/40"', content, flags=re.DOTALL)

# Replace the flex layout with SplitPane
layout_replacement = """
      {/* Dashboard Content */}
      <SplitPane>
        <div className="h-full">
          <SystemMetrics pollingInterval={pollingInterval} />
        </div>
        <div className="h-full flex flex-col">
          {/* Tabs */}
          <div className="flex gap-2 mb-4">
            <button 
              onClick={() => setActiveTab('overview')}
              className={`px-4 py-2 rounded-lg text-sm font-medium transition-all ${activeTab === 'overview' ? 'bg-white dark:bg-slate-800 text-slate-800 dark:text-slate-200 shadow-sm border border-slate-200 dark:border-slate-700' : 'text-slate-600 dark:text-slate-400 hover:bg-white/50 dark:hover:bg-slate-800/50 border border-transparent'}`}
            >
              Processes
            </button>
            <button 
              onClick={() => setActiveTab('docker')}
              className={`px-4 py-2 rounded-lg text-sm font-medium transition-all ${activeTab === 'docker' ? 'bg-white dark:bg-slate-800 text-slate-800 dark:text-slate-200 shadow-sm border border-slate-200 dark:border-slate-700' : 'text-slate-600 dark:text-slate-400 hover:bg-white/50 dark:hover:bg-slate-800/50 border border-transparent'}`}
            >
              Docker
            </button>
          </div>
          
          <div className="flex-1 min-h-0">
            {activeTab === 'overview' ? <ProcessList pollingInterval={pollingInterval} /> : <DockerStatus pollingInterval={pollingInterval} />}
          </div>
        </div>
      </SplitPane>
"""

content = re.sub(r'\{/\* Dashboard Content \*/\}.*', layout_replacement, content, flags=re.DOTALL)

with open('frontend/src/pages/Stats.jsx', 'w') as f:
    f.write(content + "\n    </div>\n  );\n}\n\nexport default Stats;\n")

