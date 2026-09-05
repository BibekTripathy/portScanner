import re

with open('frontend/src/pages/Stats.jsx', 'r') as f:
    content = f.read()

# Update page wrapper background
content = re.sub(
    r'<div className=\{`app-container min-h-screen p-4 md:p-8 transition-colors duration-300 \$\{darkMode \? \'\' : \'light\'\}`\}>',
    '<div className="min-h-screen p-4 md:p-8 transition-colors duration-300 bg-[#87CEEB] dark:bg-[#040d1a] text-black dark:text-white">',
    content
)

# Replace the entire <header> ... </header> with Port Scanner header
header_replacement = """      <header className="flex flex-col sm:flex-row sm:justify-between sm:items-center mb-8 bg-slate-100 dark:bg-slate-800 p-4 rounded-xl shadow-sm border border-slate-200 dark:border-slate-700 gap-4">
        <div className="flex items-center gap-4">
          <button 
            onClick={() => navigate('/')} 
            className="p-2 hover:bg-slate-200 dark:hover:bg-slate-700 rounded-full transition-colors hidden sm:block text-slate-500 dark:text-slate-400"
            title="Back to Home"
          >
            <ArrowLeft size={20} />
          </button>
          <h1 className="text-2xl font-bold tracking-tight text-slate-800 dark:text-slate-200 flex items-center gap-2">
            System Monitor
          </h1>
        </div>
        
        {/* Controls */}
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2 bg-white dark:bg-slate-700 px-3 py-1.5 rounded-lg border border-slate-200 dark:border-slate-600">
            <span className="text-sm font-medium text-slate-600 dark:text-slate-300">Auto-refresh:</span>
            <select
              value={pollingInterval === null ? 'paused' : pollingInterval.toString()}
              onChange={(e) => setPollingInterval(e.target.value === 'paused' ? null : parseInt(e.target.value))}
              className="text-sm bg-transparent outline-none cursor-pointer text-slate-700 dark:text-slate-200 font-medium"
            >
              <option value="1000">1s</option>
              <option value="3000">3s</option>
              <option value="5000">5s</option>
              <option value="10000">10s</option>
              <option value="paused">Off</option>
            </select>
          </div>

          <button
            onClick={toggleTheme}
            className="p-2 rounded-full bg-white dark:bg-slate-700 border border-slate-200 dark:border-slate-600 shadow-sm hover:bg-slate-50 dark:hover:bg-slate-600 transition-colors text-slate-500 dark:text-slate-400"
            title={darkMode ? 'Switch to light mode' : 'Switch to dark mode'}
            aria-label="Toggle theme"
          >
            {!darkMode ? (
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"></path>
              </svg>
            ) : (
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <circle cx="12" cy="12" r="5"></circle>
                <line x1="12" y1="1" x2="12" y2="3"></line>
                <line x1="12" y1="21" x2="12" y2="23"></line>
                <line x1="4.22" y1="4.22" x2="5.64" y2="5.64"></line>
                <line x1="18.36" y1="18.36" x2="19.78" y2="19.78"></line>
                <line x1="1" y1="12" x2="3" y2="12"></line>
                <line x1="21" y1="12" x2="23" y2="12"></line>
                <line x1="4.22" y1="19.78" x2="5.64" y2="18.36"></line>
                <line x1="18.36" y1="5.64" x2="19.78" y2="4.22"></line>
              </svg>
            )}
          </button>
        </div>
      </header>"""

content = re.sub(r'<header className="mb-8 flex justify-between items-start">.*?</header>', header_replacement, content, flags=re.DOTALL)

# Also remove the separate Theme Toggle Button since it's now in the header
content = re.sub(r'\{/\* Theme Toggle Button.*?</button>', '', content, flags=re.DOTALL)

# Replace the manual toggleTheme function with the useTheme hook (like I did before)
content = content.replace("import '../index.css';", "import '../index.css';\nimport { useTheme } from '../hooks/useTheme';")
content = re.sub(r'const \[darkMode, setDarkMode\] = useState\(true\);.*?const toggleTheme =.*?};', 'const { darkMode, toggleTheme } = useTheme();', content, flags=re.DOTALL)

# Tab Navigation Styles
# In v1.6.0 it uses style={{ backgroundColor: 'var(--bg-card)' }}
# We will replace it with Tailwind pill container
content = re.sub(
    r'<nav className="flex gap-1 mb-6 rounded-lg p-1 w-fit" style=\{\{ backgroundColor: \'var\(--bg-card\)\' \}\}>.*?</nav>',
    """<nav className="flex gap-2 mb-6 w-fit">
        {['overview', 'processes', 'docker'].map((tab) => (
          <button
            key={tab}
            onClick={() => setActiveTab(tab)}
            className={`px-4 py-2 rounded-lg text-sm font-medium capitalize transition-all ${
              activeTab === tab
                ? 'bg-white dark:bg-slate-800 text-slate-800 dark:text-slate-200 shadow-sm border border-slate-200 dark:border-slate-700'
                : 'text-slate-600 dark:text-slate-400 hover:bg-white/50 dark:hover:bg-slate-800/50 border border-transparent'
            }`}
          >
            {tab}
          </button>
        ))}
      </nav>""",
    content,
    flags=re.DOTALL
)

with open('frontend/src/pages/Stats.jsx', 'w') as f:
    f.write(content)

