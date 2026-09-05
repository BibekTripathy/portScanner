import re

with open('frontend/src/components/DockerStatus.jsx', 'r') as f:
    content = f.read()

# Replace theme-muted
content = content.replace('theme-muted', 'text-slate-500 dark:text-slate-400')

# Badge background
content = content.replace("style={{ backgroundColor: 'var(--bg-tertiary)' }}", "className=\"bg-slate-100 dark:bg-slate-700 text-slate-600 dark:text-slate-300\"")
content = content.replace('className="text-xs text-slate-500 dark:text-slate-400 px-2 py-1 rounded" className="bg-slate-100 dark:bg-slate-700 text-slate-600 dark:text-slate-300"', 'className="text-xs text-slate-600 dark:text-slate-300 bg-slate-100 dark:bg-slate-700 px-2 py-1 rounded"')

# Let's fix the double className issue if it arises:
content = re.sub(r'className="([^"]*?)\s*text-slate-500 dark:text-slate-400\s*([^"]*?)"\s*className="bg-slate-100 dark:bg-slate-700 text-slate-600 dark:text-slate-300"', r'className="\1 \2 bg-slate-100 dark:bg-slate-700 text-slate-600 dark:text-slate-300"', content)

# Container cards
content = content.replace('bg-slate-900/50 border border-slate-700/40 p-4 hover:border-slate-600', 'bg-white dark:bg-slate-800/50 border border-slate-200 dark:border-slate-700/50 p-4 hover:border-cyan-500/50 dark:hover:border-cyan-500/50 shadow-sm')

# Text inside cards
content = content.replace('text-slate-200', 'text-slate-800 dark:text-slate-200')
content = content.replace('text-slate-500 mt-1', 'text-slate-500 dark:text-slate-400 mt-1')
content = content.replace('text-slate-300', 'text-slate-700 dark:text-slate-300')
content = content.replace('bg-slate-700/50 text-slate-400 border-slate-600 hover:text-white hover:bg-slate-600', 'bg-slate-50 dark:bg-slate-700/50 text-slate-600 dark:text-slate-400 border-slate-200 dark:border-slate-600 hover:bg-slate-200 dark:hover:bg-slate-600 hover:text-slate-900 dark:hover:text-white')

# Button base
content = content.replace('bg-slate-700/50 border-slate-600 text-slate-300 hover:bg-slate-600 hover:text-white', 'bg-slate-50 dark:bg-slate-700/50 border-slate-200 dark:border-slate-600 text-slate-600 dark:text-slate-300 hover:bg-slate-200 dark:hover:bg-slate-600 hover:text-slate-900 dark:hover:text-white')
content = content.replace('bg-slate-800/30 border-slate-700/30 text-slate-600', 'bg-slate-100 dark:bg-slate-800/30 border-slate-200 dark:border-slate-700/30 text-slate-400 dark:text-slate-500')

# Remove duplicate text-slate-800 dark:text-slate-200 that might have happened
content = content.replace('text-slate-800 dark:text-slate-800 dark:text-slate-200', 'text-slate-800 dark:text-slate-200')

with open('frontend/src/components/DockerStatus.jsx', 'w') as f:
    f.write(content)
