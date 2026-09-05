import re

with open('frontend/src/components/DockerStatus.jsx', 'r') as f:
    content = f.read()

# Fix the badge
content = re.sub(
    r'<span className="text-xs text-slate-600 dark:text-slate-700 dark:text-slate-300 bg-slate-100 dark:bg-slate-700 px-2 py-1 rounded">',
    '<span className="text-xs bg-slate-100 dark:bg-slate-700 text-slate-700 dark:text-slate-200 px-2 py-1 rounded shadow-sm border border-slate-200 dark:border-slate-600">',
    content
)

# Fix empty state text
content = re.sub(
    r'<div className="text-slate-500 dark:text-slate-400 text-sm text-center py-8">',
    '<div className="text-slate-600 dark:text-slate-200 text-sm text-center py-8">',
    content
)

# Fix loading text
content = re.sub(
    r'<div className="text-slate-500 dark:text-slate-400 animate-pulse p-4 text-center">Loading…</div>',
    '<div className="text-slate-600 dark:text-slate-200 animate-pulse p-4 text-center">Loading…</div>',
    content
)

# Fix the title
content = re.sub(
    r'<h2 className="text-sm font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider">',
    '<h2 className="text-sm font-bold uppercase tracking-wider text-slate-700 dark:text-slate-200">',
    content
)

# Fix ActionBtn
# Right now it's: : `bg-slate-700/50 border-slate-600 text-slate-700 dark:text-slate-300 hover:bg-slate-600 hover:text-white ${className}`
content = re.sub(
    r'bg-slate-700/50 border-slate-600 text-slate-700 dark:text-slate-300 hover:bg-slate-600 hover:text-white',
    'bg-white dark:bg-slate-700 border-slate-200 dark:border-slate-600 text-slate-700 dark:text-slate-200 hover:bg-slate-50 dark:hover:bg-slate-600',
    content
)

with open('frontend/src/components/DockerStatus.jsx', 'w') as f:
    f.write(content)
