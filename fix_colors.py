import re

files = [
    'frontend/src/components/SystemMetrics.jsx',
    'frontend/src/components/ProcessList.jsx',
    'frontend/src/components/DockerStatus.jsx'
]

for filepath in files:
    with open(filepath, 'r') as f:
        content = f.read()

    # Boxes / Cards
    # In ProcessList: bg-[var(--bg-card)]
    # In SystemMetrics: theme-card
    content = content.replace('theme-card', 'bg-white dark:bg-slate-800 shadow-sm border border-slate-200 dark:border-slate-700')
    content = content.replace('bg-[var(--bg-card)]', 'bg-white dark:bg-slate-800')
    content = content.replace('bg-[var(--table-header-bg)]', 'bg-slate-50 dark:bg-slate-700/50')
    
    # Text colors
    content = content.replace('text-[var(--text-primary)]', 'text-slate-800 dark:text-slate-200')
    content = content.replace('text-[var(--text-secondary)]', 'text-slate-600 dark:text-slate-400')
    content = content.replace('text-[var(--text-muted)]', 'text-slate-500 dark:text-slate-400')
    
    # Border
    content = content.replace('border-[var(--border-card)]', 'border-slate-200 dark:border-slate-700')
    content = content.replace('divide-[var(--border-card)]', 'divide-slate-200 dark:divide-slate-700')
    
    # Hover row
    content = content.replace('hover:bg-[var(--hover-row)]', 'hover:bg-slate-50 dark:hover:bg-slate-700/50')

    # Now for inline styles. Let's do regex replacements so we replace the whole style tag if it only contains the color, 
    # or just the specific key-value pair.
    
    # For style={{ color: 'var(--text-primary)' }} etc that I can easily spot:
    content = re.sub(r'style=\{\{\s*color:\s*[\'"]var\(--text-primary\)[\'"]\s*\}\}', 'className="text-slate-800 dark:text-slate-200"', content)
    content = re.sub(r'style=\{\{\s*color:\s*[\'"]var\(--text-secondary\)[\'"]\s*\}\}', 'className="text-slate-600 dark:text-slate-400"', content)
    content = re.sub(r'style=\{\{\s*color:\s*[\'"]var\(--text-muted\)[\'"]\s*\}\}', 'className="text-slate-500 dark:text-slate-400"', content)
    
    # Uptime box style (from before):
    content = content.replace("style={{ color: 'var(--text-muted)', backgroundColor: 'var(--bg-primary)', borderColor: 'var(--border-card)' }}", "className=\"text-slate-500 dark:text-slate-400 bg-white dark:bg-slate-800 border-slate-200 dark:border-slate-700\"")
    
    # Mixed styles: 
    # SystemMetrics has:
    # <span className="w-2 h-2 rounded-full shadow-[0_0_5px_currentColor]" style={{ backgroundColor: m.color, color: m.color }} />
    # <span style={{ color: 'var(--text-secondary)' }}>{m.label}: </span>
    content = content.replace("<span style={{ color: 'var(--text-secondary)' }}>", "<span className=\"text-slate-600 dark:text-slate-400\">")
    content = content.replace("<span className=\"font-bold\" style={{ color: 'var(--text-primary)' }}>", "<span className=\"font-bold text-slate-800 dark:text-slate-200\">")
    
    # SystemMetrics Bar Chart styles:
    content = content.replace("style={{ color: m.color || 'var(--text-primary)' }}", "style={{ color: m.color }} className={!m.color ? 'text-slate-800 dark:text-slate-200' : ''}")
    content = content.replace("style={{ color: 'var(--text-muted)' }}", "className=\"text-slate-500 dark:text-slate-400\"")
    content = content.replace("style={{ color: 'var(--text-primary)' }}", "className=\"text-slate-800 dark:text-slate-200\"")
    
    # Bar Chart background:
    content = content.replace("style={{ backgroundColor: 'var(--bg-tertiary)', borderColor: 'var(--border-card)' }}", "className=\"bg-slate-100 dark:bg-slate-700 border-slate-200 dark:border-slate-600\"")
    
    # Core CPU bar background:
    content = content.replace("bg-[var(--bg-primary)]", "bg-slate-100 dark:bg-slate-800")
    content = content.replace("bg-[var(--bg-secondary)]", "bg-slate-50 dark:bg-slate-800/50")
    content = content.replace("text-[var(--text-muted)]", "text-slate-500 dark:text-slate-400")
    
    # ProcessList inline styles:
    content = content.replace("style={{ color: 'var(--text-primary)' }}", "className=\"text-slate-800 dark:text-slate-200\"")
    content = content.replace("style={{ color: 'var(--text-secondary)' }}", "className=\"text-slate-600 dark:text-slate-400\"")

    # Table fixed things:
    content = content.replace("bg-[var(--bg-card)]", "bg-white dark:bg-slate-800")
    
    with open(filepath, 'w') as f:
        f.write(content)

