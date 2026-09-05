import os, re

files = [
    'frontend/src/components/SystemMetrics.jsx',
    'frontend/src/components/ProcessList.jsx',
    'frontend/src/components/DockerStatus.jsx',
]

for filepath in files:
    with open(filepath, 'r') as f:
        content = f.read()

    # 1. Replace theme-card class
    content = content.replace('theme-card', 'bg-white dark:bg-slate-800 shadow-sm border border-slate-200 dark:border-slate-700')
    
    # 2. Text utility classes replacement (Tailwind strings)
    content = content.replace('text-[var(--text-primary)]', 'text-slate-800 dark:text-slate-200')
    content = content.replace('text-[var(--text-secondary)]', 'text-slate-600 dark:text-slate-400')
    content = content.replace('text-[var(--text-muted)]', 'text-slate-500 dark:text-slate-400')
    
    content = content.replace('bg-[var(--bg-primary)]', 'bg-slate-50 dark:bg-slate-900')
    content = content.replace('bg-[var(--bg-card)]', 'bg-white dark:bg-slate-800')
    content = content.replace('border-[var(--border-card)]', 'border-slate-200 dark:border-slate-700')
    content = content.replace('divide-[var(--border-card)]', 'divide-slate-200 dark:divide-slate-700')

    # Replace inline styles that match exactly style={{ color: 'var(--text-primary)' }} etc
    # We replace the whole style tag and inject the class into the preceding className instead, or just wrap it.
    # It's easier to just swap the text in the style dict for 'undefined' and add a class? 
    # Actually, the user wants me to do it. Let me just replace the inline style strings for things I know.
    
    # Let's replace the inline styles where we can.
    content = content.replace("style={{ color: 'var(--text-primary)' }}", "className=\"text-slate-800 dark:text-slate-200\"")
    content = content.replace("style={{ color: 'var(--text-secondary)' }}", "className=\"text-slate-600 dark:text-slate-400\"")
    content = content.replace("style={{ color: 'var(--text-muted)' }}", "className=\"text-slate-500 dark:text-slate-400\"")
    
    # For mixed styles:
    content = content.replace("color: 'var(--text-primary)'", "color: undefined")
    content = content.replace("color: 'var(--text-secondary)'", "color: undefined")
    content = content.replace("color: 'var(--text-muted)'", "color: undefined")
    
    content = content.replace("backgroundColor: 'var(--bg-primary)'", "backgroundColor: undefined")
    content = content.replace("backgroundColor: 'var(--bg-secondary)'", "backgroundColor: undefined")
    content = content.replace("backgroundColor: 'var(--bg-tertiary)'", "backgroundColor: undefined")
    content = content.replace("backgroundColor: 'var(--bg-card)'", "backgroundColor: undefined")
    
    content = content.replace("borderColor: 'var(--border-card)'", "borderColor: undefined")

    with open(filepath, 'w') as f:
        f.write(content)

