import re

with open('frontend/src/components/ProcessList.jsx', 'r') as f:
    content = f.read()

# Replace in table row
content = content.replace(
    '<td className="py-3 px-2 font-mono text-xs" style={{ color: \'var(--accent-neon)\' }}>{p.pid}</td>',
    '<td className="py-3 px-2 font-mono text-xs text-slate-800 dark:text-slate-200">{p.pid}</td>'
)

# Replace in card view
content = content.replace(
    '<span>PID: <span style={{ color: \'var(--accent-neon)\' }}>{p.pid}</span></span>',
    '<span>PID: <span className="text-slate-800 dark:text-slate-200">{p.pid}</span></span>'
)

with open('frontend/src/components/ProcessList.jsx', 'w') as f:
    f.write(content)
