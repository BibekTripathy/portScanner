import re

with open('frontend/src/components/ProcessList.jsx', 'r') as f:
    content = f.read()

# Replace the CPU column block
content = re.sub(
    r'<div className="flex items-center gap-2">\s*<span className="w-12">\{p\.cpu_percent\.toFixed\(1\)\}%</span>\s*<div className="w-16 h-1\.5 rounded-full bg-slate-100 dark:bg-slate-800 overflow-hidden hidden sm:block">\s*<div className="h-full bg-cyan-500 rounded-full" style=\{\{ width: `\$\{Math\.min\(p\.cpu_percent, 100\)\}%` \}\} />\s*</div>\s*</div>',
    r'{p.cpu_percent.toFixed(1)}%',
    content
)

# Replace the RAM column block
content = re.sub(
    r'<div className="flex items-center gap-2">\s*<span className="w-12">\{p\.memory_percent\.toFixed\(1\)\}%</span>\s*<div className="w-16 h-1\.5 rounded-full bg-slate-100 dark:bg-slate-800 overflow-hidden hidden sm:block">\s*<div className="h-full bg-emerald-500 rounded-full" style=\{\{ width: `\$\{Math\.min\(p\.memory_percent, 100\)\}%` \}\} />\s*</div>\s*</div>',
    r'{p.memory_percent.toFixed(1)}%',
    content
)

with open('frontend/src/components/ProcessList.jsx', 'w') as f:
    f.write(content)

