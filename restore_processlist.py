import re

with open('frontend/src/components/ProcessList.jsx', 'r') as f:
    content = f.read()

# Remove Kill import
content = content.replace(', Kill', '')

# Replace theme-card
content = content.replace('theme-card', 'bg-white dark:bg-slate-800 shadow-sm border border-slate-200 dark:border-slate-700')

# Table fixed layout
content = content.replace('<table className="w-full text-left text-sm whitespace-nowrap">', '<table className="w-full table-fixed text-left text-sm whitespace-nowrap">')

# Column widths
content = content.replace('<th className="pb-3 px-2 font-medium cursor-pointer select-none hover:text-[var(--text-primary)]" onClick={() => handleSort(\'pid\')}>', '<th className="w-16 sm:w-24 pb-3 px-2 font-medium cursor-pointer select-none hover:text-[var(--text-primary)]" onClick={() => handleSort(\'pid\')}>')
content = content.replace('<th className="pb-3 px-2 font-medium cursor-pointer select-none hover:text-[var(--text-primary)]" onClick={() => handleSort(\'username\')}>', '<th className="w-20 sm:w-28 pb-3 px-2 font-medium cursor-pointer select-none hover:text-[var(--text-primary)]" onClick={() => handleSort(\'username\')}>')
content = content.replace('<th className="pb-3 px-2 font-medium cursor-pointer select-none hover:text-[var(--text-primary)]" onClick={() => handleSort(\'cpu_percent\')}>', '<th className="w-20 sm:w-24 pb-3 px-2 font-medium cursor-pointer select-none hover:text-[var(--text-primary)]" onClick={() => handleSort(\'cpu_percent\')}>')
content = content.replace('<th className="pb-3 px-2 font-medium cursor-pointer select-none hover:text-[var(--text-primary)]" onClick={() => handleSort(\'memory_percent\')}>', '<th className="w-20 sm:w-24 pb-3 px-2 font-medium cursor-pointer select-none hover:text-[var(--text-primary)]" onClick={() => handleSort(\'memory_percent\')}>')
content = content.replace('<th className="pb-3 px-2 font-medium cursor-pointer select-none hover:text-[var(--text-primary)]" onClick={() => handleSort(\'status\')}>', '<th className="w-24 pb-3 px-2 font-medium cursor-pointer select-none hover:text-[var(--text-primary)]" onClick={() => handleSort(\'status\')}>')
content = content.replace('<th className="pb-3 px-2 font-medium text-right">', '<th className="w-20 pb-3 px-2 font-medium text-right">')

# Truncate Name column
content = content.replace('<td className="py-3 px-2 font-medium" style={{ color: \'var(--text-primary)\' }}>', '<td className="py-3 px-2 font-medium truncate" style={{ color: \'var(--text-primary)\' }}>')

# Remove inline charts (CPU and RAM bars in cells)
content = re.sub(r'<div className="w-16 h-1\.5 ml-2.*?</div>', '', content, flags=re.DOTALL)
content = re.sub(r'<div className="w-12 h-1\.5 ml-2.*?</div>', '', content, flags=re.DOTALL)

with open('frontend/src/components/ProcessList.jsx', 'w') as f:
    f.write(content)
