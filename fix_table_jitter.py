import re

with open('frontend/src/components/ProcessList.jsx', 'r') as f:
    content = f.read()

# 1. Add table-fixed
content = content.replace(
    '<table className="w-full text-left text-sm whitespace-nowrap">',
    '<table className="w-full table-fixed text-left text-sm whitespace-nowrap">'
)

# 2. Add fixed widths to the TH headers
content = content.replace(
    '<th className="pb-3 px-2 font-medium cursor-pointer select-none hover:text-[var(--text-primary)]" onClick={() => handleSort(\'pid\')}>',
    '<th className="w-16 sm:w-20 pb-3 px-2 font-medium cursor-pointer select-none hover:text-slate-800 dark:hover:text-slate-200" onClick={() => handleSort(\'pid\')}>'
)
content = content.replace(
    '<th className="pb-3 px-2 font-medium cursor-pointer select-none hover:text-[var(--text-primary)]" onClick={() => handleSort(\'name\')}>',
    '<th className="pb-3 px-2 font-medium cursor-pointer select-none hover:text-slate-800 dark:hover:text-slate-200" onClick={() => handleSort(\'name\')}>'
) # We'll let Name take the remaining space
content = content.replace(
    '<th className="pb-3 px-2 font-medium cursor-pointer select-none hover:text-[var(--text-primary)]" onClick={() => handleSort(\'username\')}>',
    '<th className="w-20 sm:w-24 pb-3 px-2 font-medium cursor-pointer select-none hover:text-slate-800 dark:hover:text-slate-200" onClick={() => handleSort(\'username\')}>'
)
content = content.replace(
    '<th className="pb-3 px-2 font-medium cursor-pointer select-none hover:text-[var(--text-primary)]" onClick={() => handleSort(\'cpu_percent\')}>',
    '<th className="w-20 sm:w-24 pb-3 px-2 font-medium cursor-pointer select-none hover:text-slate-800 dark:hover:text-slate-200" onClick={() => handleSort(\'cpu_percent\')}>'
)
content = content.replace(
    '<th className="pb-3 px-2 font-medium cursor-pointer select-none hover:text-[var(--text-primary)]" onClick={() => handleSort(\'memory_percent\')}>',
    '<th className="w-20 sm:w-24 pb-3 px-2 font-medium cursor-pointer select-none hover:text-slate-800 dark:hover:text-slate-200" onClick={() => handleSort(\'memory_percent\')}>'
)
content = content.replace(
    '<th className="pb-3 px-2 font-medium cursor-pointer select-none hover:text-[var(--text-primary)]" onClick={() => handleSort(\'status\')}>',
    '<th className="w-20 sm:w-24 pb-3 px-2 font-medium cursor-pointer select-none hover:text-slate-800 dark:hover:text-slate-200" onClick={() => handleSort(\'status\')}>'
)
content = content.replace(
    '<th className="pb-3 px-2 font-medium text-right">',
    '<th className="w-16 pb-3 px-2 font-medium text-right">'
)

# 3. Add truncate to the name column TD
content = content.replace(
    '<td className="py-3 px-2 font-medium text-slate-800 dark:text-slate-200">{p.name}</td>',
    '<td className="py-3 px-2 font-medium text-slate-800 dark:text-slate-200 truncate" title={p.name}>{p.name}</td>'
)

with open('frontend/src/components/ProcessList.jsx', 'w') as f:
    f.write(content)
