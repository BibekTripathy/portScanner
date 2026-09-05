import re

with open('frontend/src/components/ProcessList.jsx', 'r') as f:
    content = f.read()

content = re.sub(
    r'<th className="pb-3 px-2 font-medium cursor-pointer select-none hover:text-slate-800 dark:text-slate-200" onClick=\{\(\) => handleSort\(\'pid\'\)\}>',
    '<th className="w-16 sm:w-20 pb-3 px-2 font-medium cursor-pointer select-none hover:text-slate-800 dark:text-slate-200" onClick={() => handleSort(\'pid\')}>',
    content
)

content = re.sub(
    r'<th className="pb-3 px-2 font-medium cursor-pointer select-none hover:text-slate-800 dark:text-slate-200" onClick=\{\(\) => handleSort\(\'username\'\)\}>',
    '<th className="w-20 sm:w-24 pb-3 px-2 font-medium cursor-pointer select-none hover:text-slate-800 dark:text-slate-200" onClick={() => handleSort(\'username\')}>',
    content
)

content = re.sub(
    r'<th className="pb-3 px-2 font-medium cursor-pointer select-none hover:text-slate-800 dark:text-slate-200" onClick=\{\(\) => handleSort\(\'cpu_percent\'\)\}>',
    '<th className="w-20 sm:w-24 pb-3 px-2 font-medium cursor-pointer select-none hover:text-slate-800 dark:text-slate-200" onClick={() => handleSort(\'cpu_percent\')}>',
    content
)

content = re.sub(
    r'<th className="pb-3 px-2 font-medium cursor-pointer select-none hover:text-slate-800 dark:text-slate-200" onClick=\{\(\) => handleSort\(\'memory_percent\'\)\}>',
    '<th className="w-20 sm:w-24 pb-3 px-2 font-medium cursor-pointer select-none hover:text-slate-800 dark:text-slate-200" onClick={() => handleSort(\'memory_percent\')}>',
    content
)

content = re.sub(
    r'<th className="pb-3 px-2 font-medium cursor-pointer select-none hover:text-slate-800 dark:text-slate-200" onClick=\{\(\) => handleSort\(\'status\'\)\}>',
    '<th className="w-20 sm:w-24 pb-3 px-2 font-medium cursor-pointer select-none hover:text-slate-800 dark:text-slate-200" onClick={() => handleSort(\'status\')}>',
    content
)

with open('frontend/src/components/ProcessList.jsx', 'w') as f:
    f.write(content)
