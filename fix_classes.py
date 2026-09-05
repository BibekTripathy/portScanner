import re

with open('frontend/src/components/SystemMetrics.jsx', 'r') as f:
    content = f.read()

# Fix multiple classNames
content = re.sub(
    r'className="([^"]+)"\s+className="([^"]+)"',
    r'className="\1 \2"',
    content
)
# For the one with template literal
content = re.sub(
    r'className=\{`([^`]+)`\}\s+className="([^"]+)"',
    r'className={`\1 \2`}',
    content
)

# For the conditional className
content = content.replace(
    'className="text-sm font-bold uppercase tracking-wider" style={{ color: m.color }} className={!m.color ? \'text-slate-800 dark:text-slate-200\' : \'\'}',
    'className={`text-sm font-bold uppercase tracking-wider ${!m.color ? \'text-slate-800 dark:text-slate-200\' : \'\'}`} style={{ color: m.color }}'
)

# Remove the Network Traffic box and Network metric mapping
# In SystemMetrics.jsx, Network is added to the metrics array.
# The user wants to remove the Network box.
# Network is in `metrics` array around line 335.
content = re.sub(r'\{\s*label:\s*\'Network\'.*?\},', '', content, flags=re.DOTALL)
# And the Network Traffic box at the bottom:
content = re.sub(r'\{/\* Network Traffic Box \*/\}.*?</div>\s*</div>\s*</div>\s*</div>', '', content, flags=re.DOTALL)
# Wait, let's just make it simpler. I'll manually replace the network box if my regex is too greedy.

# Let's write the fixed content
with open('frontend/src/components/SystemMetrics.jsx', 'w') as f:
    f.write(content)

