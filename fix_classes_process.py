import re

with open('frontend/src/components/ProcessList.jsx', 'r') as f:
    content = f.read()

# Fix multiple classNames
content = re.sub(
    r'className="([^"]+)"\s+className="([^"]+)"',
    r'className="\1 \2"',
    content
)

with open('frontend/src/components/ProcessList.jsx', 'w') as f:
    f.write(content)
