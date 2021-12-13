import re
from pathlib import Path

count = 0

def repl(matchobj):
    global count
    count+=1
    return f'{str(count)} |'

readme = Path("README.md")

if readme.exists():
    with open(readme, 'r', errors="surrogateescape") as f:
        readme_lines = f.read()

    readme_lines = re.sub("^([0-9]+[ .]?)\|", repl, readme_lines, flags=re.MULTILINE)

    with open(readme, 'w', errors="surrogateescape") as f:
        f.write(readme_lines)
else:
    print("The source file doesn't exist.")