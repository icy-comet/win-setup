from pathlib import Path

readme = Path("README.md")

if readme.exists():
    with open(readme, 'r', errors="surrogateescape") as f:
        readme_lines = f.readlines()

    actual_count = 0

    for line_idx in range(len(readme_lines)):
        line = readme_lines[line_idx]
        try:
            count_in_file = line.split()[0].strip(" \n.")
            if int(count_in_file):
                actual_count+=1
                line = line.replace(count_in_file, str(actual_count), 1)
                readme_lines[line_idx] = line
        except:
            # int conversion fails if it's not a sr. record line
            pass

    with open(readme, 'w', errors="surrogateescape") as f:
        f.write(''.join(readme_lines))
else:
    print("The source file doesn't exist.")