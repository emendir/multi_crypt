#!/usr/bin/python
"""DON'T FORGET TO UPDATE:
pyproject.toml
git commit
"""
import sys
import os
import shutil

PROJECT_DIR = os.path.dirname(__file__)

# os.system("./generate_docs.sh")

os.system("rm -r build  >/dev/null 2>/dev/null")
os.system("rm -r dist  >/dev/null 2>/dev/null")
os.system("rm -r *.egg-info  >/dev/null 2>/dev/null")

python_executables = [
    "/usr/bin/python3",
    sys.executable
]
# install locally
for executable in python_executables:
    os.system("pip install --no-cache-dir . --break-system-packages")


os.system(f"cd ../CodePub; python3 . {os.getcwd()}")

if '--website-only' in sys.argv:
    sys.exit()


os.system("rm -r dist")             # remove old dist folder
os.system("python -m build --wheel .")       # build project package
print("")
print("set username to __token__")
os.system("twine upload dist/*")    # publish on pypi

# publish on GitHub
os.system("git checkout master")
os.system("git merge developing")
os.system("git push github master")
os.system("git checkout developing")
