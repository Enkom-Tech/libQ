#!/usr/bin/env python3

import git
from pathlib import Path
import subprocess
import os

repo = git.Repo(".")


def shell(command, expect=0, cwd=None):
    ret = subprocess.run(command, cwd=cwd)
    if ret.returncode != expect:
        raise Exception("Error {}. Expected {}.".format(ret, expect))


format_python_files = False
format_rust_files = False

for item in repo.index.diff("HEAD"):
    path = Path(item.a_path)
    if path.suffix == ".py":
        format_python_files = True
    elif path.suffix == ".rs":
        format_rust_files = True

do_nothing = True

if format_python_files == True:
    shell(["black", "."])
    do_nothing = False
if format_rust_files == True:
    shell(["cargo", "fmt"])
    do_nothing = False

if do_nothing:
    exit(0)

for item in repo.index.diff("HEAD"):
    repo.git.add(item.a_path)
