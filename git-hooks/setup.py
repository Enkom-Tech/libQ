#!/usr/bin/env python3

import os
import stat
import subprocess
import sys
from pathlib import Path

def run_command(cmd, check=True):
    """Run a command and return the result."""
    try:
        result = subprocess.run(cmd, shell=True, check=check, capture_output=True, text=True)
        return result
    except subprocess.CalledProcessError as e:
        print(f"Error running command: {cmd}")
        print(f"Error: {e}")
        if not check:
            return None
        sys.exit(1)

def main():
    """Set up pre-commit hooks for lib-q development."""

    # Make the pre-commit script executable
    pre_commit_path = Path(__file__).parent / "pre-commit.py"
    pre_commit_path.chmod(pre_commit_path.stat().st_mode | stat.S_IEXEC)

    # Check if rustfmt is available
    print("Checking for rustfmt...")
    result = run_command("rustfmt --version", check=False)
    if result is None:
        print("Warning: rustfmt not found. Please install rustfmt:")
        print("  rustup component add rustfmt")
    else:
        print(f"Found rustfmt: {result.stdout.strip()}")

    # Check if black is available
    print("Checking for black...")
    result = run_command("black --version", check=False)
    if result is None:
        print("Warning: black not found. Please install black:")
        print("  pip install black")
        print("  or")
        print("  pip install -r git-hooks/requirements.txt")
    else:
        print(f"Found black: {result.stdout.strip()}")

    # Install the pre-commit hook
    hooks_dir = Path(".git/hooks")
    if not hooks_dir.exists():
        print("Warning: .git/hooks directory not found. Are you in a git repository?")
        return

    pre_commit_hook = hooks_dir / "pre-commit"
    if pre_commit_hook.exists():
        print(f"Pre-commit hook already exists at {pre_commit_hook}")
        response = input("Overwrite existing pre-commit hook? [y/N]: ")
        if response.lower() != 'y':
            print("Setup cancelled.")
            return

    # Copy the pre-commit hook
    import shutil
    shutil.copy2(pre_commit_path, pre_commit_hook)
    print(f"Installed pre-commit hook to {pre_commit_hook}")

    print("\nPre-commit hooks setup complete!")
    print("The hooks will:")
    print("- Run 'cargo fmt' on all Rust files")
    print("- Run 'black' on all Python files")
    print("- Automatically stage formatted files")

if __name__ == "__main__":
    main()
