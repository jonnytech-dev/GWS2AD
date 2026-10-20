"""Runs every test file and prints one summary line. Usage:  python tests/run_all.py"""
import glob
import os
import subprocess
import sys

here = os.path.dirname(os.path.abspath(__file__))
failed = []
for path in sorted(glob.glob(os.path.join(here, 'test_*.py'))):
    name = os.path.basename(path)
    if name == 'test_support.py':
        continue
    result = subprocess.run([sys.executable, path], capture_output=True, text=True)
    last = (result.stdout.strip().splitlines() or ['(no output)'])[-1]
    print(f"{'ok  ' if result.returncode == 0 else 'FAIL'} {name}: {last}")
    if result.returncode:
        failed.append(name)
sys.exit(1 if failed else 0)
