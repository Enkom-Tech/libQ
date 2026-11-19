#!/bin/sh
# L0: 11 runs of LaZer python/anon_cred at the pinned commit; prints sizes and times.
# Usage: LAZER_DIR=<LaZer checkout> VENV_PYTHON=<python with cffi, jinja2> sh l0_runs.sh
# If Python needs libstdc++/zlib from a non-default location, set LD_LIBRARY_PATH yourself.
: "${LAZER_DIR:?set LAZER_DIR to the LaZer checkout}"
: "${VENV_PYTHON:?set VENV_PYTHON to a python with cffi and jinja2}"
cd "$LAZER_DIR/python/anon_cred" || exit 1
i=0
while [ $i -lt 11 ]; do
  PYTHONPATH=..:. "$VENV_PYTHON" anon_cred.py 2>&1 | grep -E "bytes|Issue time|Show time" | tr '\n' ' '
  echo
  i=$((i+1))
done
