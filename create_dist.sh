#!/bin/sh

set -e

# first create venv
./create_venv.sh

# create 
venv/bin/pip install pyinstaller
venv/bin/pyinstaller zap_asset.py
