#!/bin/sh

set -e

# first create venv
./create_venv.sh

# create 
venv/bin/pip install pyinstaller
venv/bin/pyinstaller zap_asset.py
# pyinstaller misses these text resources
mkdir -p dist/zap_asset/mnemonic
cp -r venv/lib/python3.7/site-packages/mnemonic/wordlist dist/zap_asset/mnemonic
