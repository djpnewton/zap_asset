#!/bin/sh

set -e

# create virtual envrionment
virtualenv --python=python3.7 ./venv
venv/bin/pip3 install -r requirements.txt

# create wrapper script
cat > zap_asset.sh <<EOL
#!/bin/sh

venv/bin/python3 zap_asset.py "\$@"
EOL
chmod 755 zap_asset.sh
