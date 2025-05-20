#!/bin/bash

# Create necessary directories
mkdir -p logs output reports

# Set proper permissions
chmod +x scripts/*.sh
chmod +x core/cli.py
chmod 755 -R .

# Install Python dependencies
pip3 install -r requirements.txt

# Create symbolic link
sudo ln -s $(pwd)/core/cli.py /usr/local/bin/evil-jwt-force

echo "Installation complete! You can now run 'evil-jwt-force' from anywhere."