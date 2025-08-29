#!/bin/bash

# Setup Script for the Email Daemon

# Step 1: Update system and install dependencies
echo "Updating system and installing dependencies..."
sudo apt-get update -y
sudo apt-get upgrade -y

# Install required Python packages
pip install -r requirements.txt

# Step 2: Setup Redis (optional, if you're using Redis for queuing)
echo "Setting up Redis..."
sudo apt-get install redis-server -y
sudo systemctl enable redis-server
sudo systemctl start redis-server

# Step 3: Configure DKIM
echo "Setting up DKIM..."

# Generate DKIM key pair (if not already done)
mkdir -p /etc/ssl/dkim
openssl genpkey -algorithm RSA -out /etc/ssl/dkim/private.key -pkeyopt rsa_keygen_bits:2048
openssl rsa -pubout -in /etc/ssl/dkim/private.key -out /etc/ssl/dkim/public.key

# Configure DKIM in your DNS (you will need to create a DKIM TXT record manually in your DNS provider)
echo "Please add the following DKIM TXT record to your DNS provider:"
echo "Name: selector._domainkey.yourdomain.com"
echo "Value: v=DKIM1; k=rsa; p=$(cat /etc/ssl/dkim/public.key)"

# Step 4: Setup SSL certificates
echo "Setting up SSL certificates..."

# Create self-signed SSL certificates (or use valid ones from a provider)
openssl req -new -newkey rsa:2048 -days 365 -nodes -x509 -keyout /etc/ssl/certs/daemon.key -out /etc/ssl/certs/daemon.crt

# Step 5: Setup the systemd service for the daemon
echo "Setting up systemd service..."

# Create the systemd service file
cat <<EOL | sudo tee /etc/systemd/system/email_daemon.service
[Unit]
Description=Email Daemon Service
After=network.target

[Service]
ExecStart=/usr/bin/python3 /path/to/your/email_daemon.py
WorkingDirectory=/path/to/your/project
User=your_user
Group=your_group
Restart=always
PIDFile=/run/email_daemon.pid
StandardOutput=syslog
StandardError=syslog

[Install]
WantedBy=multi-user.target
EOL

# Reload systemd to apply the new service
sudo systemctl daemon-reload

# Step 6: Enable and start the service
echo "Enabling and starting the Email Daemon service..."
sudo systemctl enable email_daemon
sudo systemctl start email_daemon

# Step 7: Check the status of the service
echo "Checking the status of the Email Daemon..."
sudo systemctl status email_daemon

echo "Setup complete! Your Email Daemon is now running."
