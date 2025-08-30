#!/bin/bash

# Setup Script for the Email Daemon
KEYS_DIR="/etc/shared_keys"
MASTER=""
SCP_PASSWORD="RestrictedAccess"

while [[ $# -gt 0 ]]; do
  case $1 in
    --master)
      MASTER="$2"
      shift 2
      ;;
    *)
      echo "Unknown option $1"
      exit 1
      ;;
  esac
done

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

if [ ! -f ~/.ssh/id_rsa ]; then
  echo "Creating SSH keys on source server..."
  ssh-keygen -t rsa -b 2048 -f ~/.ssh/id_rsa -N ""
fi

ssh-copy-id -i ~/.ssh/id_rsa.pub dkim-user@$MASTER

# Setting Up SSL and DKIM from master server
scp "dkim-user@$MASTER:/etc/relays/fullchain.pem" "$KEYS_DIR/fullchain.pem"
scp "dkim-user@$MASTER:/etc/relays/ca.pem" "$KEYS_DIR/ca.pem"
scp "dkim-user@$MASTER:/etc/relays/ssl.key" "$KEYS_DIR/ssl.key"
scp "dkim-user@$MASTER:/etc/relays/ssl.pem" "$KEYS_DIR/ssl.pem"
scp "dkim-user@$MASTER:/etc/relays/relay.private" "$KEYS_DIR/relay.private"
scp "dkim-user@$MASTER:/etc/relays/relay.public" "$KEYS_DIR/relay.public"


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
