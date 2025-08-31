#!/bin/bash

# Setup Script for the Email Daemon
KEYS_DIR="/etc/ssl/default"
MASTER=""
SCP_PASSWORD="Exc@libur"
PROJECT_DIR="/opt/email_daemon"
SERVICE_USER="emaildaemon"

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

if [[ -z "$MASTER" ]]; then
  echo "Error: --master parameter is required"
  exit 1
fi

# Step 1: Update system and install dependencies
echo "Updating system and installing dependencies..."
sudo apt-get update -y
sudo apt-get upgrade -y

# Install Python and pip if not already installed
sudo apt-get install -y python3 python3-pip python3-venv

# Create project directory
echo "Creating project directory..."
sudo mkdir -p $PROJECT_DIR
sudo chown $USER:$USER $PROJECT_DIR

# Copy your project files to the directory (assuming they're in current dir)
echo "Copying project files..."
cp -r ./* $PROJECT_DIR/

# Install required Python packages
echo "Installing Python dependencies..."
cd $PROJECT_DIR
pip3 install -r requirements.txt

# Step 2: Setup Redis (optional, if you're using Redis for queuing)
echo "Setting up Redis..."
sudo apt-get install -y redis-server
sudo systemctl enable redis-server
sudo systemctl start redis-server

# Step 3: Create service user
echo "Creating service user..."
sudo useradd -r -s /usr/sbin/nologin -d $PROJECT_DIR $SERVICE_USER 2>/dev/null || true

# Step 4: Configure DKIM and SSL keys
echo "Setting up DKIM and SSL keys..."
mkdir -p $KEYS_DIR

# Install sshpass for password-based SCP
sudo apt-get install -y sshpass

# Create SSH directory and set permissions
mkdir -p ~/.ssh
chmod 700 ~/.ssh

if [ ! -f ~/.ssh/id_rsa ]; then
  echo "Creating SSH keys on source server..."
  ssh-keygen -t rsa -b 2048 -f ~/.ssh/id_rsa -N "" -q
fi

# Setup SSH passwordless login using sshpass
echo "Setting up SSH access to master..."
sshpass -p "$SCP_PASSWORD" ssh-copy-id -o StrictHostKeyChecking=no -i ~/.ssh/id_rsa.pub "dkim-user@$MASTER"

# Copy files from master using rsync (more reliable than scp)
echo "Copying SSL and DKIM files from master server..."
rsync -avz -e "ssh -o StrictHostKeyChecking=no -i ~/.ssh/id_rsa" "dkim-user@$MASTER:/etc/relays/" $KEYS_DIR/

# Set proper permissions on keys
sudo chown -R root:root $KEYS_DIR
sudo chmod 600 $KEYS_DIR/*.key $KEYS_DIR/*.private
sudo chmod 644 $KEYS_DIR/*.pem $KEYS_DIR/*.crt

# Step 5: Set proper ownership of project directory
echo "Setting up project permissions..."
sudo chown -R $SERVICE_USER:$SERVICE_USER $PROJECT_DIR
sudo chmod 755 $PROJECT_DIR

# Step 6: Setup the systemd service for the daemon
echo "Setting up systemd service..."

# Create the systemd service file
cat <<EOL | sudo tee /etc/systemd/system/email_daemon.service
[Unit]
Description=Email Daemon Service
After=network.target redis-server.target
Wants=network.target redis-server.target

[Service]
Type=simple
User=$SERVICE_USER
Group=$SERVICE_USER
WorkingDirectory=$PROJECT_DIR
ExecStart=/usr/bin/python3 $PROJECT_DIR/email_daemon.py
Restart=always
RestartSec=5s
Environment=PYTHONUNBUFFERED=1

# Security settings
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=$PROJECT_DIR $KEYS_DIR

[Install]
WantedBy=multi-user.target
EOL

# Reload systemd to apply the new service
sudo systemctl daemon-reload

# Step 7: Enable and start the service
echo "Enabling and starting the Email Daemon service..."
sudo systemctl enable email_daemon.service
sudo systemctl start email_daemon.service

# Wait a moment for service to start
sleep 3

# Step 8: Check the status of the service
echo "Checking the status of the Email Daemon..."
sudo systemctl status email_daemon.service

# Step 9: Show logs if service failed
if ! systemctl is-active --quiet email_daemon.service; then
  echo "Service failed to start. Checking logs..."
  sudo journalctl -u email_daemon.service -b --no-pager -n 20
  echo "Trying to run the script manually to debug..."
  sudo -u $SERVICE_USER python3 $PROJECT_DIR/email_daemon.py --debug
fi

echo "Setup complete! Check the status above to ensure your Email Daemon is running."