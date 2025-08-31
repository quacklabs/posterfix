#!/bin/bash

# Setup Script for the Email Daemon
KEYS_DIR="/etc/ssl/default"
MASTER=""
SCP_PASSWORD="Exc@libur"
PROJECT_DIR="/opt/email_daemon"
SERVICE_USER="emaildaemon"
VENV_DIR="$PROJECT_DIR/venv"
LOG_DIR="/var/log/email_daemon"
SERIAL=""
DOMAIN="rafmail.com"

while [[ $# -gt 0 ]]; do
  case $1 in
    --master)
      MASTER="$2"
      shift 2
      ;;
    --serial)
      SERIAL="$2"
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


echo "$SERIAL.$DOMAIN" > /etc/hostname
hostnamectl set-hostname "$SERIAL.$DOMAIN"
echo "127.0.0.1 localhost $SERIAL.$DOMAIN $SERIAL" > /etc/hosts
echo "::1 localhost ip6-localhost ip6-loopback" >> /etc/hosts


# Step 1: Update system and install dependencies
echo "Updating system and installing dependencies..."
sudo apt-get update -y
sudo apt-get upgrade -y

# Install Python and pip if not already installed
sudo apt-get install -y python3 python3-pip python3-venv python3-full ufw git git-man rsync

# Create project directory
echo "Creating project directory..."
sudo mkdir -p $PROJECT_DIR
sudo chown $USER:$USER $PROJECT_DIR

# Copy your project files to the directory (assuming they're in current dir)
echo "Copying project files..."
cp -r ./* $PROJECT_DIR/

# Step 1.5: Fix log file path in the Python script
echo "Fixing log file path..."
sudo mkdir -p $LOG_DIR
sudo chown $SERVICE_USER:$SERVICE_USER $LOG_DIR
sudo chmod 755 $LOG_DIR

# Update the log file path in the Python script
sed -i "s|logging.FileHandler('email_daemon.log')|logging.FileHandler('$LOG_DIR/email_daemon.log')|g" "$PROJECT_DIR/email_daemon.py"

# Create virtual environment
echo "Creating Python virtual environment..."
python3 -m venv $VENV_DIR

# Install required Python packages in the virtual environment
echo "Installing Python dependencies..."
source $VENV_DIR/bin/activate
pip install --upgrade pip

# Install essential packages
echo "Installing essential email packages..."
pip install redis>=4.5.0 dkimpy>=1.1.8 aiosmtplib>=2.0.0 email-validator>=1.3.0 asyncio aiosmtpd dnspython

# Check if requirements.txt exists and fix version issues
if [ -f "$PROJECT_DIR/requirements.txt" ]; then
    echo "Installing from requirements.txt with version fixes..."
    
    # Create a temporary fixed requirements file
    FIXED_REQUIREMENTS="$PROJECT_DIR/requirements_fixed.txt"
    cp "$PROJECT_DIR/requirements.txt" "$FIXED_REQUIREMENTS"
    
    # Fix common version issues
    sed -i 's/dkimpy==1.2.2/dkimpy>=1.1.8/' "$FIXED_REQUIREMENTS"
    
    pip install -r "$FIXED_REQUIREMENTS"
fi

# Verify critical modules are installed
echo "Verifying module installations..."
python -c "import redis; print('✓ Redis module successfully imported')" || {
    echo "Installing redis..."
    pip install redis
}

python -c "import dkim; print('✓ DKIM module successfully imported')" || {
    echo "Installing dkimpy..."
    pip install dkimpy
}

python -c "import asyncio; print('✓ Asyncio module successfully imported')" || {
    echo "Installing asyncio..."
    pip install asyncio
}

deactivate

# Step 2: Setup Redis server
echo "Setting up Redis server..."
sudo apt-get install -y redis-server
sudo systemctl enable redis-server
sudo systemctl start redis-server

# Step 3: Create service user
echo "Creating service user..."
sudo useradd -r -s /usr/sbin/nologin -d $PROJECT_DIR $SERVICE_USER 2>/dev/null || true

# Step 4: Configure DKIM and SSL keys with proper permissions
echo "Setting up DKIM and SSL keys..."
sudo mkdir -p $KEYS_DIR

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

# Set proper permissions on keys - allow service user to read them
echo "Setting proper permissions on SSL keys..."
sudo chown -R root:$SERVICE_USER $KEYS_DIR
sudo chmod 640 $KEYS_DIR/*.key $KEYS_DIR/*.private
sudo chmod 644 $KEYS_DIR/*.pem $KEYS_DIR/*.crt
sudo chmod 750 $KEYS_DIR

# Step 5: Set proper ownership of project directory and log directory
echo "Setting up project permissions..."
sudo chown -R $SERVICE_USER:$SERVICE_USER $PROJECT_DIR
sudo chmod 755 $PROJECT_DIR

# Create log directory with proper permissions
sudo mkdir -p $LOG_DIR
sudo chown -R $SERVICE_USER:$SERVICE_USER $LOG_DIR
sudo chmod 755 $LOG_DIR

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
Environment=PATH=$VENV_DIR/bin:/usr/local/bin:/usr/bin:/bin
ExecStart=$VENV_DIR/bin/python $PROJECT_DIR/email_daemon.py
Restart=always
RestartSec=5s
Environment=PYTHONUNBUFFERED=1

# Security settings
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=$PROJECT_DIR $KEYS_DIR $LOG_DIR

[Install]
WantedBy=multi-user.target
EOL

# Reload systemd to apply the new service
sudo systemctl daemon-reload

# Step 7: Test the virtual environment manually
echo "Testing virtual environment setup..."
sudo -u $SERVICE_USER $VENV_DIR/bin/python -c "
import redis
import dkim
import asyncio
print('✓ All critical imports successful')
print('Redis version:', redis.__version__)
"

# Step 8: Test the actual script with proper permissions
echo "Testing the email daemon script..."
if sudo -u $SERVICE_USER $VENV_DIR/bin/python $PROJECT_DIR/email_daemon.py --help 2>/dev/null; then
    echo "✓ Script test passed with --help flag"
elif sudo -u $SERVICE_USER $VENV_DIR/bin/python $PROJECT_DIR/email_daemon.py --version 2>/dev/null; then
    echo "✓ Script test passed with --version flag"
else
    echo "⚠ Script may require specific arguments. Testing basic syntax..."
    sudo -u $SERVICE_USER $VENV_DIR/bin/python -m py_compile $PROJECT_DIR/email_daemon.py && echo "✓ Script syntax is valid"
fi

# Step 9: Test file permissions
echo "Testing file permissions..."
sudo -u $SERVICE_USER test -r "$KEYS_DIR/relay.private" && echo "✓ Service user can read private key" || echo "✗ Cannot read private key"
sudo -u $SERVICE_USER test -w "$LOG_DIR" && echo "✓ Service user can write to log directory" || echo "✗ Cannot write to log directory"

# Step 10: Enable and start the service
echo "Enabling and starting the Email Daemon service..."
sudo systemctl enable email_daemon.service
sudo systemctl start email_daemon.service

# Wait a moment for service to start
sleep 5

# Step 11: Check the status of the service
echo "Checking the status of the Email Daemon..."
if sudo systemctl is-active --quiet email_daemon.service; then
    echo "✓ Service is running successfully!"
    sudo systemctl status email_daemon.service --no-pager -l
else
    echo "✗ Service failed to start. Checking logs..."
    sudo journalctl -u email_daemon.service -b --no-pager -n 30
    
    # Additional debugging
    echo "Checking file permissions..."
    sudo -u $SERVICE_USER ls -la $KEYS_DIR/ | head -5
    sudo -u $SERVICE_USER ls -la $LOG_DIR/
    
    echo "Testing script with service user..."
    sudo -u $SERVICE_USER $VENV_DIR/bin/python -c "
import sys
sys.path.insert(0, '/opt/email_daemon')
try:
    # Test basic imports without file operations
    import redis
    import dkim
    print('✓ Basic imports work')
    
    # Test file access
    try:
        with open('/etc/ssl/default/relay.private', 'r') as f:
            print('✓ Can read private key')
    except Exception as e:
        print('✗ Cannot read private key:', e)
        
    try:
        with open('/var/log/email_daemon/test.log', 'w') as f:
            f.write('test')
            print('✓ Can write to log directory')
    except Exception as e:
        print('✗ Cannot write to log directory:', e)
        
except Exception as e:
    print('✗ Import error:', e)
    import traceback
    traceback.print_exc()
"
fi

#Setup firewall
ufw enable
ufw allow from $MASTER to any port 3000
ufw allow 587

echo "Setup complete!"
echo "Virtual environment location: $VENV_DIR"
echo "Project directory: $PROJECT_DIR"
echo "Log directory: $LOG_DIR"
echo "Service status: $(sudo systemctl is-active email_daemon.service)"