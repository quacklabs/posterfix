#!/bin/bash

# Setup Script for the Email Daemon
KEYS_DIR="/etc/ssl/default"
MASTER=""
SCP_PASSWORD="Exc@libur"
PROJECT_DIR="/opt/email_daemon"
SERVICE_USER="emaildaemon"
VENV_DIR="$PROJECT_DIR/venv"

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
sudo apt-get install -y python3 python3-pip python3-venv python3-full

# Create project directory
echo "Creating project directory..."
sudo mkdir -p $PROJECT_DIR
sudo chown $USER:$USER $PROJECT_DIR

# Copy your project files to the directory (assuming they're in current dir)
echo "Copying project files..."
cp -r ./* $PROJECT_DIR/

# Step 1.5: Fix asyncore import issue in the Python script
echo "Checking for asyncore import issues..."
if grep -q "import asyncore" "$PROJECT_DIR/email_daemon.py"; then
    echo "Found asyncore import. Fixing for Python 3.12 compatibility..."
    
    # Create backup
    cp "$PROJECT_DIR/email_daemon.py" "$PROJECT_DIR/email_daemon.py.backup"
    
    # Replace asyncore with asyncio alternatives
    sed -i 's/import asyncore/# import asyncore  # Removed in Python 3.12/g' "$PROJECT_DIR/email_daemon.py"
    sed -i 's/asyncore\./asyncio./g' "$PROJECT_DIR/email_daemon.py"
    
    # Add asyncio import if not present
    if ! grep -q "import asyncio" "$PROJECT_DIR/email_daemon.py"; then
        sed -i '1i import asyncio' "$PROJECT_DIR/email_daemon.py"
    fi
    
    echo "Asyncore imports fixed for Python 3.12"
fi

# Create virtual environment
echo "Creating Python virtual environment..."
python3 -m venv $VENV_DIR

# Install required Python packages in the virtual environment
echo "Installing Python dependencies..."
source $VENV_DIR/bin/activate
pip install --upgrade pip

# Install essential packages
echo "Installing essential email packages..."
pip install redis>=4.5.0 dkimpy>=1.1.8 aiosmtplib>=2.0.0 email-validator>=1.3.0 asyncio aiosmtpd

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

# Step 4: Configure DKIM and SSL keys
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
ReadWritePaths=$PROJECT_DIR $KEYS_DIR

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
print('DKIM version:', dkim.__version__)
"

# Step 8: Test the actual script
echo "Testing the email daemon script..."
if sudo -u $SERVICE_USER $VENV_DIR/bin/python $PROJECT_DIR/email_daemon.py --help 2>/dev/null; then
    echo "✓ Script test passed with --help flag"
elif sudo -u $SERVICE_USER $VENV_DIR/bin/python $PROJECT_DIR/email_daemon.py --version 2>/dev/null; then
    echo "✓ Script test passed with --version flag"
else
    echo "⚠ Script may require specific arguments. Testing basic syntax..."
    sudo -u $SERVICE_USER $VENV_DIR/bin/python -m py_compile $PROJECT_DIR/email_daemon.py && echo "✓ Script syntax is valid"
fi

# Step 9: Enable and start the service
echo "Enabling and starting the Email Daemon service..."
sudo systemctl enable email_daemon.service
sudo systemctl start email_daemon.service

# Wait a moment for service to start
sleep 5

# Step 10: Check the status of the service
echo "Checking the status of the Email Daemon..."
if sudo systemctl is-active --quiet email_daemon.service; then
    echo "✓ Service is running successfully!"
    sudo systemctl status email_daemon.service --no-pager -l
else
    echo "✗ Service failed to start. Checking logs..."
    sudo journalctl -u email_daemon.service -b --no-pager -n 30
    
    # Additional debugging
    echo "Checking script for import issues..."
    sudo -u $SERVICE_USER $VENV_DIR/bin/python -c "
import sys
sys.path.insert(0, '/opt/email_daemon')
try:
    from email_daemon import main
    print('✓ Script can be imported successfully')
except Exception as e:
    print('✗ Import error:', e)
    import traceback
    traceback.print_exc()
"
fi

echo "Setup complete!"
echo "Virtual environment location: $VENV_DIR"
echo "Project directory: $PROJECT_DIR"
echo "Service status: $(sudo systemctl is-active email_daemon.service)"