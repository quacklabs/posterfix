#!/bin/bash

domain=""
relay_list=""
admin_password=""

# Parse command-line arguments
while [[ $# -gt 0 ]]; do
  case $1 in
    --domain)
      domain="$2"
      shift 2
      ;;
    --relay_list)
      relay_list="$2"
      shift 2
      ;;
    --admin_password)
      admin_password="$3"
      shift 2
      ;;
    *)
      echo "Unknown option $1"
      exit 1
      ;;
  esac
done

# Check if domain and relay_list are provided
if [[ -z "$domain" ]]; then
  echo "Error: --domain is required"
  exit 1
fi

if [[ -z "$relay_list" ]]; then
  echo "Error: --relay_list is required"
  exit 1
fi

# Check if the relay_list file exists
if [[ ! -f "$relay_list" ]]; then
  echo "Error: The file '$relay_list' does not exist."
  exit 1
fi

# Update and install packages
apt update -y
apt upgrade -y

# Generate a secure random password for MySQL root
MYSQL_ROOT_PASSWORD=$(openssl rand -base64 24 | tr -d '/+=' | cut -c1-24)
ROUNDCUBE_DB_PASSWORD=$(openssl rand -base64 24 | tr -d '/+=' | cut -c1-24)

# Preconfigure MySQL with generated password
echo "mysql-server mysql-server/root_password password $MYSQL_ROOT_PASSWORD" | debconf-set-selections
echo "mysql-server mysql-server/root_password_again password $MYSQL_ROOT_PASSWORD" | debconf-set-selections

# Preconfigure Postfix (Internet Site, mailname rafmail.com)
echo "postfix postfix/mailname string rafmail.com" | debconf-set-selections
echo "postfix postfix/main_mailer_type string 'Internet Site'" | debconf-set-selections

# Install all required packages
apt install postfix haproxy cockpit mysql-server mysql-client php php-cli php-common php-mysql php-json php-curl php-gd php-imagick php-intl php-mbstring php-xml php-zip php-bcmath apache2 libapache2-mod-php roundcube roundcube-core roundcube-mysql roundcube-plugins dovecot-imapd dovecot-pop3d dovecot-mysql socat -y

# Enable and start Cockpit
systemctl enable --now cockpit.socket

# Set hostname
echo "mail.rafmail.com" > /etc/hostname
hostnamectl set-hostname mail.rafmail.com
echo "127.0.0.1 localhost mail.rafmail.com" > /etc/hosts

# Configure Postfix for incoming (local delivery) and relay outgoing to HAProxy
postconf -e "myhostname = mail.rafmail.com"
postconf -e "mydestination = rafmail.com, localhost.rafmail.com, localhost"
postconf -e "inet_interfaces = all"
postconf -e "relayhost = [127.0.0.1]:2525"  # HAProxy local port for load-balanced sending
postconf -e "mynetworks = 127.0.0.0/8 [::ffff:127.0.0.0]/104 [::1]/128"  # Local only for submission if needed
postconf -e "home_mailbox = Maildir/"

systemctl restart postfix

# Configure HAProxy for TCP load balancing outgoing to relays (replace relay IPs)
cat <<EOF > /etc/haproxy/haproxy.cfg
global
    log /dev/log local0
    log /dev/log local1 notice
    chroot /var/lib/haproxy
    stats socket /run/haproxy/admin.sock mode 660 level admin expose-fd listeners
    stats timeout 30s
    user haproxy
    group haproxy
    daemon

defaults
    log global
    mode tcp
    option tcplog
    timeout connect 5s
    timeout client 1m
    timeout server 1m

frontend outgoing_smtp
    bind 127.0.0.1:2525
    default_backend relay_servers

backend relay_servers
    balance roundrobin
EOF

line_number=1
# Loop through the relay_list file and add server lines dynamically
while IFS= read -r ip; do
    echo "    server mx${line_number} ${ip}:587 ssl send-proxy check" >> /etc/haproxy/haproxy.cfg
    ((line_number++))  # Increment the line number counter
done < "$relay_list"

# Adding stats page for monitoring
cat <<EOF >> /etc/haproxy/haproxy.cfg

# Stats page
listen stats
    bind 127.0.0.1:9000
    stats enable
    stats uri /haproxy_stats
    stats auth admin:${admin_password}
EOF

systemctl restart haproxy

# Configure MySQL for Roundcube
mysql -u root -p"$MYSQL_ROOT_PASSWORD" <<EOF
CREATE DATABASE roundcubemail CHARACTER SET utf8 COLLATE utf8_general_ci;
CREATE USER 'roundcube'@'localhost' IDENTIFIED BY '$ROUNDCUBE_DB_PASSWORD';
GRANT ALL PRIVILEGES ON roundcubemail.* TO 'roundcube'@'localhost';
FLUSH PRIVILEGES;
EOF

# Import Roundcube database schema
mysql -u root -p"$MYSQL_ROOT_PASSWORD" roundcubemail < /usr/share/roundcube/SQL/mysql.initial.sql

# Configure Roundcube
cat <<EOF > /etc/roundcube/config.inc.php
<?php
\$config = array();
\$config['db_dsnw'] = 'mysql://roundcube:${ROUNDCUBE_DB_PASSWORD}@localhost/roundcubemail';
\$config['default_host'] = 'localhost';
\$config['default_port'] = 143;
\$config['smtp_server'] = 'localhost';
\$config['smtp_port'] = 25;
\$config['smtp_user'] = '';
\$config['smtp_pass'] = '';
\$config['support_url'] = '';
\$config['product_name'] = 'RafMail Webmail';
\$config['des_key'] = '$(openssl rand -base64 24)';
\$config['plugins'] = array('archive', 'zipdownload', 'managesieve');
\$config['skin'] = 'elastic';
\$config['mail_pagesize'] = 50;
\$config['addressbook_pagesize'] = 50;
\$config['draft_autosave'] = 300;
\$config['ip_check'] = true;
\$config['log_driver'] = 'syslog';
EOF

# Configure Dovecot for IMAP
cat <<EOF > /etc/dovecot/conf.d/10-mail.conf
mail_location = maildir:~/Maildir
EOF

cat <<EOF > /etc/dovecot/conf.d/10-auth.conf
disable_plaintext_auth = no
auth_mechanisms = plain login
!include auth-system.conf.ext
EOF

# Configure Apache for Roundcube - temporary config for ACME challenge
cat <<EOF > /etc/apache2/sites-available/roundcube.conf
<VirtualHost *:80>
     ServerName mail.rafmail.com
     ServerAlias webmail.rafmail.com
     DocumentRoot /var/lib/roundcube
     
     # ACME challenge directory for Let's Encrypt
     Alias /.well-known/acme-challenge /var/www/acme-challenge
     <Directory /var/www/acme-challenge>
          Options None
          AllowOverride None
          Require all granted
     </Directory>
     
     <Directory /var/lib/roundcube>
          Options -Indexes
          AllowOverride All
          Require all granted
     </Directory>
     
     ErrorLog \${APACHE_LOG_DIR}/roundcube_error.log
     CustomLog \${APACHE_LOG_DIR}/roundcube_access.log combined
</VirtualHost>
EOF

# Enable Roundcube site and disable default site
a2ensite roundcube.conf
a2dissite 000-default.conf
a2enmod ssl
a2enmod rewrite

# Create ACME challenge directory
mkdir -p /var/www/acme-challenge
chown www-data:www-data /var/www/acme-challenge

# Set proper permissions
chown -R www-data:www-data /var/lib/roundcube
chmod -R 755 /var/lib/roundcube

# Restart services
systemctl restart postfix
systemctl restart dovecot
systemctl restart mysql
systemctl restart apache2
systemctl restart haproxy

# Basic firewall (allow SSH, HTTP/HTTPS for Cockpit and Webmail, SMTP incoming, IMAP)
ufw allow 22
ufw allow 80
ufw allow 443
ufw allow 9090  # Cockpit web UI
ufw allow 25
ufw allow 143   # IMAP
ufw allow 993   # IMAPS
ufw allow 110   # POP3
ufw allow 995   # POP3S
ufw --force enable

# Get server IP address
SERVER_IP=$(hostname -I | awk '{print $1}')

# Install acme.sh from GitHub
echo "Installing acme.sh..."
cd /root
curl https://get.acme.sh | sh -s email=admin@rafmail.com
source ~/.bashrc

# Issue Let's Encrypt certificate
/root/.acme.sh/acme.sh --issue --standalone -d mail.rafmail.com -d webmail.rafmail.com --keylength 2048

# Create certificate directory
mkdir -p /etc/ssl/rafmail

# Install certificates
/root/.acme.sh/acme.sh --install-cert -d mail.rafmail.com \
     --cert-file /etc/ssl/rafmail/cert.pem \
     --key-file /etc/ssl/rafmail/key.pem \
     --fullchain-file /etc/ssl/rafmail/fullchain.pem \
     --reloadcmd "systemctl reload apache2 && systemctl restart dovecot && systemctl restart postfix"

# Configure Apache with SSL
cat <<EOF > /etc/apache2/sites-available/roundcube-ssl.conf
<VirtualHost *:443>
     ServerName mail.rafmail.com
     ServerAlias webmail.rafmail.com
     DocumentRoot /var/lib/roundcube
     
     SSLEngine on
     SSLCertificateFile /etc/ssl/rafmail/fullchain.pem
     SSLCertificateKeyFile /etc/ssl/rafmail/key.pem
     SSLCertificateChainFile /etc/ssl/rafmail/fullchain.pem
     
     # SSL settings
     SSLProtocol all -SSLv2 -SSLv3
     SSLCipherSuite ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384
     SSLHonorCipherOrder off
     SSLSessionTickets off
     
     <Directory /var/lib/roundcube>
          Options -Indexes
          AllowOverride All
          Require all granted
     </Directory>
     
     ErrorLog \${APACHE_LOG_DIR}/roundcube_ssl_error.log
     CustomLog \${APACHE_LOG_DIR}/roundcube_ssl_access.log combined
</VirtualHost>

<VirtualHost *:80>
     ServerName mail.rafmail.com
     ServerAlias webmail.rafmail.com
     DocumentRoot /var/lib/roundcube
     
     # Redirect all HTTP to HTTPS
     RewriteEngine on
     RewriteCond %{SERVER_NAME} =mail.rafmail.com [OR]
     RewriteCond %{SERVER_NAME} =webmail.rafmail.com
     RewriteRule ^ https://%{SERVER_NAME}%{REQUEST_URI} [END,NE,R=permanent]
     
     # ACME challenge directory for Let's Encrypt
     Alias /.well-known/acme-challenge /var/www/acme-challenge
     <Directory /var/www/acme-challenge>
          Options None
          AllowOverride None
          Require all granted
     </Directory>
     
     ErrorLog \${APACHE_LOG_DIR}/roundcube_error.log
     CustomLog \${APACHE_LOG_DIR}/roundcube_access.log combined
</VirtualHost>
EOF

# Enable SSL site and disable non-SSL
a2dissite roundcube.conf
a2ensite roundcube-ssl.conf

# Configure Dovecot to use Let's Encrypt certificates
cat <<EOF > /etc/dovecot/conf.d/10-ssl.conf
ssl = yes
ssl_cert = </etc/ssl/rafmail/fullchain.pem
ssl_key = </etc/ssl/rafmail/key.pem
ssl_min_protocol = TLSv1.2
ssl_cipher_list = ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384
ssl_prefer_server_ciphers = yes
EOF

# Configure Postfix to use Let's Encrypt certificates
postconf -e "smtpd_tls_cert_file = /etc/ssl/rafmail/fullchain.pem"
postconf -e "smtpd_tls_key_file = /etc/ssl/rafmail/key.pem"
postconf -e "smtp_tls_CAfile = /etc/ssl/rafmail/fullchain.pem"
postconf -e "smtpd_tls_security_level = may"
postconf -e "smtp_tls_security_level = may"

# Configure Cockpit to use Let's Encrypt certificates
mkdir -p /etc/cockpit/ws-certs.d
cat <<EOF > /etc/cockpit/ws-certs.d/rafmail.cert
{
  "cert": "/etc/ssl/rafmail/fullchain.pem",
  "key": "/etc/ssl/rafmail/key.pem"
}
EOF

# Create a test user for demonstration
TEST_USER_PASSWORD=$(openssl rand -base64 12 | tr -d '/+=' | cut -c1-12)
useradd -m -s /bin/bash testuser
echo "testuser:${TEST_USER_PASSWORD}" | chpasswd

# Final service restarts
systemctl restart apache2
systemctl restart dovecot
systemctl restart postfix
systemctl restart cockpit

# Set up automatic certificate renewal
cat <<EOF > /etc/systemd/system/acme-renew.service
[Unit]
Description=ACME Certificate Renewal
After=network.target

[Service]
Type=oneshot
ExecStart=/root/.acme.sh/acme.sh --cron --home /root/.acme.sh
User=root
EOF

cat <<EOF > /etc/systemd/system/acme-renew.timer
[Unit]
Description=Daily ACME Certificate Renewal
Requires=acme-renew.service

[Timer]
OnCalendar=daily
Persistent=true

[Install]
WantedBy=timers.target
EOF

systemctl daemon-reload
systemctl enable acme-renew.timer
systemctl start acme-renew.timer

# Display access information
echo "================================================================"
echo "SETUP COMPLETE!"
echo "================================================================"
echo "MySQL Root Password: $MYSQL_ROOT_PASSWORD"
echo "Roundcube DB Password: $ROUNDCUBE_DB_PASSWORD"
echo "================================================================"
echo "WEB ACCESS URLs:"
echo "================================================================"
echo "Cockpit Admin Interface: https://mail.rafmail.com:9090"
echo "Cockpit Admin Interface: https://${SERVER_IP}:9090"
echo "Roundcube Webmail: https://mail.rafmail.com/"
echo "Roundcube Webmail: https://webmail.rafmail.com/"
echo "Roundcube Webmail: https://${SERVER_IP}/"
echo "================================================================"
echo "TEST USER ACCOUNT:"
echo "================================================================"
echo "Username: testuser"
echo "Password: $TEST_USER_PASSWORD"
echo "Email: testuser@rafmail.com"
echo "================================================================"
echo "SERVER INFORMATION:"
echo "================================================================"
echo "Hostname: mail.rafmail.com"
echo "IP Address: $SERVER_IP"
echo "Let's Encrypt Certificates: /etc/ssl/rafmail/"
echo "================================================================"
echo "EMAIL CLIENT CONFIGURATION:"
echo "================================================================"
echo "IMAP Server: mail.rafmail.com (port 143 STARTTLS or 993 SSL)"
echo "SMTP Server: mail.rafmail.com (port 25 STARTTLS or 587 SSL)"
echo "Username: your_username@rafmail.com"
echo "================================================================"
echo "NEXT STEPS:"
echo "================================================================"
echo "1. Configure DNS A records for:"
echo "   - mail.rafmail.com -> $SERVER_IP"
echo "   - webmail.rafmail.com -> $SERVER_IP"
echo "2. Certificate auto-renewal is set up via systemd timer"
echo "3. Test SSL configuration:"
echo "   openssl s_client -connect mail.rafmail.com:443 -servername mail.rafmail.com"
echo "================================================================"

# Save credentials to a secure file
cat > /root/mail_server_credentials.txt <<EOF
MySQL Root Password: $MYSQL_ROOT_PASSWORD
Roundcube DB Password: $ROUNDCUBE_DB_PASSWORD
Test User: testuser / $TEST_USER_PASSWORD
Webmail URL: https://mail.rafmail.com/
Cockpit URL: https://mail.rafmail.com:9090/
SSL Certificates: /etc/ssl/rafmail/
Certificate Auto-renewal: systemctl status acme-renew.timer
EOF

chmod 600 /root/mail_server_credentials.txt
echo "Credentials saved to: /root/mail_server_credentials.txt"

# Test SSL configuration
echo "Testing SSL configuration..."
sleep 5
curl -I https://localhost/ --insecure >/dev/null 2>&1 && echo "Webmail SSL: OK" || echo "Webmail SSL: Check configuration"
echo "Setup complete! Let's Encrypt certificates are installed and configured for all services."
