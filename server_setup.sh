#!/bin/bash

DOMAIN=""
RELAY_LIST=""
PASSWORD=""
CERT_DIR="/etc/ssl/default"
KEYS_DIR="/etc/dkim"
SHARED_DIR="/etc/relays"

# Parse command-line arguments
while [[ $# -gt 0 ]]; do
  case $1 in
    --domain)
      DOMAIN="$2"
      shift 2
      ;;
    --relay_list)
      RELAY_LIST="$2"
      shift 2
      ;;
    --password)
      PASSWORD="$2"
      shift 2
      ;;
    *)
      echo "Unknown option $1"
      exit 1
      ;;
  esac
done

# Check if DOMAIN, password and relay_list are provided
if [[ -z "$DOMAIN" ]]; then
  echo "Error: --domain is required"
  exit 1
fi

# Check if DOMAIN and relay_list are provided
if [[ -z "$PASSWORD" ]]; then
  echo "Error: --password is required"
  exit 1
fi

if [[ -z "$RELAY_LIST" ]]; then
  echo "Error: --relay_list is required"
  exit 1
fi

# Check if the relay_list file exists
if [[ ! -f "$RELAY_LIST" ]]; then
  echo "Error: The file '$RELAY_LIST' does not exist."
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
echo "postfix postfix/mailname string $DOMAIN" | debconf-set-selections
echo "postfix postfix/main_mailer_type string 'Internet Site'" | debconf-set-selections

# Install all required packages
apt install ufw postfix haproxy cockpit mysql-server mysql-client php php-cli php-common php-mysql php-json php-gd php-imagick php-intl nginx php-fpm php-xml php-curl php-mbstring php-zip php-bcmath apache2 libapache2-mod-php dovecot-imapd dovecot-pop3d dovecot-mysql socat -y

# Enable and start Cockpit
systemctl enable --now cockpit.socket

# Set hostname
echo "mail.$DOMAIN" > /etc/hostname
hostnamectl set-hostname mail
echo "127.0.0.1 localhost $DOMAIN" > /etc/hosts

# Configure Postfix for incoming (local delivery) and relay outgoing to HAProxy
postconf -e "myhostname = $DOMAIN"
postconf -e "mydestination = $DOMAIN, localhost.$DOMAIN, localhost"
postconf -e "inet_interfaces = all"
postconf -e "relayhost = [127.0.0.1]:2525"
postconf -e "mynetworks = 127.0.0.0/8 [::ffff:127.0.0.0]/104 [::1]/128"
postconf -e "home_mailbox = Maildir/"

systemctl restart postfix

# Configure Dovecot for IMAP
cat <<EOF > /etc/dovecot/conf.d/10-mail.conf
mail_location = maildir:~/Maildir
EOF

cat <<EOF > /etc/dovecot/conf.d/10-auth.conf
disable_plaintext_auth = no
auth_mechanisms = plain login
!include auth-system.conf.ext
EOF

# Enable Roundcube site and disable default site
a2dissite 000-default.conf
a2enmod ssl
a2enmod rewrite

# Create ACME challenge directory
mkdir -p /var/www/acme-challenge
chown www-data:www-data /var/www/acme-challenge


# Restart services
systemctl enable ufw
systemctl restart postfix
systemctl restart dovecot
systemctl restart mysql
systemctl restart apache2
systemctl restart haproxy

# Basic firewall (allow SSH, HTTP/HTTPS for Cockpit and Webmail, SMTP incoming, IMAP)
ufw allow 22
ufw allow 80
ufw allow 443
ufw allow 9090 
ufw block 25
ufw allow 143 
ufw allow 993
ufw allow 110
ufw allow 995
ufw allow 9000
ufw allow 587
ufw --force enable

# Get server IP address
SERVER_IP=$(hostname -I | awk '{print $1}')

# Install acme.sh from GitHub
echo "Installing acme.sh..."
cd /root
curl https://get.acme.sh | sh -s email=admin@${DOMAIN}
# source ~/.bashrc


WILDCARD="*.$DOMAIN"
# Issue Let's Encrypt certificate
echo "Requesting wildcard SSL certificate for $DOMAIN and $WILDCARD..."
mkdir -p $CERT_DIR
/root/.acme.sh/acme.sh --set-default-ca --server letsencrypt
sudo systemctl stop apache2
sudo systemctl stop nginx


if [ -f "/root/.acme.sh/$DOMAIN/$DOMAIN.cer" ]; then
    echo "Attempting to install the certificate..."
    /root/.acme.sh/acme.sh --renew -d $DOMAIN -d $WILDCARD --standalone --force

    /root/.acme.sh/acme.sh --install-cert -d $DOMAIN \
        --ca-file $CERT_DIR/ca.pem \
        --cert-file $CERT_DIR/$DOMAIN.pem \
        --key-file $CERT_DIR/$DOMAIN.key \
        --fullchain-file $CERT_DIR/fullchain.pem \
        --reloadcmd "systemctl reload apache2 && systemctl restart dovecot && systemctl restart postfix"
else
    rm -rf /root/.acme.sh/$DOMAIN/*
    echo "Please add the following DNS TXT records for domain verification:"

    /root/.acme.sh/acme.sh --issue -d $DOMAIN -d $WILDCARD --keylength 2048 --standalone --force 


    # Check if the certificate has been issued successfully
    if [ -f "/root/.acme.sh/$DOMAIN/$DOMAIN.cer" ]; then
      echo "Certificate issued successfully! Installing the certificate..."
      /root/.acme.sh/acme.sh --install-cert -d $DOMAIN \
        --ca-file $CERT_DIR/ca.pem \
        --cert-file $CERT_DIR/$DOMAIN.pem \
        --key-file $CERT_DIR/$DOMAIN.key \
        --fullchain-file $CERT_DIR/fullchain.pem \
        --reloadcmd "systemctl reload apache2 && systemctl restart dovecot && systemctl restart postfix"

    else
      echo "Error: Certificate issuance failed. Please check your DNS records and try again."
      exit 1
    fi
fi


#Setup DKIM
mkdir -p "$KEYS_DIR"
cd "$KEYS_DIR" || exit

openssl genpkey -algorithm RSA -out "relay.private" -pkeyopt rsa_keygen_bits:2048
openssl rsa -in "relay.private" -pubout -out "relay.public"

PUBLIC_KEY=$(cat "relay.public" | grep -v "-----" | tr -d '\n')
TXT_RECORD="relay._domainkey.${DOMAIN} IN TXT (\"v=DKIM1; k=rsa; p=${PUBLIC_KEY}\")"
echo "### Add the following DNS TXT record to your DNS configuration ###"
echo "$TXT_RECORD"
echo ""
cd ~


# Configure HAProxy for TCP load balancing outgoing to relays (replace relay IPs)
cat $CERT_DIR/fullchain.pem > /etc/haproxy/ca.crt
cat $CERT_DIR/$DOMAIN.key > /etc/haproxy/ca.crt.key
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
    bind *:2525
    default_backend relay_servers

backend relay_servers
    balance roundrobin
    option smtpchk EHLO $DOMAIN
EOF

line_number=1
# Loop through the relay_list file and add server lines dynamically
while IFS= read -r ip; do
    echo "    server mx${line_number} ${ip}:587 ssl ca-file /etc/ssl/default/ca.pem crt /etc/ssl/default/fullchain.pem verify required check send-proxy" >> /etc/haproxy/haproxy.cfg
    ((line_number++))  # Increment the line number counter
done < "$RELAY_LIST"

# Adding stats page for monitoring
cat <<EOF >> /etc/haproxy/haproxy.cfg

# Stats page
listen stats
    bind *:9000
    mode http
    stats enable
    stats uri /stats
    stats refresh 10s
    stats auth admin:Password
EOF

systemctl restart haproxy


# Configure Dovecot to use Let's Encrypt certificates
cat <<EOF > /etc/dovecot/conf.d/10-ssl.conf
ssl = yes
ssl_cert = <$CERT_DIR/fullchain.pem
ssl_key = <$CERT_DIR/$DOMAIN.key
ssl_min_protocol = TLSv1.2
ssl_cipher_list = ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384
ssl_prefer_server_ciphers = yes
EOF

# Configure Postfix to use Let's Encrypt certificates
postconf -e "smtpd_tls_cert_file = $CERT_DIR/$DOMAIN.pem"
postconf -e "smtpd_tls_key_file = $CERT_DIR/$DOMAIN.key"
postconf -e "smtp_tls_CAfile = $CERT_DIR/fullchain.pem"
postconf -e "smtpd_tls_security_level = may"

# Configure Cockpit to use Let's Encrypt certificates
mkdir -p /etc/cockpit/ws-certs.d
sudo cat $CERT_DIR/fullchain.pem $CERT_DIR/$DOMAIN.key \
    | sudo tee /etc/cockpit/ws-certs.d/rafmail.cert

cat /dev/null > /etc/cockpit/disallowed-users

#Setup keys for relay servers
useradd -m -s /bin/bash "dkim-user"
echo "dkim-user:Exc@libur" | chpasswd
usermod -s /usr/sbin/nologin "dkim-user"

cat $CERT_DIR/fullchain.pem > $SHARED_DIR/fullchain.pem
cat $CERT_DIR/ca.pem > $SHARED_DIR/ca.pem
cat $CERT_DIR/$DOMAIN.key > $SHARED_DIR/ssl.key
cat $CERT_DIR/$DOMAIN.pem > $SHARED_DIR/ssl.pem
cat $KEYS_DIR/relay.private > $SHARED_DIR/relay.private
cat $KEY_DIR/relay.public > $SHARED_DIR/relay.public

chown -R dkim-user:dkim-user $SHARED_DIR
chmod 750 $SHARED_DIR

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
echo "Cockpit Admin Interface: https://$DOMAIN:9090"
echo "Cockpit Admin Interface: https://${SERVER_IP}:9090"
echo "Roundcube Webmail: https://mail.$DOMAIN/"
echo "Roundcube Webmail: https://webmail.$DOMAIN/"
echo "Roundcube Webmail: https://${SERVER_IP}/"
echo "================================================================"
echo "TEST USER ACCOUNT:"
echo "================================================================"
echo "Username: testuser"
echo "Password: $TEST_USER_PASSWORD"
echo "Email: testuser@$DOMAIN"
echo "================================================================"
echo "SERVER INFORMATION:"
echo "================================================================"
echo "Hostname: mail.$DOMAIN"
echo "IP Address: $SERVER_IP"
echo "Let's Encrypt Certificates: $CERT_DIR"
echo "================================================================"
echo "EMAIL CLIENT CONFIGURATION:"
echo "================================================================"
echo "IMAP Server: $DOMAIN (port 143 STARTTLS or 993 SSL)"
echo "SMTP Server: $DOMAIN (port 25 STARTTLS or 587 SSL)"
echo "Username: your_username@$DOMAIN"
echo "================================================================"
echo "NEXT STEPS:"
echo "================================================================"
echo "1. Configure DNS A records for:"
echo "  - DOMAIN -> $SERVER_IP"
echo "  - webmail.$DOMAIN -> $SERVER_IP"
echo "  - DKIM -> $TXT_RECORD"
echo "2. Certificate auto-renewal is set up via systemd timer"
echo "3. Test SSL configuration:"
echo "  openssl s_client -connect mail.$DOMAIN:443 -servername mail.$DOMAIN"
echo "================================================================"

# Save credentials to a secure file
cat > /root/mail_server_credentials.txt <<EOF
MySQL Root Password: $MYSQL_ROOT_PASSWORD
Test User: testuser / $TEST_USER_PASSWORD
Webmail URL: https://mail.$DOMAIN/
Cockpit URL: https://$DOMAIN:9090/
SSL Certificates: $CERT_DIR
Certificate Auto-renewal: systemctl status acme-renew.timer
Cluster Health: https://$DOMAIN:9000
EOF

chmod 600 /root/mail_server_credentials.txt
echo "Credentials saved to: /root/mail_server_credentials.txt"

# Test SSL configuration
echo "Testing SSL configuration..."
sleep 5
curl -I https://localhost/ --insecure >/dev/null 2>&1 && echo "Webmail SSL: OK" || echo "Webmail SSL: Check configuration"
echo "Setup complete! Let's Encrypt certificates are installed and configured for all services."