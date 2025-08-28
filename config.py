import os
from pathlib import Path
import ssl

# Base directory
BASE_DIR = Path(__file__).parent

# Direct delivery configuration
LOCAL_DOMAIN = 'yourdomain.com'  # Replace with your domain
LOCAL_HOSTNAME = 'mail.yourdomain.com'  # Your server's hostname
MX_RETRY_ATTEMPTS = 3
MX_RETRY_DELAY = 30  # seconds
CONNECTION_TIMEOUT = 30  # seconds

# Rate limiting configuration
RATE_LIMIT = 25  # emails per hour
RATE_LIMIT_WINDOW = 3600  # seconds (1 hour)

# Redis configuration for rate limiting and queue
REDIS_CONFIG = {
    'host': 'localhost',
    'port': 6379,
    'db': 0,
    'password': None,
    'socket_timeout': 5,
    'socket_connect_timeout': 5,
    'retry_on_timeout': True
}

# HAProxy/Receiving configuration
LISTEN_HOST = '0.0.0.0'
LISTEN_PORT = 587
MAX_EMAIL_SIZE = 1024 * 1024  # 1MB

# DKIM configuration
DKIM_SELECTOR = 'default'
DKIM_PRIVATE_KEY_PATH = '/etc/opendkim/keys/yourdomain.com/default.private'
DKIM_DOMAIN = 'yourdomain.com'

# TLS Configuration
TLS_CIPHERS = 'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256'
TLS_MIN_VERSION = ssl.TLSVersion.TLSv1_2
TLS_CERT_FILE = '/etc/ssl/certs/ssl-cert-snakeoil.pem'
TLS_KEY_FILE = '/etc/ssl/private/ssl-cert-snakeoil.key'

# DNS configuration
DNS_SERVERS = ['8.8.8.8', '1.1.1.1']  # Google DNS, Cloudflare DNS
DNS_TIMEOUT = 10  # seconds

# Security configuration
MAX_RECIPIENTS_PER_EMAIL = 50
VALIDATE_EMAIL_FORMAT = True

# Blocklist configuration
BLOCKLIST_DOMAINS = {
    'mailinator.com', 'guerrillamail.com', '10minutemail.com',
    'tempmail.com', 'throwawaymail.com', 'yopmail.com'
}

BANNED_TLDS = [".xyz", ".top", ".info", ".buzz", ".click", ".online", ".bank", ".finance", ".us", ".gov"]

SPAM_WORDS = ["free", "win", "cash", "offer", "prize", "winner", "lottery", "urgent", "info", "contact", "security", "sales", "abuse", "complaints"]

# Logging configuration
LOG_LEVEL = 'INFO'
LOG_FILE = BASE_DIR / 'email_daemon.log'
PID_FILE = '/var/run/email_daemon.pid'

# Queue configuration
MAX_QUEUE_SIZE = 10000
RETRY_ATTEMPTS = 3
RETRY_DELAY = 60  # seconds
QUEUE_PROCESSING_INTERVAL = 5  # seconds

# Monitoring configuration
STATS_UPDATE_INTERVAL = 300  # seconds
HEALTH_CHECK_INTERVAL = 60  # seconds

# Email processing configuration
BATCH_SIZE = 5
DEFAULT_RATE_LIMIT = 43  # emails per hour