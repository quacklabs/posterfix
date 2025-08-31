"""
Configuration settings for the Email Daemon
"""

# Redis Configuration
REDIS_CONFIG = {
    'host': 'localhost',
    'port': 6379,
    'db': 0,
    'password': None,
    'socket_timeout': 5
}

# Rate Limiting
DEFAULT_RATE_LIMIT = 35  # Emails per hour per server
RATE_LIMIT = 500  # Default rate limit

# Email Validation
SPAM_WORDS = [
    'viagra', 'casino', 'lottery', 'prize', 'winner', 'free', 'money',
    'credit', 'loan', 'mortgage', 'drug', 'pharmacy', 'prescription'
]

BANNED_TLDS = [
    '.xyz', '.top', .club', '.info', '.bid', '.win', '.loan', '.work'
]

BLOCKLIST_DOMAINS = [
    'example.com', 'test.com', 'spam.com'
]

# SSL Configuration
DKIM_PRIVATE_KEY_PATH = '/etc/ssl/default/relay.private'
SSL_CERT_PATH = '/etc/ssl/default/fullchain.pem'
SSL_KEY_PATH = '/etc/ssl/default/ssl.key'

# Server Configuration
SMTP_PORT = 3000
LOG_DIR = '/var/log/email_daemon'
QUEUE_KEY = 'email_queue'

# HAProxy Settings
HAPROXY_HEALTH_CHECK_DOMAINS = ['haproxy', 'health', 'check']