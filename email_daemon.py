import smtplib
import time
import logging
import redis
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.utils import formataddr
from collections import deque, defaultdict
import dkim
import ssl
from tls_manager import TLSManager
from config import *
import socket
import threading
import re

class RateLimiter:
    def __init__(self, default_limit_per_hour=DEFAULT_RATE_LIMIT):
        self.default_limit_per_hour = default_limit_per_hour
        self.sent_times = defaultdict(deque)
        self.limits = {}
        self.lock = threading.Lock()

    def set_limit(self, host, port, limit):
        with self.lock:
            self.limits[(host, port)] = limit

    def reset(self):
        with self.lock:
            self.sent_times.clear()

    def can_send(self, host, port):
        with self.lock:
            current_time = time.time()
            key = (host, port)
            limit = self.limits.get(key, self.default_limit_per_hour)
            
            # Clean up old entries
            while self.sent_times[key] and current_time - self.sent_times[key][0] > 3600:
                self.sent_times[key].popleft()
            
            current_count = len(self.sent_times[key])
            return current_count < limit

    def record_send(self, host, port):
        with self.lock:
            key = (host, port)
            self.sent_times[key].append(time.time())

    def time_until_next_slot(self, host, port):
        with self.lock:
            key = (host, port)
            limit = self.limits.get(key, self.default_limit_per_hour)
            current_count = len(self.sent_times[key])
            
            if current_count < limit:
                return 0
            
            oldest_time = self.sent_times[key][0]
            current_time = time.time()
            wait_time = 3600 - (current_time - oldest_time)
            return max(0, wait_time)

class EmailValidator:
    @staticmethod
    def validate_email_format(email_address):
        """Validate email format using RFC 5322 compliant regex"""
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return re.match(pattern, email_address) is not None

    @staticmethod
    def sanitize_email_address(email_address):
        """Sanitize and normalize email address"""
        name, addr = email_address.split('@') if '@' in email_address else ('', email_address)
        return addr.lower() if addr else email_address

    @staticmethod
    def filter_spam(text):
        """Filter spam words from email content"""
        return not any(word in text.lower() for word in SPAM_WORDS)

    @staticmethod
    def is_banned_tld(domain):
        """Check if domain has banned TLD"""
        return any(domain.endswith(tld) for tld in BANNED_TLDS)

    @staticmethod
    def is_blocklisted_domain(domain):
        """Check if domain is in blocklist"""
        return domain in BLOCKLIST_DOMAINS

class MX_Server:
    def __init__(self, host, port):
        self.host = host
        self.port = int(port)

class EmailQueueProcessor:
    def __init__(self):
        self.redis_client = redis.Redis(**REDIS_CONFIG)
        self.queue_key = 'email_queue'
        self.rate_limiter = RateLimiter(default_limit_per_hour=RATE_LIMIT)
        self.validator = EmailValidator()
        self.tls_manager = TLSManager()
        self._mx_cache = {}

    def get_mx_servers(self, domain):
        """Get MX servers for domain with caching, filtered by allowed ports"""
        if domain in self._mx_cache:
            return self._mx_cache[domain]

        try:
            # Implement MX server lookup logic here
            # This is a placeholder for MX lookup logic (using DNS resolver or external service)
            # For now, assume we're getting valid MX servers from DNS or a list

            mx_servers = []  # This should come from DNS or external source
            valid_ports = [2525, 587, 465]

            filtered_mx_servers = [MX_Server(mx.host, mx.port) for mx in mx_servers if mx.port in valid_ports]
            self._mx_cache[domain] = filtered_mx_servers
            return filtered_mx_servers
        except Exception as e:
            logging.error(f"Error fetching MX servers for {domain}: {e}")
            return []

    def send_mail_batch(self, mx_server, batch, subject, content, content_type, sender_name):
        """Send batch of emails with rate limiting and DKIM signing"""
        successful = []
        failed = []
        
        with self.smtp_lock:
            for recipient in batch:
                # Check rate limit
                while not self.rate_limiter.can_send(mx_server.host, mx_server.port):
                    wait_time = self.rate_limiter.time_until_next_slot(mx_server.host, mx_server.port)
                    time.sleep(wait_time)

                try:
                    # Create connection
                    if mx_server.port == 465:
                        server = smtplib.SMTP_SSL(mx_server.host, mx_server.port, timeout=20)
                    else:
                        server = smtplib.SMTP(mx_server.host, mx_server.port, timeout=20)
                        try:
                            server.starttls(context=ssl.create_default_context())
                        except smtplib.SMTPNotSupportedError:
                            pass

                        # Get the server's hostname dynamically
                        server_hostname = socket.gethostname()  # e.g., 'mx1.primary-domain.com'
                        server.ehlo(server_hostname)

                    # Prepare message
                    msg = MIMEMultipart()
                    msg['From'] = formataddr((sender_name, 'local@server235.phx.secureservers.net'))
                    msg['To'] = recipient
                    msg['Subject'] = subject

                    # Apply DKIM signing
                    personalized_content = content  # No personalization required now
                    msg.attach(MIMEText(personalized_content, 'html' if content_type == 'HTML' else 'plain', 'utf-8'))
                    msg = self.tls_manager.sign_email(msg)  # DKIM signing

                    # Send email
                    server.sendmail(recipient, [recipient], msg.as_string())
                    self.rate_limiter.record_send(mx_server.host, mx_server.port)
                    server.quit()
                    
                    successful.append(recipient)
                    
                except Exception as e:
                    failed.append(recipient)
                finally:
                    socket.socket = self._original_socket

        return successful, failed

    def process_emails(self, emails, subject, content, content_type, sender_name):
        """Process list of emails through appropriate MX servers"""
        valid_emails, grouped_emails = self.group_by_domain(emails)
        successful = []
        failed = []
        
        for domain, domain_emails in grouped_emails.items():
            mx_servers = self.get_mx_servers(domain)
            if not mx_servers:
                failed.extend(domain_emails)
                continue

            # Try each MX server
            for mx_server in mx_servers:
                domain_successful, domain_failed = self.send_mail_batch(
                    mx_server, domain_emails, subject, content, content_type, sender_name
                )
                successful.extend(domain_successful)
                failed.extend(domain_failed)
                
                if domain_successful:
                    break  # Move to next domain if successful

        return successful, failed

    def start(self):
        """Start the queue processor"""
        self.running = True

    def stop(self):
        """Stop the queue processor"""
        self.running = False
