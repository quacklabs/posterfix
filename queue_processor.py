import re
import time
import random
import socket
import smtplib
import ssl
import dns.resolver
from collections import defaultdict, deque
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.utils import formataddr
from datetime import datetime
import threading
from config import *

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

class EmailQueueProcessor:
    def __init__(self):
        self.rate_limiter = RateLimiter(default_limit_per_hour=RATE_LIMIT)
        self.validator = EmailValidator()
        self._original_socket = socket.socket
        self._mx_cache = {}
        self.smtp_lock = threading.Lock()
        self.running = False

    def get_mx_servers(self, domain):
        """Get MX servers for domain with caching"""
        if domain in self._mx_cache:
            return self._mx_cache[domain]
        
        try:
            if domain == 'outlook.com':
                mx_servers = [MX_Server('smtp-mail.outlook.com', 587)]
            elif domain == 'gmail.com':
                mx_servers = [MX_Server('smtp.gmail.com', 587)]
            else:
                socket.socket = self._original_socket
                resolver = dns.resolver.Resolver()
                resolver.timeout = 15.0
                resolver.lifetime = 15.0
                resolver.nameservers = DNS_SERVERS
                mx_records = resolver.resolve(domain, 'MX')
                mx_servers = [MX_Server(str(record.exchange).rstrip('.'), 587) 
                             for record in sorted(mx_records, key=lambda r: r.preference)]
            
            self._mx_cache[domain] = mx_servers
            return mx_servers
            
        except Exception as e:
            return []
        finally:
            socket.socket = self._original_socket

    def personalize_content(self, content, recipient):
        """Personalize email content with recipient-specific data"""
        content = content.replace('[[-Email-]]', recipient)
        content = content.replace('[[-Now-]]', datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
        return content

    def group_by_domain(self, emails):
        """Group emails by domain with validation"""
        grouped_emails = defaultdict(list)
        valid_emails = []
        
        for email in emails:
            if self.validator.validate_email_format(email) and self.validator.filter_spam(email.split('@')[0].strip()):
                domain = email.split('@')[1].strip().lower()
                if (not self.validator.is_banned_tld(domain) and 
                    not self.validator.is_blocklisted_domain(domain)):
                    grouped_emails[domain].append(email)
                    valid_emails.append(email)
        
        return valid_emails, grouped_emails

    def send_mail_batch(self, mx_server, batch, subject, content, content_type, sender_name):
        """Send batch of emails with rate limiting"""
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
                        server = smtplib.SMTP_SSL(mx_server.host, mx_server.port, timeout=10)
                    else:
                        server = smtplib.SMTP(mx_server.host, mx_server.port, timeout=10)
                        try:
                            server.starttls(context=ssl.create_default_context())
                        except smtplib.SMTPNotSupportedError:
                            pass
                        server.ehlo('localhost')

                    # Prepare message
                    msg = MIMEMultipart()
                    msg['From'] = formataddr((sender_name, 'local@server235.phx.secureservers.net'))
                    msg['To'] = recipient
                    msg['Subject'] = subject.replace('[[-Email-]]', recipient)
                    
                    personalized_content = self.personalize_content(content, recipient)
                    msg.attach(MIMEText(personalized_content, 'html' if content_type == 'HTML' else 'plain', 'utf-8'))

                    # Send email
                    server.sendmail(recipient, [recipient], msg.as_string())
                    self.rate_limiter.record_send(mx_server.host, mx_server.port)
                    
                    server.noop()
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