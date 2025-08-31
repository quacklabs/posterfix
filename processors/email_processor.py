"""
Main email processing functionality
"""
import time
import logging
import redis
import socket
import dns.resolver
import json
import queue
import threading

from .rate_limiter import RateLimiter
from .validator import EmailValidator
from ..servers.smtp_server import HAProxySMTPServer
from .. import config

logger = logging.getLogger('EmailDaemon')

class MX_Server:
    def __init__(self, host, port):
        self.host = host
        self.port = int(port)

class EmailQueueProcessor:
    def __init__(self):
        self.redis_client = redis.Redis(**config.REDIS_CONFIG)
        self.queue_key = config.QUEUE_KEY
        self.rate_limiter = RateLimiter(default_limit_per_hour=config.RATE_LIMIT)
        self.validator = EmailValidator()
        self._mx_cache = {}
        self.smtp_lock = threading.Lock()
        self.running = False
        self.local_queue = queue.Queue()
        self.haproxy_server = None

    def add_to_queue(self, recipients, subject, content, content_type, sender_name):
        """Add email to processing queue"""
        email_data = {
            'recipients': recipients,
            'subject': subject,
            'content': content,
            'content_type': content_type,
            'sender_name': sender_name,
            'timestamp': time.time()
        }
        
        try:
            self.redis_client.rpush(self.queue_key, json.dumps(email_data))
        except Exception as e:
            logger.error(f"Failed to add to Redis queue: {e}")
            
        self.local_queue.put(email_data)
        logger.info(f"Added {len(recipients)} recipients to queue")

    def process_queue(self):
        """Process emails from the queue"""
        while self.running:
            try:
                try:
                    email_data = self.local_queue.get_nowait()
                except queue.Empty:
                    email_data_json = self.redis_client.blpop(self.queue_key, timeout=1)
                    if not email_data_json:
                        time.sleep(1)
                        continue
                    email_data = json.loads(email_data_json[1])
                
                recipients = email_data['recipients']
                subject = email_data['subject']
                content = email_data['content']
                content_type = email_data['content_type']
                sender_name = email_data['sender_name']
                
                successful, failed = self.process_emails(recipients, subject, content, content_type, sender_name)
                
                logger.info(f"Processed email: {len(successful)} successful, {len(failed)} failed")
                
            except Exception as e:
                logger.error(f"Error processing queue: {e}")
                time.sleep(5)

    def ping_mx_server(self, host, port):
        """Ping the MX server on the given port to check if it's an SMTP server"""
        hostname = socket.gethostname()
        greeting = f'EHLO {hostname}\r\n'
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(10)
                s.connect((host, port))
                s.sendall(greeting.encode('utf-8'))
                response = s.recv(1024)
                if b'220' in response:
                    return True
                else:
                    logger.error(f"Failed to communicate with SMTP server {host}:{port}")
                    return False
        except socket.error as e:
            logger.error(f"Error connecting to {host}:{port} - {e}")
            return False

    def get_mx_servers(self, domain):
        """Get MX servers for domain with caching, filtered by allowed ports"""
        if domain in self._mx_cache:
            return self._mx_cache[domain]
        
        try:
            answers = dns.resolver.resolve(domain, 'MX')
            mx_servers = []
            valid_ports = [2525, 587, 465]
            
            for rdata in answers:
                host = rdata.exchange.to_text().rstrip('.')
                for port in valid_ports:
                    if self.ping_mx_server(host, port):
                        mx_servers.append(MX_Server(host, port))

            self._mx_cache[domain] = mx_servers
            return mx_servers
        except Exception as e:
            logger.error(f"Error fetching MX servers for {domain}: {e}")
            return []

    def group_by_domain(self, emails):
        """Group emails by domain and validate them"""
        valid_emails = []
        grouped_emails = defaultdict(list)
        
        for email_addr in emails:
            if not self.validator.validate_email_format(email_addr):
                logger.warning(f"Invalid email format: {email_addr}")
                continue
                
            domain = email_addr.split('@')[1]
            
            if (self.validator.is_banned_tld(domain) or 
                self.validator.is_blocklisted_domain(domain)):
                logger.warning(f"Email domain blocked: {domain}")
                continue
                
            valid_emails.append(email_addr)
            grouped_emails[domain].append(email_addr)
            
        return valid_emails, grouped_emails

    def send_mail_batch(self, mx_server, batch, subject, content, content_type, sender_name):
        """Send batch of emails with rate limiting"""
        successful = []
        failed = []
        
        with self.smtp_lock:
            for recipient in batch:
                while not self.rate_limiter.can_send(mx_server.host, mx_server.port):
                    wait_time = self.rate_limiter.time_until_next_slot(mx_server.host, mx_server.port)
                    logger.info(f"Rate limit reached for {mx_server.host}:{mx_server.port}, waiting {wait_time:.2f}s")
                    time.sleep(wait_time)

                try:
                    # Your email sending logic here
                    # This would use smtplib to actually send emails
                    self.rate_limiter.record_send(mx_server.host, mx_server.port)
                    successful.append(recipient)
                    logger.info(f"Successfully sent email to {recipient}")
                    
                except Exception as e:
                    failed.append(recipient)
                    logger.error(f"Failed to send email to {recipient}: {e}")

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
                logger.error(f"No MX servers found for domain: {domain}")
                continue

            for mx_server in mx_servers:
                try:
                    domain_successful, domain_failed = self.send_mail_batch(
                        mx_server, domain_emails, subject, content, content_type, sender_name
                    )
                    successful.extend(domain_successful)
                    failed.extend(domain_failed)
                    
                    if domain_successful:
                        break
                except Exception as e:
                    logger.error(f"Failed to send to {mx_server.host}:{mx_server.port}: {e}")
                    continue

        return successful, failed

    def start(self):
        """Start the queue processor"""
        self.running = True
        
        # Start queue processing thread
        self.queue_thread = threading.Thread(target=self.process_queue)
        self.queue_thread.daemon = True
        self.queue_thread.start()
        
        # Start HAProxy SMTP server
        self.haproxy_server = HAProxySMTPServer('0.0.0.0', config.SMTP_PORT, self, use_ssl=True)
        self.haproxy_server.start()
        
        logger.info("Email daemon started successfully")

    def stop(self):
        """Stop the queue processor"""
        self.running = False
        if self.haproxy_server:
            self.haproxy_server.stop()
        logger.info("Email daemon stopped")