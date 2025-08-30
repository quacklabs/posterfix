import smtplib
import time
import logging
import redis
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.utils import formataddr, parseaddr
from collections import deque, defaultdict
import dkim
import ssl
from tls_manager import TLSManager
from config import *
import socket
import threading
import re
import dns.resolver
import asyncore
import asynchat
import email
from email import policy
from email.parser import BytesParser
import json
import queue
import select

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('email_daemon.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('EmailDaemon')

class HAProxySMTPChannel(asynchat.async_chat):
    """Custom SMTP channel for HAProxy connections"""
    
    def __init__(self, sock, addr, processor):
        asynchat.async_chat.__init__(self, sock=sock)
        self.set_terminator(b'\r\n')
        self.processor = processor
        self.data = b''
        self.mailfrom = None
        self.rcpttos = []
        self.received_data = b''
        self.state = 'COMMAND'
        self.push('220 %s ESMTP Email Daemon ready' % socket.getfqdn())
        
    def collect_incoming_data(self, data):
        self.received_data += data
        
    def found_terminator(self):
        line = self.received_data.decode('utf-8').strip()
        self.received_data = b''
        
        if self.state == 'COMMAND':
            if not line:
                self.push('500 Error: bad syntax')
                return
                
            i = line.find(' ')
            if i < 0:
                command = line.upper()
                arg = None
            else:
                command = line[:i].upper()
                arg = line[i+1:].strip()
                
            method_name = 'smtp_' + command
            if not hasattr(self, method_name):
                self.push('502 Error: command "%s" not implemented' % command)
                return
                
            method = getattr(self, method_name)
            method(arg)
        elif self.state == 'DATA':
            if line == '.':
                # End of data
                self.smtp_DATA_end()
            else:
                # Remove leading dot if present (SMTP transparency)
                if line.startswith('..'):
                    line = line[1:]
                self.data += line + '\r\n'
                
    def smtp_EHLO(self, arg):
        if not arg:
            self.push('501 Syntax: EHLO hostname')
            return
        self.push('250-%s' % socket.getfqdn())
        self.push('250-8BITMIME')
        self.push('250-PIPELINING')
        self.push('250-SIZE 10485760')
        self.push('250 HELP')
        
    def smtp_HELO(self, arg):
        if not arg:
            self.push('501 Syntax: HELO hostname')
            return
        self.push('250 %s' % socket.getfqdn())
        
    def smtp_NOOP(self, arg):
        self.push('250 OK')
        
    def smtp_QUIT(self, arg):
        self.push('221 Bye')
        self.close_when_done()
        
    def smtp_MAIL(self, arg):
        if not arg or not arg.upper().startswith('FROM:'):
            self.push('501 Syntax: MAIL FROM:<address>')
            return
            
        # Extract email address
        addr = arg[5:].strip()
        if addr.startswith('<') and addr.endswith('>'):
            addr = addr[1:-1]
            
        # Validate email
        if not self.processor.validator.validate_email_format(addr):
            self.push('553 Invalid sender address')
            return
            
        self.mailfrom = addr
        self.push('250 OK')
        
    def smtp_RCPT(self, arg):
        if not self.mailfrom:
            self.push('503 Need MAIL before RCPT')
            return
            
        if not arg or not arg.upper().startswith('TO:'):
            self.push('501 Syntax: RCPT TO:<address>')
            return
            
        # Extract email address
        addr = arg[3:].strip()
        if addr.startswith('<') and addr.endswith('>'):
            addr = addr[1:-1]
            
        # Validate email
        if not self.processor.validator.validate_email_format(addr):
            self.push('553 Invalid recipient address')
            return
            
        self.rcpttos.append(addr)
        self.push('250 OK')
        
    def smtp_RSET(self, arg):
        self.mailfrom = None
        self.rcpttos = []
        self.data = b''
        self.state = 'COMMAND'
        self.push('250 OK')
        
    def smtp_DATA(self, arg):
        if not self.rcpttos:
            self.push('503 Need RCPT before DATA')
            return
            
        self.push('354 End data with <CR><LF>.<CR><LF>')
        self.state = 'DATA'
        
    def smtp_DATA_end(self):
        # Parse the email data
        try:
            msg = BytesParser(policy=policy.default).parsebytes(self.data)
            
            # Extract subject and content
            subject = msg['Subject'] or 'No Subject'
            
            # Get the body content
            if msg.is_multipart():
                for part in msg.walk():
                    if part.get_content_type() == "text/plain":
                        content = part.get_payload(decode=True).decode(errors='replace')
                        content_type = 'plain'
                        break
                    elif part.get_content_type() == "text/html":
                        content = part.get_payload(decode=True).decode(errors='replace')
                        content_type = 'HTML'
                        break
                else:
                    # Fallback to the first part
                    content = msg.get_payload(decode=True).decode(errors='replace')
                    content_type = 'plain'
            else:
                content = msg.get_payload(decode=True).decode(errors='replace')
                content_type = 'plain'
            
            # Extract sender name
            sender_name, sender_email = parseaddr(msg['From'] or self.mailfrom)
            
            # Add to processing queue
            self.processor.add_to_queue(self.rcpttos, subject, content, content_type, 
                                       sender_name or sender_email or self.mailfrom)
            
            self.push('250 OK: Message queued for delivery')
            
        except Exception as e:
            logger.error(f"Error processing email data: {e}")
            self.push('451 Error: Failed to process message')
            
        finally:
            self.data = b''
            self.state = 'COMMAND'
            self.mailfrom = None
            self.rcpttos = []

class HAProxySMTPServer(asyncore.dispatcher):
    """SMTP server for HAProxy connections"""
    
    def __init__(self, host, port, processor):
        asyncore.dispatcher.__init__(self)
        self.processor = processor
        self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
        self.set_reuse_addr()
        self.bind((host, port))
        self.listen(5)
        logger.info(f"HAProxy SMTP server listening on {host}:{port}")
        
    def handle_accept(self):
        pair = self.accept()
        if pair is not None:
            sock, addr = pair
            logger.info(f"Incoming connection from {addr}")
            HAProxySMTPChannel(sock, addr, self.processor)

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
        self.smtp_lock = threading.Lock()
        self.running = False
        self.local_queue = queue.Queue()

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
        
        # Add to both Redis and local queue for redundancy
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
                # Try to get from local queue first
                try:
                    email_data = self.local_queue.get_nowait()
                except queue.Empty:
                    # Fall back to Redis
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
                
                # Process the email
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
                s.settimeout(10)  # Timeout after 10 seconds
                s.connect((host, port))  # Try to connect to the host and port
                s.sendall(greeting.encode('utf-8'))
                response = s.recv(1024)  # Receive server response
                if b'220' in response:  # Check for "220" SMTP greeting code
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
            # Perform DNS lookup to get MX servers
            answers = dns.resolver.resolve(domain, 'MX')
            mx_servers = []
            valid_ports = [2525, 587, 465]  # Your preferred ports only
            
            for rdata in answers:
                host = rdata.exchange.to_text().rstrip('.')  # Get the MX host
                # Ping each MX server on the valid SMTP ports
                for port in valid_ports:
                    if self.ping_mx_server(host, port):  # Only add to list if it responds as SMTP
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
            # Validate email format
            if not self.validator.validate_email_format(email_addr):
                logger.warning(f"Invalid email format: {email_addr}")
                continue
                
            # Extract domain
            domain = email_addr.split('@')[1]
            
            # Check for banned TLDs and blocklisted domains
            if (self.validator.is_banned_tld(domain) or 
                self.validator.is_blocklisted_domain(domain)):
                logger.warning(f"Email domain blocked: {domain}")
                continue
                
            valid_emails.append(email_addr)
            grouped_emails[domain].append(email_addr)
            
        return valid_emails, grouped_emails

    def send_mail_batch(self, mx_server, batch, subject, content, content_type, sender_name):
        """Send batch of emails with rate limiting and DKIM signing"""
        successful = []
        failed = []
        
        with self.smtp_lock:
            for recipient in batch:
                # Check rate limit
                while not self.rate_limiter.can_send(mx_server.host, mx_server.port):
                    wait_time = self.rate_limiter.time_until_next_slot(mx_server.host, mx_server.port)
                    logger.info(f"Rate limit reached for {mx_server.host}:{mx_server.port}, waiting {wait_time:.2f}s")
                    time.sleep(wait_time)

                try:
                    # Create connection with appropriate settings
                    if mx_server.port == 465:
                        server = smtplib.SMTP_SSL(
                            host=mx_server.host, 
                            port=mx_server.port, 
                            timeout=30,
                            context=ssl.create_default_context()
                        )
                    else:
                        server = smtplib.SMTP(
                            host=mx_server.host, 
                            port=mx_server.port, 
                            timeout=30
                        )
                        if mx_server.port in [587, 2525]:  # Start TLS on submission ports
                            server.starttls(context=ssl.create_default_context())

                    # Identify ourselves
                    server.ehlo_or_helo_if_needed()

                    # Prepare message
                    msg = MIMEMultipart()
                    msg['From'] = formataddr((sender_name, f'{sender_name}@yourdomain.com'))
                    msg['To'] = recipient
                    msg['Subject'] = subject
                    msg['Date'] = email.utils.formatdate()

                    # Add content
                    msg.attach(MIMEText(content, 'html' if content_type == 'HTML' else 'plain', 'utf-8'))
                    
                    # Apply DKIM signing if available
                    try:
                        msg = self.tls_manager.sign_email(msg)
                    except Exception as e:
                        logger.warning(f"DKIM signing failed: {e}")

                    # Send email
                    server.sendmail(f'{sender_name}@yourdomain.com', [recipient], msg.as_string())
                    self.rate_limiter.record_send(mx_server.host, mx_server.port)
                    server.quit()
                    
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

            # Try each MX server until we find one that works
            for mx_server in mx_servers:
                try:
                    domain_successful, domain_failed = self.send_mail_batch(
                        mx_server, domain_emails, subject, content, content_type, sender_name
                    )
                    successful.extend(domain_successful)
                    failed.extend(domain_failed)
                    
                    if domain_successful:
                        break  # Move to next domain if successful
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
        self.haproxy_server = HAProxySMTPServer('0.0.0.0', 3000, self)
        
        # Start asyncore loop in a separate thread
        self.asyncore_thread = threading.Thread(target=asyncore.loop, kwargs={'timeout': 1})
        self.asyncore_thread.daemon = True
        self.asyncore_thread.start()
        
        logger.info("Email daemon started successfully")

    def stop(self):
        """Stop the queue processor"""
        self.running = False
        logger.info("Email daemon stopped")

# Main execution
if __name__ == "__main__":
    processor = EmailQueueProcessor()
    
    try:
        processor.start()
        # Keep the main thread alive
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        processor.stop()