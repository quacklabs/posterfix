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
import email
from email import policy
from email.parser import BytesParser
import json
import queue
import select
import socketserver
import threading
import asyncio
from socketserver import ThreadingMixIn

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/var/log/email_daemon/email_daemon.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('EmailDaemon')

# SSL-enabled TCP server
class SSLThreadedTCPServer(ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True
    timeout = 10
    
    def __init__(self, server_address, handler_class, processor, ssl_context=None):
        super().__init__(server_address, handler_class)
        self.processor = processor
        self.ssl_context = ssl_context
        
    def get_request(self):
        socket, addr = super().get_request()
        socket.settimeout(10)
        
        if self.ssl_context:
            try:
                # Wrap socket with SSL immediately (HAProxy expects this)
                socket = self.ssl_context.wrap_socket(socket, server_side=True)
                logger.info(f"SSL handshake completed with {addr}")
            except ssl.SSLError as e:
                logger.warning(f"SSL handshake failed with {addr}: {e}")
                try:
                    # Still try to send SMTP response
                    socket.sendall(b'220 ESMTP Email Daemon ready\r\n')
                except:
                    pass
                socket.close()
                raise
            except Exception as e:
                logger.error(f"Error wrapping socket with SSL: {e}")
                socket.close()
                raise
        return socket, addr

class SMTPRequestHandler(socketserver.BaseRequestHandler):
    def __init__(self, request, client_address, server):
        self.processor = server.processor
        self.data = b''
        self.mailfrom = None
        self.rcpttos = []
        self.received_data = b''
        self.state = 'COMMAND'
        self.connected = True
        self.client_ip, self.client_port = client_address
        super().__init__(request, client_address, server)

    def setup(self):
        try:
            logger.info(f"New connection from {self.client_ip}:{self.client_port}")
            
            # Send immediate SMTP greeting - HAProxy expects this immediately
            greeting = '220 %s ESMTP Email Daemon ready\r\n' % socket.getfqdn()
            self.request.sendall(greeting.encode())
            logger.debug("SMTP 220 greeting sent")
            
        except Exception as e:
            logger.error(f"Error in setup: {e}")
            self.connected = False

    def handle(self):
        logger.info(f"Handling connection from {self.client_ip}:{self.client_port}")
        
        if not self.connected:
            return
            
        buffer = b''
        while self.connected:
            try:
                self.request.settimeout(30.0)
                
                data = self.request.recv(1024)
                if not data:
                    logger.info(f"Client {self.client_ip} disconnected")
                    break
                
                buffer += data
                logger.debug(f"Received {len(data)} bytes from {self.client_ip}")
                
                # Process complete SMTP commands
                while b'\r\n' in buffer:
                    line_end = buffer.find(b'\r\n')
                    line_data = buffer[:line_end]
                    buffer = buffer[line_end + 2:]
                    
                    try:
                        line = line_data.decode('utf-8').strip()
                    except UnicodeDecodeError:
                        line = line_data.decode('latin-1', errors='ignore').strip()
                    
                    if line:
                        logger.info(f"Received command: {line}")
                        self.process_smtp_command(line)
                    
            except socket.timeout:
                logger.warning(f"Socket timeout with {self.client_ip}")
                break
            except (ConnectionResetError, BrokenPipeError):
                logger.info(f"Connection reset by {self.client_ip}")
                break
            except Exception as e:
                logger.error(f"Error handling request: {e}")
                break

    def process_smtp_command(self, line):
        """Process SMTP commands with HAProxy health check support"""
        # Check if this is a HAProxy health check
        if self.is_haproxy_health_check(line):
            self.handle_haproxy_health_check(line)
            return
            
        if self.state == 'COMMAND':
            self.process_smtp_command_state(line)
        elif self.state == 'DATA':
            self.process_data_line(line)

    def is_haproxy_health_check(self, line):
        """Detect HAProxy health check patterns"""
        line_upper = line.upper()
        
        # HAProxy health check patterns
        health_check_patterns = [
            line_upper == 'EHLO',
            line_upper.startswith('EHLO '),
            line_upper == 'HELO',
            line_upper.startswith('HELO '),
            line_upper == 'QUIT',
            line_upper == 'NOOP',
            'HAPROXY' in line_upper,
            'HEALTH' in line_upper,
            'CHECK' in line_upper
        ]
        
        return any(health_check_patterns)

    def handle_haproxy_health_check(self, line):
        """Handle HAProxy health check commands"""
        line_upper = line.upper()
        
        if line_upper == 'QUIT':
            self.send_response('221 Bye')
            self.connected = False
            logger.info("HAProxy health check completed with QUIT")
            return
            
        elif line_upper == 'NOOP':
            self.send_response('250 OK')
            logger.info("Responded to NOOP health check")
            return
            
        elif line_upper.startswith('EHLO ') or line_upper == 'EHLO':
            # HAProxy EHLO health check
            self.send_response('250-%s' % socket.getfqdn())
            self.send_response('250-8BITMIME')
            self.send_response('250-PIPELINING')
            self.send_response('250-SIZE 10485760')
            self.send_response('250 HELP')
            logger.info("Responded to EHLO health check")
            return
            
        elif line_upper.startswith('HELO ') or line_upper == 'HELO':
            self.send_response('250 %s' % socket.getfqdn())
            logger.info("Responded to HELO health check")
            return
            
        else:
            self.send_response('250 OK')
            logger.info(f"Responded to unknown health check: {line}")

    def process_smtp_command_state(self, line):
        """Process regular SMTP commands"""
        i = line.find(' ')
        if i < 0:
            command = line.upper()
            arg = None
        else:
            command = line[:i].upper()
            arg = line[i+1:].strip()
            
        method_name = 'smtp_' + command
        if not hasattr(self, method_name):
            self.send_response('502 Error: command "%s" not implemented' % command)
            return
            
        method = getattr(self, method_name)
        method(arg)

    def process_data_line(self, line):
        if line == '.':
            self.smtp_DATA_end()
        else:
            if line.startswith('..'):
                line = line[1:]
            self.data += line + '\r\n'

    def send_response(self, response):
        try:
            logger.debug(f"Sending response: {response}")
            self.request.sendall(response.encode() + b'\r\n')
        except Exception as e:
            logger.error(f"Error sending response: {e}")
            self.connected = False

    # SMTP command methods
    def smtp_EHLO(self, arg):
        if not arg:
            self.send_response('501 Syntax: EHLO hostname')
            return
            
        self.send_response('250-%s' % socket.getfqdn())
        self.send_response('250-8BITMIME')
        self.send_response('250-PIPELINING')
        self.send_response('250-SIZE 10485760')
        self.send_response('250 HELP')
        
    def smtp_HELO(self, arg):
        if not arg:
            self.send_response('501 Syntax: HELO hostname')
            return
        self.send_response('250 %s' % socket.getfqdn())
        
    def smtp_NOOP(self, arg):
        self.send_response('250 OK')
        
    def smtp_QUIT(self, arg):
        self.send_response('221 Bye')
        self.connected = False
        
    def smtp_MAIL(self, arg):
        if not arg or not arg.upper().startswith('FROM:'):
            self.send_response('501 Syntax: MAIL FROM:<address>')
            return
            
        addr = arg[5:].strip()
        if addr.startswith('<') and addr.endswith('>'):
            addr = addr[1:-1]
            
        if not self.processor.validator.validate_email_format(addr):
            self.send_response('553 Invalid sender address')
            return
            
        self.mailfrom = addr
        self.send_response('250 OK')
        
    def smtp_RCPT(self, arg):
        if not self.mailfrom:
            self.send_response('503 Need MAIL before RCPT')
            return
            
        if not arg or not arg.upper().startswith('TO:'):
            self.send_response('501 Syntax: RCPT TO:<address>')
            return
            
        addr = arg[3:].strip()
        if addr.startswith('<') and addr.endswith('>'):
            addr = addr[1:-1]
            
        if not self.processor.validator.validate_email_format(addr):
            self.send_response('553 Invalid recipient address')
            return
            
        self.rcpttos.append(addr)
        self.send_response('250 OK')
        
    def smtp_RSET(self, arg):
        self.mailfrom = None
        self.rcpttos = []
        self.data = b''
        self.state = 'COMMAND'
        self.send_response('250 OK')
        
    def smtp_DATA(self, arg):
        if not self.rcpttos:
            self.send_response('503 Need RCPT before DATA')
            return
            
        self.send_response('354 End data with <CR><LF>.<CR><LF>')
        self.state = 'DATA'
        
    def smtp_STARTTLS(self, arg):
        self.send_response('454 TLS not available')
        
    def smtp_VRFY(self, arg):
        self.send_response('252 Cannot verify user')
        
    def smtp_EXPN(self, arg):
        self.send_response('502 EXPN not implemented')
        
    def smtp_HELP(self, arg):
        self.send_response('214 Supported commands: EHLO, HELO, MAIL, RCPT, DATA, RSET, NOOP, QUIT')

    def smtp_DATA_end(self):
        try:
            msg = BytesParser(policy=policy.default).parsebytes(self.data.encode())
            subject = msg['Subject'] or 'No Subject'
            
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
                    content = msg.get_payload(decode=True).decode(errors='replace')
                    content_type = 'plain'
            else:
                content = msg.get_payload(decode=True).decode(errors='replace')
                content_type = 'plain'
            
            sender_name, sender_email = parseaddr(msg['From'] or self.mailfrom)
            
            self.processor.add_to_queue(self.rcpttos, subject, content, content_type, 
                                       sender_name or sender_email or self.mailfrom)
            
            self.send_response('250 OK: Message queued for delivery')
            
        except Exception as e:
            logger.error(f"Error processing email data: {e}")
            self.send_response('451 Error: Failed to process message')
        finally:
            self.data = b''
            self.state = 'COMMAND'
            self.mailfrom = None
            self.rcpttos = []

class HAProxySMTPServer:
    def __init__(self, host, port, processor, use_ssl=True):
        self.processor = processor
        self.host = host
        self.port = port
        self.use_ssl = use_ssl
        self.server = None
        self.ssl_context = None
        
        if use_ssl:
            self.setup_ssl_context()
        
    def setup_ssl_context(self):
        """Setup SSL context for secure connections"""
        try:
            self.ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            # Load your SSL certificates
            self.ssl_context.load_cert_chain(
                certfile='/etc/ssl/default/fullchain.pem',
                keyfile='/etc/ssl/default/ssl.key'
            )
            # Use compatible cipher settings
            self.ssl_context.set_ciphers('ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:ECDH+AESGCM:DH+AESGCM:ECDH+AES256:DH+AES256:ECDH+AES128:DH+AES:RSA+AESGCM:RSA+AES:!aNULL:!MD5:!DSS')
            self.ssl_context.check_hostname = False
            self.ssl_context.verify_mode = ssl.CERT_NONE
            
            logger.info("SSL context configured successfully")
            
        except Exception as e:
            logger.error(f"Failed to setup SSL context: {e}")
            # Fallback to basic context
            self.ssl_context = ssl.create_default_context()
            self.ssl_context.check_hostname = False
            self.ssl_context.verify_mode = ssl.CERT_NONE
        
    def start(self):
        class HandlerFactory:
            def __init__(self, processor):
                self.processor = processor
                
            def __call__(self, *args):
                return SMTPRequestHandler(*args)
        
        class CustomServer(SSLThreadedTCPServer):
            def __init__(self, server_address, handler_class, processor, ssl_context=None):
                super().__init__(server_address, handler_class, processor, ssl_context)
                self.processor = processor
        
        handler_factory = HandlerFactory(self.processor)
        
        try:
            self.server = CustomServer(
                (self.host, self.port), 
                handler_factory, 
                self.processor,
                self.ssl_context if self.use_ssl else None
            )
            
            self.server.socket.settimeout(30)
            
            ssl_status = "with SSL" if self.use_ssl else "without SSL"
            logger.info(f"HAProxy SMTP server listening on {self.host}:{self.port} {ssl_status}")
            
            # Test local connectivity
            test_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            test_socket.settimeout(2)
            result = test_socket.connect_ex((self.host, self.port))
            test_socket.close()
            
            if result == 0:
                logger.info("✓ Port 3000 is open locally")
            else:
                logger.error("✗ Port 3000 is not accessible locally")
            
            self.server_thread = threading.Thread(target=self.server.serve_forever)
            self.server_thread.daemon = True
            self.server_thread.start()
            
        except Exception as e:
            logger.error(f"Failed to start SMTP server: {e}")
            raise
        
    def stop(self):
        if self.server:
            self.server.shutdown()
            self.server.server_close()

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
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return re.match(pattern, email_address) is not None

    @staticmethod
    def sanitize_email_address(email_address):
        name, addr = email_address.split('@') if '@' in email_address else ('', email_address)
        return addr.lower() if addr else email_address

    @staticmethod
    def filter_spam(text):
        return not any(word in text.lower() for word in SPAM_WORDS)

    @staticmethod
    def is_banned_tld(domain):
        return any(domain.endswith(tld) for tld in BANNED_TLDS)

    @staticmethod
    def is_blocklisted_domain(domain):
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
        self.haproxy_server = None

    def add_to_queue(self, recipients, subject, content, content_type, sender_name):
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
        successful = []
        failed = []
        
        with self.smtp_lock:
            for recipient in batch:
                while not self.rate_limiter.can_send(mx_server.host, mx_server.port):
                    wait_time = self.rate_limiter.time_until_next_slot(mx_server.host, mx_server.port)
                    logger.info(f"Rate limit reached for {mx_server.host}:{mx_server.port}, waiting {wait_time:.2f}s")
                    time.sleep(wait_time)

                try:
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
                        if mx_server.port in [587, 2525]:
                            server.starttls(context=ssl.create_default_context())

                    server.ehlo_or_helo_if_needed()

                    msg = MIMEMultipart()
                    msg['From'] = formataddr((sender_name, f'{sender_name}@yourdomain.com'))
                    msg['To'] = recipient
                    msg['Subject'] = subject
                    msg['Date'] = email.utils.formatdate()

                    msg.attach(MIMEText(content, 'html' if content_type == 'HTML' else 'plain', 'utf-8'))
                    
                    try:
                        msg = self.tls_manager.sign_email(msg)
                    except Exception as e:
                        logger.warning(f"DKIM signing failed: {e}")

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
        self.running = True
        
        # Start queue processing thread
        self.queue_thread = threading.Thread(target=self.process_queue)
        self.queue_thread.daemon = True
        self.queue_thread.start()
        
        # Start HAProxy SMTP server WITH SSL
        self.haproxy_server = HAProxySMTPServer('0.0.0.0', 3000, self, use_ssl=True)
        self.haproxy_server.start()
        
        logger.info("Email daemon started successfully with SSL support")

    def stop(self):
        self.running = False
        if self.haproxy_server:
            self.haproxy_server.stop()
        logger.info("Email daemon stopped")

# Main execution
if __name__ == "__main__":
    processor = EmailQueueProcessor()
    
    try:
        processor.start()
        logger.info("Email daemon started. Waiting for HAProxy SSL connections...")
        
        while True:
            time.sleep(60)
            logger.debug("Daemon heartbeat")
            
    except KeyboardInterrupt:
        logger.info("Shutting down...")
        processor.stop()
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        processor.stop()