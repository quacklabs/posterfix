#!/usr/bin/env python3
"""
Email Daemon - Complete solution in a single file
"""
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
import sys
import os
import fcntl
import termios
import struct

# ==================== CONFIGURATION ====================
REDIS_CONFIG = {
    'host': 'localhost',
    'port': 6379,
    'db': 0,
    'password': None,
    'socket_timeout': 5
}

DEFAULT_RATE_LIMIT = 1000
RATE_LIMIT = 500

SPAM_WORDS = [
    'viagra', 'casino', 'lottery', 'prize', 'winner', 'free', 'money',
    'credit', 'loan', 'mortgage', 'drug', 'pharmacy', 'prescription'
]

BANNED_TLDS = [
    '.xyz', '.top', '.club', '.info', '.bid', '.win', '.loan', '.work'
]

BLOCKLIST_DOMAINS = [
    'example.com', 'test.com', 'spam.com'
]

DKIM_PRIVATE_KEY_PATH = '/etc/ssl/default/relay.private'
SSL_CERT_PATH = '/etc/ssl/default/fullchain.pem'
SSL_KEY_PATH = '/etc/ssl/default/ssl.key'

SMTP_PORT = 3000
LOG_DIR = '/var/log/email_daemon'
QUEUE_KEY = 'email_queue'

HAPROXY_HEALTH_CHECK_DOMAINS = ['haproxy', 'health', 'check']
# ==================== END CONFIG ====================

# ==================== LOGGING SETUP ====================
class BroadcastHandler(logging.Handler):
    def __init__(self):
        super().__init__()
        self.terminals = self.get_active_terminals()
        
    def get_active_terminals(self):
        terminals = []
        try:
            for term_dir in ['/dev/pts', '/dev']:
                if os.path.exists(term_dir):
                    for entry in os.listdir(term_dir):
                        if entry.startswith('pts/') or entry.startswith('tty'):
                            term_path = os.path.join(term_dir, entry)
                            if self.is_terminal_active(term_path):
                                terminals.append(term_path)
        except Exception:
            pass
        return terminals
    
    def is_terminal_active(self, term_path):
        try:
            with open(term_path, 'w') as f:
                fcntl.ioctl(f, termios.TIOCGWINSZ, struct.pack('HHHH', 0, 0, 0, 0))
            return True
        except:
            return False
    
    def emit(self, record):
        try:
            msg = self.format(record) + '\n'
            for term in self.terminals:
                try:
                    with open(term, 'w') as f:
                        f.write(msg)
                        f.flush()
                except:
                    if term in self.terminals:
                        self.terminals.remove(term)
        except Exception as e:
            sys.stderr.write(f"Broadcast error: {e}\n")
    
    def refresh_terminals(self):
        self.terminals = self.get_active_terminals()

# Configure logging
os.makedirs(LOG_DIR, exist_ok=True)

logger = logging.getLogger('EmailDaemon')
logger.setLevel(logging.DEBUG)

# Remove existing handlers
for handler in logger.handlers[:]:
    logger.removeHandler(handler)

# Create handlers
file_handler = logging.FileHandler(f'{LOG_DIR}/email_daemon.log')
stream_handler = logging.StreamHandler()
broadcast_handler = BroadcastHandler()

# Formatters
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
file_handler.setFormatter(formatter)
stream_handler.setFormatter(formatter)
broadcast_handler.setFormatter(formatter)

# Add handlers
logger.addHandler(file_handler)
logger.addHandler(stream_handler)
logger.addHandler(broadcast_handler)


def extract_address(command: str) -> str | None:
    """
    Extracts the email address between <> in SMTP commands like:
    MAIL FROM:<user@example.com>
    RCPT TO:<dest@example.com>
    """
    match = re.search(r'<([^<>]+)>', command)
    return match.group(1) if match else None

# ==================== VALIDATOR ====================
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

# ==================== RATE LIMITER ====================
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

# ==================== TLS MANAGER ====================
class TLSManager:
    def __init__(self):
        self.private_key = self.load_private_key(DKIM_PRIVATE_KEY_PATH)

    def load_private_key(self, path):
        try:
            with open(path, 'rb') as f:
                return f.read()
        except Exception as e:
            raise ValueError(f"Error loading private key: {e}")

    def sign_email(self, message_bytes: bytes, signing_domain: str, selector: str = 'default') -> bytes:
        """
        Sign the provided full email message bytes using DKIM and return the signed message bytes
        (DKIM-Signature header + original message).
        - message_bytes: full RFC 2822 message bytes
        - signing_domain: domain to use in the DKIM signature (example: example.com)
        - selector: DKIM selector (default 'default')
        """
        try:
            if not self.private_key:
                logger.warning("No DKIM private key loaded; skipping DKIM signing")
                return message_bytes

            # Minimal include headers - these are commonly signed
            include_headers = [b"From", b"To", b"Subject", b"Date", b"Message-ID"]

            sig = dkim.sign(
                message_bytes,
                selector=selector.encode('ascii'),
                domain=signing_domain.encode('ascii'),
                privkey=self.private_key,
                include_headers=include_headers,
                canonicalize=(b"relaxed", b"simple")
            )

            # dkim.sign returns raw bytes like b"DKIM-Signature: ...\r\n"
            signed = sig + message_bytes
            return signed
        except Exception as e:
            logger.error(f"❌ DKIM signing failed for domain {signing_domain}: {e}")
            return message_bytes



# ==================== MX SERVER ====================
class MX_Server:
    def __init__(self, host, port):
        self.host = host
        self.port = int(port)

# ==================== SMTP HANDLER ====================
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
        self.session_id = f"{self.client_ip}:{self.client_port}-{int(time.time())}"
        self.validator = EmailValidator()
        super().__init__(request, client_address, server)

    def setup(self):
        try:
            logger.info(f"🔄 NEW CONNECTION [{self.session_id}] from {self.client_ip}:{self.client_port}")
            
            greeting = '220 %s ESMTP Email Daemon ready\r\n' % socket.getfqdn()
            self.request.sendall(greeting.encode())
            logger.info(f"📤 [{self.session_id}] Sent: 220 ESMTP ready")
            
        except Exception as e:
            logger.error(f"❌ [{self.session_id}] Setup error: {e}")
            self.connected = False

    def handle(self):
        logger.info(f"🔧 [{self.session_id}] Handling connection")
        
        if not self.connected:
            return
            
        buffer = b''
        while self.connected:
            try:
                self.request.settimeout(15.0)
                
                data = self.request.recv(1024)
                if not data:
                    logger.info(f"📴 [{self.session_id}] Client disconnected gracefully")
                    break
                
                buffer += data
                logger.debug(f"📥 [{self.session_id}] Received {len(data)} bytes")
                
                while b'\r\n' in buffer:
                    line_end = buffer.find(b'\r\n')
                    line_data = buffer[:line_end]
                    buffer = buffer[line_end + 2:]
                    
                    try:
                        line = line_data.decode('utf-8').strip()
                    except UnicodeDecodeError:
                        line = line_data.decode('latin-1', errors='ignore').strip()
                    
                    if line:
                        logger.info(f"📨 [{self.session_id}] Received: {line}")
                        self.process_smtp_command(line)
                    
            except socket.timeout:
                logger.warning(f"⏰ [{self.session_id}] Socket timeout - closing connection")
                break
            except (ConnectionResetError, BrokenPipeError):
                logger.info(f"🔌 [{self.session_id}] Connection reset by client")
                break
            except Exception as e:
                logger.error(f"💥 [{self.session_id}] Handle error: {e}")
                break

    def process_smtp_command(self, line):
        if self.state == 'COMMAND':
            self.process_smtp_command_state(line)
        elif self.state == 'DATA':
            self.process_data_line(line)
   
    def process_smtp_command_state(self, line):
        i = line.find(' ')
        if i < 0:
            command = line.upper()
            arg = None
        else:
            command = line[:i].upper()
            arg = line[i+1:].strip()
            
        method_name = 'smtp_' + command
        if not hasattr(self, method_name):
            self.send_response('502 5.5.2 Error: command "%s" not implemented' % command)
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
            logger.info(f"📤 [{self.session_id}] Sending: {response}")
            self.request.sendall(response.encode() + b'\r\n')
        except Exception as e:
            logger.error(f"❌ [{self.session_id}] Send error: {e}")
            self.connected = False

    # SMTP command methods
    def smtp_EHLO(self, arg):
        logger.info(f"📨 [{self.session_id}] Processing EHLO: {arg}")
        if not arg:
            self.send_response('501 5.5.4 Syntax: EHLO hostname')
            return
            
        self.send_response('250-%s' % socket.getfqdn())
        self.send_response('250-8BITMIME')
        self.send_response('250-PIPELINING')
        self.send_response('250-SIZE 10485760')
        self.send_response('250 HELP')

    def smtp_HELO(self, arg):
        logger.info(f"📨 [{self.session_id}] Processing HELO: {arg}")
        if not arg:
            self.send_response('501 5.5.4 Syntax: HELO hostname')
            return
        self.send_response('250 %s' % socket.getfqdn())
        
    def smtp_NOOP(self, arg):
        logger.info(f"📨 [{self.session_id}] Processing NOOP")
        self.send_response('250 2.0.0 OK')
        
    def smtp_QUIT(self, arg):
        logger.info(f"📨 [{self.session_id}] Processing QUIT")
        self.send_response('221 2.0.0 Bye')
        self.connected = False
        
    def smtp_MAIL(self, arg):
        logger.info(f"📨 [{self.session_id}] Processing MAIL: {arg}")
        if not arg or not arg.upper().startswith('FROM:'):
            self.send_response('501 5.5.4 Syntax: MAIL FROM:<address>')
            return
            
        addr = extract_address(arg)
        # ) arg[5:].strip()
        if addr.startswith('<') and addr.endswith('>'):
            addr = addr[1:-1]
            
        if not self.validator.validate_email_format(addr):
            self.send_response('553 5.1.7 Invalid sender address')
            return
            
        self.mailfrom = addr
        self.send_response('250 2.1.0 OK')
        
    def smtp_RCPT(self, arg):
        logger.info(f"📨 [{self.session_id}] Processing RCPT: {arg}")
        if not self.mailfrom:
            self.send_response('503 5.5.1 Need MAIL before RCPT')
            return
            
        if not arg or not arg.upper().startswith('TO:'):
            self.send_response('501 5.5.4 Syntax: RCPT TO:<address>')
            return
            
        addr = arg[3:].strip()
        if addr.startswith('<') and addr.endswith('>'):
            addr = addr[1:-1]
            
        if not self.validator.validate_email_format(addr):
            self.send_response('553 5.1.7 Invalid recipient address')
            return
            
        self.rcpttos.append(addr)
        self.send_response('250 2.1.5 OK')
        
    def smtp_RSET(self, arg):
        logger.info(f"📨 [{self.session_id}] Processing RSET")
        self.mailfrom = None
        self.rcpttos = []
        self.data = b''
        self.state = 'COMMAND'
        self.send_response('250 2.0.0 OK')
        
    def smtp_DATA(self, arg):
        logger.info(f"📨 [{self.session_id}] Processing DATA")
        if not self.rcpttos:
            self.send_response('503 5.5.1 Need RCPT before DATA')
            return
            
        self.send_response('354 3.0.0 End data with <CR><LF>.<CR><LF>')
        self.state = 'DATA'
        
    def smtp_STARTTLS(self, arg):
        logger.info(f"📨 [{self.session_id}] Processing STARTTLS")
        self.send_response('454 4.7.0 TLS not available')
        
    def smtp_VRFY(self, arg):
        logger.info(f"📨 [{self.session_id}] Processing VRFY: {arg}")
        self.send_response('252 2.1.5 Cannot verify user')
        
    def smtp_EXPN(self, arg):
        logger.info(f"📨 [{self.session_id}] Processing EXPN: {arg}")
        self.send_response('502 5.5.2 EXPN not implemented')
        
    def smtp_HELP(self, arg):
        logger.info(f"📨 [{self.session_id}] Processing HELP: {arg}")
        self.send_response('214 2.0.0 Supported commands: EHLO, HELO, MAIL, RCPT, DATA, RSET, NOOP, QUIT')

    def smtp_DATA_end(self):
        try:
            logger.info(f"📨 [{self.session_id}] Processing DATA end")
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
            
            self.send_response('250 2.0.0 OK: Message queued for delivery')
            
        except Exception as e:
            logger.error(f"❌ [{self.session_id}] DATA processing error: {e}")
            self.send_response('451 4.3.0 Error: Failed to process message')
        finally:
            self.data = b''
            self.state = 'COMMAND'
            self.mailfrom = None
            self.rcpttos = []

# ==================== SERVER CLASSES ====================
class DualModeTCPServer(ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True
    timeout = 5
    
    def __init__(self, server_address, handler_class, processor, ssl_context=None):
        super().__init__(server_address, handler_class)
        self.processor = processor
        self.ssl_context = ssl_context
        
    def get_request(self):
        socket, addr = super().get_request()
        socket.settimeout(10)
        
        try:
            peek_data = socket.recv(5, socket.MSG_PEEK)
            if len(peek_data) >= 5 and self.is_ssl_handshake(peek_data):
                if self.ssl_context:
                    try:
                        socket = self.ssl_context.wrap_socket(socket, server_side=True)
                        logger.info(f"🔒 SSL handshake completed with {addr[0]}")
                    except ssl.SSLError as e:
                        logger.warning(f"❌ SSL handshake failed: {e}")
        except Exception:
            pass
        
        return socket, addr
    
    def is_ssl_handshake(self, data):
        return data[0] == 0x16 and len(data) >= 5 and data[1:3] == b'\x03\x01'

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
        try:
            self.ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            self.ssl_context.load_cert_chain(
                certfile=SSL_CERT_PATH,
                keyfile=SSL_KEY_PATH
            )
            self.ssl_context.set_ciphers('ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:ECDH+AESGCM:DH+AESGCM:ECDH+AES256:DH+AES256:ECDH+AES128:DH+AES:RSA+AESGCM:RSA+AES:!aNULL:!MD5:!DSS')
            self.ssl_context.check_hostname = False
            self.ssl_context.verify_mode = ssl.CERT_NONE
            
        except Exception as e:
            logger.error(f"❌ SSL context setup failed: {e}")
            self.ssl_context = None
        
    def start(self):
        class HandlerFactory:
            def __init__(self, processor):
                self.processor = processor
                
            def __call__(self, *args):
                return SMTPRequestHandler(*args)
        
        class CustomServer(DualModeTCPServer):
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
            
            logger.info(f"🚀 HAProxy SMTP server listening on {self.host}:{self.port}")
            
            self.server_thread = threading.Thread(target=self.server.serve_forever)
            self.server_thread.daemon = True
            self.server_thread.start()
            
        except Exception as e:
            logger.error(f"💥 Failed to start SMTP server: {e}")
            raise
        
    def stop(self):
        if self.server:
            self.server.shutdown()
            self.server.server_close()
            logger.info("🛑 SMTP server stopped")

# ==================== EMAIL PROCESSOR ====================
class EmailQueueProcessor:
    def __init__(self):
        self.redis_client = redis.Redis(**REDIS_CONFIG)
        self.queue_key = QUEUE_KEY
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

    # Determine envelope-from (use sender_name if it's an email, else use fallback)
    if isinstance(sender_name, str) and '@' in sender_name:
        envelope_from = sender_name
    else:
        envelope_from = f"no-reply@{socket.getfqdn()}"

    for recipient in batch:
        try:
            # Rate limiting
            while not self.rate_limiter.can_send(mx_server.host, mx_server.port):
                wait_time = self.rate_limiter.time_until_next_slot(mx_server.host, mx_server.port)
                logger.info(f"Rate limit reached for {mx_server.host}:{mx_server.port}, waiting {wait_time:.2f}s")
                time.sleep(wait_time)

            logger.info(f"➡️ Connecting to MX {mx_server.host}:{mx_server.port} for recipient {recipient}")

            # Build MIME message
            msg = MIMEMultipart('alternative')
            msg['From'] = envelope_from
            msg['To'] = recipient
            msg['Subject'] = subject
            msg['Message-ID'] = email.utils.make_msgid()
            msg['Date'] = email.utils.formatdate(localtime=True)

            if content_type.lower() == 'html' or content_type.lower() == 'html':
                part = MIMEText(content, 'html')
            else:
                part = MIMEText(content, 'plain')
            msg.attach(part)

            # Prepare raw message bytes for DKIM signing
            raw = msg.as_bytes(policy=policy.SMTP)

            # Determine DKIM signing domain (attempt to use envelope domain)
            try:
                signing_domain = envelope_from.split('@', 1)[1]
            except Exception:
                signing_domain = socket.getfqdn()

            # DKIM sign
            signed_message = self.tls_manager.sign_email(raw, signing_domain, selector='default')

            smtp = None
            try:
                # Choose SSL vs plain
                if mx_server.port == 465:
                    smtp = smtplib.SMTP_SSL(mx_server.host, mx_server.port, timeout=20)
                    logger.info(f"🔒 Connected with SSL to {mx_server.host}:{mx_server.port}")
                else:
                    smtp = smtplib.SMTP(mx_server.host, mx_server.port, timeout=20)
                    smtp.ehlo()
                    logger.info(f"✅ Connected to {mx_server.host}:{mx_server.port}, ehlo complete")
                    # Try STARTTLS if available
                    try:
                        if smtp.has_extn('STARTTLS'):
                            smtp.starttls()
                            smtp.ehlo()
                            logger.info(f"🔐 STARTTLS negotiated with {mx_server.host}:{mx_server.port}")
                    except Exception as e:
                        logger.debug(f"STARTTLS not used/failed for {mx_server.host}:{mx_server.port}: {e}")

                # Send the message
                # smtplib in Python 3.12 accepts bytes payloads. If you encounter issues,
                # convert to str with appropriate encoding (but that can break DKIM).
                smtp.sendmail(envelope_from, [recipient], signed_message)
                self.rate_limiter.record_send(mx_server.host, mx_server.port)
                successful.append(recipient)
                logger.info(f"📤 Successfully sent email to {recipient} via {mx_server.host}:{mx_server.port}")

            except Exception as e:
                failed.append(recipient)
                logger.error(f"❌ Failed sending to {recipient} via {mx_server.host}:{mx_server.port}: {e}")
            finally:
                if smtp:
                    try:
                        smtp.quit()
                    except Exception:
                        try:
                            smtp.close()
                        except Exception:
                            pass

        except Exception as e:
            failed.append(recipient)
            logger.error(f"❌ Unexpected error preparing to send to {recipient}: {e}")

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
        
        # Start HAProxy SMTP server
        self.haproxy_server = HAProxySMTPServer('0.0.0.0', SMTP_PORT, self, use_ssl=True)
        self.haproxy_server.start()
        
        logger.info("Email daemon started successfully")

    def stop(self):
        self.running = False
        if self.haproxy_server:
            self.haproxy_server.stop()
        logger.info("Email daemon stopped")

# ==================== MAIN EXECUTION ====================
def main():
    logger.info("=" * 60)
    logger.info("🚀 STARTING EMAIL DAEMON")
    logger.info("=" * 60)
    
    processor = EmailQueueProcessor()
    
    try:
        processor.start()
        logger.info("✅ Email daemon started successfully!")
        logger.info("📡 Waiting for HAProxy connections...")
        logger.info("💡 Messages will be broadcast to all active terminals")
        
        while True:
            time.sleep(10)
            broadcast_handler.refresh_terminals()
            
    except KeyboardInterrupt:
        logger.info("\n🛑 Shutting down gracefully...")
        processor.stop()
    except Exception as e:
        logger.error(f"💥 Fatal error: {e}")
        import traceback
        logger.error(traceback.format_exc())
        processor.stop()

if __name__ == "__main__":
    main()