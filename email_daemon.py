#!/usr/bin/env python3
"""
Email Daemon - Plain SMTP inbound, DKIM signing outbound, direct MX relay
- No HAProxy health-check special cases
- No inbound SSL/TLS or STARTTLS; pure plaintext SMTP listener
- Outbound SMTP may use STARTTLS/SSL when talking to remote MX
- Robust MAIL/RCPT parsing using parseaddr; strips ESMTP params (SIZE=..., ORCPT=..., etc.)
- If a PROXY protocol header is present as the first line, it will be ignored.
"""
import time
import logging
import redis
import ssl
import socket
import re
import dns.resolver
import json
import queue
import socketserver
import threading
import email
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr, formatdate, make_msgid
from collections import deque, defaultdict
import dkim
import os

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
DKIM_SELECTOR = 'default'            # update if needed

SMTP_PORT = 3000
LOG_DIR = '/var/log/email_daemon'
QUEUE_KEY = 'email_queue'

# ==================== LOGGING SETUP ====================
os.makedirs(LOG_DIR, exist_ok=True)
logger = logging.getLogger('EmailDaemon')
logger.setLevel(logging.DEBUG)

for h in logger.handlers[:]:
    logger.removeHandler(h)

file_handler = logging.FileHandler(f'{LOG_DIR}/email_daemon.log')
stream_handler = logging.StreamHandler()
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
file_handler.setFormatter(formatter)
stream_handler.setFormatter(formatter)
logger.addHandler(file_handler)
logger.addHandler(stream_handler)

# ==================== UTILITIES ====================
_EMAIL_RE = re.compile(r'^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$')

class EmailValidator:
    @staticmethod
    def validate_email_format(email_address: str) -> bool:
        if not email_address:
            return False
        s = str(email_address).strip()
        return bool(_EMAIL_RE.fullmatch(s))

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
            return len(self.sent_times[key]) < limit

    def record_send(self, host, port):
        with self.lock:
            key = (host, port)
            self.sent_times[key].append(time.time())

    def time_until_next_slot(self, host, port):
        with self.lock:
            key = (host, port)
            limit = self.limits.get(key, self.default_limit_per_hour)
            count = len(self.sent_times[key])
            if count < limit:
                return 0
            oldest = self.sent_times[key][0]
            return max(0, 3600 - (time.time() - oldest))

# ==================== TLS / DKIM MANAGER ====================
class TLSManager:
    def __init__(self):
        try:
            self.private_key = self.load_private_key(DKIM_PRIVATE_KEY_PATH)
        except Exception as e:
            logger.warning(f"Could not load DKIM private key ({DKIM_PRIVATE_KEY_PATH}): {e}")
            self.private_key = None

    def load_private_key(self, path):
        with open(path, 'rb') as f:
            return f.read()

    def sign_raw_message(self, raw_bytes: bytes, mail_from: str) -> bytes:
        # If we don't have a key, return raw message unchanged
        if not self.private_key:
            return raw_bytes

        # derive signing domain from envelope sender
        try:
            domain = (mail_from.split('@', 1)[1]).lower()
        except Exception:
            # Can't determine domain -> skip signing
            return raw_bytes

        selector = DKIM_SELECTOR.encode()
        d = domain.encode()
        # include common headers
        headers = [b'from', b'to', b'subject', b'date', b'message-id']
        try:
            sig = dkim.sign(
                message=raw_bytes,
                selector=selector,
                domain=d,
                privkey=self.private_key,
                include_headers=headers,
            )
            # dkim.sign returns a b"DKIM-Signature: ..." header line + CRLF
            return sig + raw_bytes
        except Exception as e:
            logger.warning(f"DKIM signing failed: {e}")
            return raw_bytes

# ==================== SMTP SERVER (INBOUND) ====================
class SMTPRequestHandler(socketserver.BaseRequestHandler):
    """
    Plain SMTP handler:
    - Greets client immediately
    - Accepts commands EHLO/HELO/MAIL/RCPT/DATA/RSET/NOOP/QUIT/HELP
    - Robust MAIL/RCPT parsing using parseaddr; trims parameters like SIZE=...
    - Ignores a leading PROXY protocol line if present
    """

    def __init__(self, request, client_address, server):
        self.processor = server.processor
        self.data_lines = []
        self.mailfrom = None   # None = not set, "" = null sender allowed
        self.rcpttos = []
        self.state = 'COMMAND'
        self.connected = True
        super().__init__(request, client_address, server)

    def setup(self):
        try:
            greeting = f'220 {socket.gethostname()} ESMTP Email Daemon ready\r\n'
            self.request.sendall(greeting.encode())
            logger.info(f"🔄 NEW CONNECTION from {self.client_address[0]}:{self.client_address[1]}")
            logger.info(f"📤 Sent: 220 ESMTP ready")
        except Exception as e:
            logger.error(f"Setup error: {e}")
            self.connected = False

    def handle(self):
        if not self.connected:
            return
        buffer = b''
        while self.connected:
            try:
                self.request.settimeout(60.0)
                data = self.request.recv(4096)
                if not data:
                    logger.info("Client disconnected")
                    break
                buffer += data
                while b'\r\n' in buffer:
                    line_end = buffer.find(b'\r\n')
                    raw_line = buffer[:line_end]
                    buffer = buffer[line_end + 2:]
                    try:
                        line = raw_line.decode('utf-8', errors='ignore')
                    except Exception:
                        line = raw_line.decode('latin-1', errors='ignore')
                    logger.debug(f"📥 Received: {line}")
                    self.process_smtp_command(line)
            except socket.timeout:
                logger.warning("Socket timeout, closing connection")
                break
            except (ConnectionResetError, BrokenPipeError):
                logger.info("Connection reset by peer")
                break
            except Exception as e:
                logger.error(f"Handle error: {e}")
                break

    def process_smtp_command(self, line: str):
        """
        High level dispatcher. Ignores PROXY header lines if they appear.
        """
        if not line:
            return

        # If HAProxy was configured with send-proxy, we may receive a PROXY header first.
        # Ignore it so we don't treat it as an SMTP command.
        if line.startswith('PROXY '):
            logger.debug("Ignored PROXY protocol header")
            return

        if self.state == 'COMMAND':
            self.process_smtp_command_state(line)
        elif self.state == 'DATA':
            self.process_data_line(line)

    def process_smtp_command_state(self, line: str):
        # split into command and rest (arg)
        i = line.find(' ')
        if i < 0:
            command = line.upper()
            arg = None
        else:
            command = line[:i].upper()
            arg = line[i+1:].strip()
        method_name = 'smtp_' + command
        if not hasattr(self, method_name):
            self.send_response(f'502 5.5.2 Error: command "{command}" not implemented')
            return
        getattr(self, method_name)(arg)

    def process_data_line(self, line: str):
        if line == '.':
            self.smtp_DATA_end()
        else:
            # dot-stuffing support
            if line.startswith('..'):
                line = line[1:]
            self.data_lines.append(line)

    def send_response(self, response: str):
        try:
            self.request.sendall((response + '\r\n').encode())
            logger.info(f"📤 Sent: {response}")
        except Exception as e:
            logger.error(f"Send error: {e}")
            self.connected = False

    # SMTP command handlers
    def smtp_EHLO(self, arg):
        if not arg:
            self.send_response('501 5.5.4 Syntax: EHLO hostname')
            return
        self.send_response(f'250-{socket.gethostname()}')
        self.send_response('250-8BITMIME')
        self.send_response('250-PIPELINING')
        self.send_response('250-SIZE 10485760')
        self.send_response('250 HELP')

    def smtp_HELO(self, arg):
        if not arg:
            self.send_response('501 5.5.4 Syntax: HELO hostname')
            return
        self.send_response(f'250 {socket.gethostname()}')

    def smtp_NOOP(self, arg):
        self.send_response('250 2.0.0 OK')

    def smtp_QUIT(self, arg):
        self.send_response('221 2.0.0 Bye')
        self.connected = False

    def smtp_MAIL(self, arg):
        """
        Robust MAIL FROM parser:
        - Accepts: MAIL FROM:<user@example.com> SIZE=nnn
        - Accepts null sender: MAIL FROM:<>
        - Uses email.utils.parseaddr to extract address safely
        """
        if not arg:
            self.send_response("501 5.5.4 Syntax: MAIL FROM:<address>")
            return

        # some clients send 'FROM:<addr> PARAM=...' ; others may include multiple spaces
        # extract text after the first ':' if present
        try:
            # accept forms like 'FROM:<a@b>' or 'FROM: <a@b>'
            if ':' in arg:
                raw = arg.split(':', 1)[1].strip()
            else:
                raw = arg.strip()
        except Exception:
            raw = arg.strip()

        # split off any ESMTP parameters (SIZE=, BODY=, etc.)
        token = raw.split(None, 1)[0] if raw else ''

        # handle null sender explicitly
        if token == '<>' or token == '':
            self.mailfrom = ''
            self.send_response('250 2.1.0 OK')
            return

        # parseaddr handles angle brackets and quotes
        name, addr = parseaddr(token)
        addr = addr.strip()

        if not addr:
            self.send_response("553 5.1.7 Invalid sender address")
            return

        if not EmailValidator.validate_email_format(addr):
            self.send_response("553 5.1.7 Invalid sender address")
            return

        # store bare envelope sender
        self.mailfrom = addr
        logger.info(f"Envelope MAIL FROM set to: {self.mailfrom}")
        self.send_response("250 2.1.0 OK")

    def smtp_RCPT(self, arg):
        """
        Robust RCPT TO parser:
        - Accepts: RCPT TO:<user@domain> ORCPT=rfc822;...
        - Uses parseaddr and trims parameters
        """
        # mailfrom may be empty string for null sender (that's allowed)
        if self.mailfrom is None:
            self.send_response('503 5.5.1 Need MAIL before RCPT')
            return

        if not arg:
            self.send_response('501 5.5.4 Syntax: RCPT TO:<address>')
            return

        try:
            if ':' in arg:
                raw = arg.split(':', 1)[1].strip()
            else:
                raw = arg.strip()
        except Exception:
            raw = arg.strip()

        token = raw.split(None, 1)[0] if raw else ''

        # parseaddr will strip <> and quotes
        name, addr = parseaddr(token)
        addr = addr.strip()

        if not addr:
            self.send_response('553 5.1.7 Invalid recipient address')
            return

        # basic format validation
        if not EmailValidator.validate_email_format(addr):
            self.send_response('553 5.1.7 Invalid recipient address')
            return

        # append to recipients
        self.rcpttos.append(addr)
        logger.info(f"Added RCPT TO: {addr}")
        self.send_response('250 2.1.5 OK')

    def smtp_RSET(self, arg):
        self.mailfrom = None
        self.rcpttos = []
        self.data_lines = []
        self.state = 'COMMAND'
        self.send_response('250 2.0.0 OK')

    def smtp_DATA(self, arg):
        if not self.rcpttos:
            self.send_response('503 5.5.1 Need RCPT before DATA')
            return
        self.send_response('354 3.0.0 End data with <CR><LF>.<CR><LF>')
        self.state = 'DATA'

    def smtp_STARTTLS(self, arg):
        # Not supported for inbound in this daemon
        self.send_response('454 4.7.0 TLS not available')

    def smtp_HELP(self, arg):
        self.send_response('214 2.0.0 Supported: EHLO, HELO, MAIL, RCPT, DATA, RSET, NOOP, QUIT')

    def smtp_DATA_end(self):
        """
        Called once a \".\" line is received while in DATA state.
        Assembles the message, ensures minimal headers exist, queues for outbound delivery.
        """
        try:
            raw_body = '\r\n'.join(self.data_lines) + '\r\n'
            msg_bytes = raw_body.encode('utf-8', errors='replace')

            # Parse message (may be just body or full message with headers)
            try:
                parsed = BytesParser(policy=policy.default).parsebytes(msg_bytes)
            except Exception:
                parsed = None

            headers_to_add = []
            if (not parsed or not parsed['From']) and self.mailfrom:
                headers_to_add.append(f"From: <{self.mailfrom}>\r\n")
            if not parsed or not parsed['Date']:
                headers_to_add.append(f"Date: {formatdate(localtime=True)}\r\n")
            if not parsed or not parsed['Message-ID']:
                headers_to_add.append(f"Message-ID: {make_msgid()}\r\n")

            if headers_to_add:
                prefix = (''.join(headers_to_add)).encode()
                msg_bytes = prefix + msg_bytes

            # Queue full raw message (string in redis) for delivery
            self.processor.add_to_queue(
                mail_from=self.mailfrom if self.mailfrom is not None else '',
                rcpt_to=list(self.rcpttos),
                raw_message=msg_bytes,
            )
            self.send_response('250 2.0.0 OK: Message queued for delivery')
        except Exception as e:
            logger.error(f"DATA processing error: {e}")
            self.send_response('451 4.3.0 Error: Failed to process message')
        finally:
            # reset state
            self.data_lines = []
            self.state = 'COMMAND'
            self.mailfrom = None
            self.rcpttos = []

# ==================== TCP SERVER (no SSL sniffing) ====================
class PlainTCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

# ==================== OUTBOUND / QUEUE PROCESSOR ====================
class MX_Server:
    def __init__(self, host, port):
        self.host = host
        self.port = int(port)

class EmailQueueProcessor:
    def __init__(self):
        self.redis_client = redis.Redis(**REDIS_CONFIG)
        self.queue_key = QUEUE_KEY
        self.rate_limiter = RateLimiter(default_limit_per_hour=RATE_LIMIT)
        self._mx_cache = {}
        self.smtp_lock = threading.Lock()
        self.running = False
        self.local_queue = queue.Queue()
        self.tls_manager = TLSManager()
        self.server = None

    # --- Queue API ---
    def add_to_queue(self, mail_from: str, rcpt_to: list, raw_message: bytes):
        item = {
            'mail_from': mail_from,
            'rcpt_to': rcpt_to,
            'raw_message': raw_message.decode('utf-8', errors='replace'),
            'ts': time.time(),
        }
        try:
            self.redis_client.rpush(self.queue_key, json.dumps(item))
        except Exception as e:
            logger.error(f"Redis enqueue failed: {e}")
        self.local_queue.put(item)
        logger.info(f"Queued message to {len(rcpt_to)} recipient(s)")

    def process_queue(self):
        while self.running:
            try:
                try:
                    item = self.local_queue.get_nowait()
                except queue.Empty:
                    data = self.redis_client.blpop(self.queue_key, timeout=1)
                    if not data:
                        continue
                    item = json.loads(data[1])

                mail_from = item.get('mail_from', '')
                rcpt_to = item.get('rcpt_to', [])
                raw_message = item.get('raw_message', '').encode('utf-8', errors='replace')

                # DKIM sign (if key available)
                signed_bytes = self.tls_manager.sign_raw_message(raw_message, mail_from)

                # Group recipients by domain and validate
                grouped = defaultdict(list)
                for addr in rcpt_to:
                    try:
                        domain = addr.split('@', 1)[1].lower()
                        if EmailValidator.is_banned_tld(domain) or EmailValidator.is_blocklisted_domain(domain):
                            logger.warning(f"Blocked recipient domain: {domain}")
                            continue
                        grouped[domain].append(addr)
                    except Exception:
                        logger.warning(f"Invalid recipient: {addr}")

                succ_total, fail_total = 0, 0
                for domain, recipients in grouped.items():
                    mx_list = self.get_mx_servers(domain)
                    if not mx_list:
                        logger.error(f"No MX for {domain}")
                        fail_total += len(recipients)
                        continue
                    sent, failed = self.send_via_mx_list(mail_from, recipients, signed_bytes, mx_list)
                    succ_total += len(sent)
                    fail_total += len(failed)

                logger.info(f"Delivery result: {succ_total} sent, {fail_total} failed")
            except Exception as e:
                logger.error(f"Queue error: {e}")
                time.sleep(2)

    # --- MX discovery ---
    def ping_mx_server(self, host, port):
        try:
            with socket.create_connection((host, port), timeout=10) as s:
                s.settimeout(10)
                # Read banner first
                banner = b''
                try:
                    banner = s.recv(1024)
                except Exception:
                    pass
                return banner.startswith(b'220')
        except Exception:
            return False

    def get_mx_servers(self, domain):
        # cached for 1 hour
        if domain in self._mx_cache and (time.time() - self._mx_cache[domain]['ts']) < 3600:
            return self._mx_cache[domain]['list']
        try:
            answers = dns.resolver.resolve(domain, 'MX')
            mx_records = sorted([(r.preference, str(r.exchange).rstrip('.')) for r in answers])
        except Exception as e:
            logger.error(f"DNS MX lookup failed for {domain}: {e}")
            mx_records = []
        candidates = []
        valid_ports = [25, 587, 465, 2525]
        for _pref, host in mx_records:
            for port in valid_ports:
                if self.ping_mx_server(host, port):
                    candidates.append(MX_Server(host, port))
        self._mx_cache[domain] = {'ts': time.time(), 'list': candidates}
        return candidates

    # --- Outbound send ---
    def send_via_mx_list(self, mail_from, recipients, msg_bytes, mx_list):
        successful, failed = [], []
        for mx in mx_list:
            try:
                if not self.rate_limiter.can_send(mx.host, mx.port):
                    time.sleep(self.rate_limiter.time_until_next_slot(mx.host, mx.port))
                sent, failed_local = self._try_send(mx, mail_from, recipients, msg_bytes)
                successful.extend(sent)
                failed.extend(failed_local)
                if sent:
                    break  # stop if some recipients accepted by this MX
            except Exception as e:
                logger.warning(f"MX {mx.host}:{mx.port} failed: {e}")
                continue
        return successful, failed

    def _try_send(self, mx, mail_from, recipients, msg_bytes):
        import smtplib
        server = None
        try:
            if mx.port == 465:
                server = smtplib.SMTP_SSL(mx.host, mx.port, timeout=20)
            else:
                server = smtplib.SMTP(mx.host, mx.port, timeout=20)
                server.ehlo_or_helo_if_needed()
                # Try STARTTLS if offered
                try:
                    if 'starttls' in server.esmtp_features:
                        server.starttls(context=ssl.create_default_context())
                        server.ehlo()
                except Exception:
                    pass

            # MAIL FROM
            code, _ = server.mail(mail_from if mail_from is not None else '')
            if code not in (250, 251):
                raise RuntimeError(f"MAIL FROM rejected with {code}")

            accepted = []
            failed = []
            for rcpt in recipients:
                code, _ = server.rcpt(rcpt)
                if code in (250, 251):
                    accepted.append(rcpt)
                else:
                    failed.append(rcpt)

            if accepted:
                server.data(msg_bytes)

            try:
                server.quit()
            except Exception:
                try:
                    server.close()
                except Exception:
                    pass

            if accepted:
                self.rate_limiter.record_send(mx.host, mx.port)
            return accepted, failed
        except Exception:
            try:
                if server:
                    server.close()
            except Exception:
                pass
            raise

    # --- Server lifecycle ---
    def start(self):
        self.running = True
        self.queue_thread = threading.Thread(target=self.process_queue, daemon=True)
        self.queue_thread.start()

        class HandlerFactory:
            def __init__(self, processor):
                self.processor = processor
            def __call__(self, *args):
                return SMTPRequestHandler(*args)

        self.server = PlainTCPServer(('0.0.0.0', SMTP_PORT), HandlerFactory(self))
        logger.info(f"SMTP server listening on 0.0.0.0:{SMTP_PORT} (plaintext, no health-check special casing)")
        self.server_thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.server_thread.start()

    def stop(self):
        self.running = False
        try:
            if self.server:
                self.server.shutdown()
                self.server.server_close()
        except Exception:
            pass

# ==================== MAIN ====================
def main():
    logger.info("=" * 60)
    logger.info("🚀 STARTING EMAIL DAEMON (Plain SMTP + DKIM)")
    logger.info("=" * 60)
    processor = EmailQueueProcessor()
    try:
        processor.start()
        while True:
            time.sleep(10)
    except KeyboardInterrupt:
        logger.info("Shutting down...")
        processor.stop()
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        processor.stop()

if __name__ == '__main__':
    main()
