#!/usr/bin/env python3
"""
Cleaned Email Daemon - Plain SMTP inbound, DKIM signing outbound, direct MX relay.
- No HAProxy/health-check special-case logging.
- Only logs real SMTP actions: EHLO/HELO, MAIL FROM, RCPT TO, DATA start/end, QUIT and errors.
- Robust MAIL/RCPT parsing using email.utils.parseaddr; trims ESMTP params (SIZE=..., ORCPT=..., etc.)
- DKIM signing for outbound (if private key available).
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
logger.setLevel(logging.INFO)  # only log INFO+ (actual SMTP actions & errors)

# Remove existing handlers
for h in logger.handlers[:]:
    logger.removeHandler(h)

file_handler = logging.FileHandler(f'{LOG_DIR}/email_daemon.log')
stream_handler = logging.StreamHandler()
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
file_handler.setFormatter(formatter)
stream_handler.setFormatter(formatter)
logger.addHandler(file_handler)
logger.addHandler(stream_handler)

# ==================== UTILITIES ====================
_EMAIL_RE = re.compile(r'^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$')

def extract_address(command: str) -> str | None:
    """
    Extracts the email address between <> in SMTP commands like:
    MAIL FROM:<user@example.com>
    RCPT TO:<dest@example.com>
    """
    match = re.search(r'<([^<>]+)>', command)
    return match.group(1) if match else None

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
        if not self.private_key:
            return raw_bytes
        try:
            domain = (mail_from.split('@', 1)[1]).lower()
        except Exception:
            return raw_bytes
        selector = DKIM_SELECTOR.encode()
        d = domain.encode()
        headers = [b'from', b'to', b'subject', b'date', b'message-id']
        try:
            sig = dkim.sign(
                message=raw_bytes,
                selector=selector,
                domain=d,
                privkey=self.private_key,
                include_headers=headers,
            )
            return sig + raw_bytes
        except Exception as e:
            logger.warning(f"DKIM signing failed: {e}")
            return raw_bytes

# ==================== SMTP SERVER (INBOUND) ====================
class SMTPRequestHandler(socketserver.BaseRequestHandler):
    """
    Plain SMTP handler — minimal, logs only SMTP actions.
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
            greeting = f'220 {socket.gethostname()} ESMTP ready\r\n'
            self.request.sendall(greeting.encode())
        except Exception:
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
                    self.process_smtp_command(line)
            except socket.timeout:
                break
            except (ConnectionResetError, BrokenPipeError):
                break
            except Exception:
                break

    def process_smtp_command(self, line: str):
        if not line:
            return

        # If the first line is a PROXY header (HAProxy send-proxy), ignore it silently.
        if line.startswith('PROXY '):
            return

        if self.state == 'COMMAND':
            self.process_smtp_command_state(line)
        else:
            self.process_data_line(line)

    def process_smtp_command_state(self, line: str):
        i = line.find(' ')
        if i < 0:
            command = line.upper()
            arg = None
        else:
            command = line[:i].upper()
            arg = line[i+1:].strip()
        method_name = 'smtp_' + command
        if not hasattr(self, method_name):
            self.send_response('502 5.5.2 Error: command not implemented')
            return
        getattr(self, method_name)(arg)

    def process_data_line(self, line: str):
        if line == '.':
            # end of DATA
            self.smtp_DATA_end()
        else:
            if line.startswith('..'):
                line = line[1:]
            self.data_lines.append(line)

    def send_response(self, response: str):
        try:
            self.request.sendall((response + '\r\n').encode())
        except Exception:
            self.connected = False

    # --- SMTP commands (only log actual actions) ---
    def smtp_EHLO(self, arg):
        if not arg:
            self.send_response('501 5.5.4 Syntax: EHLO hostname')
            return
        self.send_response(f'250-{socket.gethostname()}')
        self.send_response('250-8BITMIME')
        self.send_response('250-PIPELINING')
        self.send_response('250-SIZE 10485760')
        self.send_response('250 HELP')
        logger.info(f"EHLO {arg}")

    def smtp_HELO(self, arg):
        if not arg:
            self.send_response('501 5.5.4 Syntax: HELO hostname')
            return
        self.send_response(f'250 {socket.gethostname()}')
        logger.info(f"HELO {arg}")

    def smtp_NOOP(self, arg):
        self.send_response('250 2.0.0 OK')

    def smtp_QUIT(self, arg):
        self.send_response('221 2.0.0 Bye')
        logger.info("QUIT")
        self.connected = False

    def smtp_MAIL(self, arg):
        if not arg:
            self.send_response("501 5.5.4 Syntax: MAIL FROM:<address>")
            return

        # extract after first ':' if present
        if ':' in arg:
            raw = arg.split(':', 1)[1].strip()
        else:
            raw = arg.strip()

        # token = first whitespace-separated token (drop params like SIZE=)
        token = raw.split(None, 1)[0] if raw else ''

        # null sender
        if token == '<>' or token == '':
            self.mailfrom = ''
            self.send_response('250 2.1.0 OK')
            logger.info("MAIL FROM: <> (null sender)")
            return

        # use parseaddr to get bare address
        addr = extract_address(token)
        # addr = addr.strip()

        if not addr or not EmailValidator.validate_email_format(addr):
            self.send_response("553 5.1.7 Invalid sender address")
            logger.info(f"MAIL FROM rejected: {token}")
            return

        self.mailfrom = addr
        self.send_response("250 2.1.0 OK")
        logger.info(f"MAIL FROM: {self.mailfrom}")

    def smtp_RCPT(self, arg):
        if self.mailfrom is None:
            self.send_response('503 5.5.1 Need MAIL before RCPT')
            return
        if not arg:
            self.send_response('501 5.5.4 Syntax: RCPT TO:<address>')
            return

        if ':' in arg:
            raw = arg.split(':', 1)[1].strip()
        else:
            raw = arg.strip()

        token = raw.split(None, 1)[0] if raw else ''
        _, addr = parseaddr(token)
        addr = addr.strip()

        if not addr or not EmailValidator.validate_email_format(addr):
            self.send_response('553 5.1.7 Invalid recipient address')
            logger.info(f"RCPT TO rejected: {token}")
            return

        self.rcpttos.append(addr)
        self.send_response('250 2.1.5 OK')
        logger.info(f"RCPT TO: {addr}")

    def smtp_RSET(self, arg):
        self.mailfrom = None
        self.rcpttos = []
        self.data_lines = []
        self.state = 'COMMAND'
        self.send_response('250 2.0.0 OK')
        logger.info("RSET")

    def smtp_DATA(self, arg):
        if not self.rcpttos:
            self.send_response('503 5.5.1 Need RCPT before DATA')
            return
        self.send_response('354 3.0.0 End data with <CR><LF>.<CR><LF>')
        self.state = 'DATA'
        logger.info("DATA start")

    def smtp_STARTTLS(self, arg):
        self.send_response('454 4.7.0 TLS not available')

    def smtp_HELP(self, arg):
        self.send_response('214 2.0.0 Supported: EHLO, HELO, MAIL, RCPT, DATA, RSET, NOOP, QUIT')

    def smtp_DATA_end(self):
        try:
            raw_body = '\r\n'.join(self.data_lines) + '\r\n'
            msg_bytes = raw_body.encode('utf-8', errors='replace')

            # attempt to parse headers; if missing, add minimal headers
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

            # enqueue for delivery
            self.processor.add_to_queue(
                mail_from=self.mailfrom if self.mailfrom is not None else '',
                rcpt_to=list(self.rcpttos),
                raw_message=msg_bytes,
            )
            self.send_response('250 2.0.0 OK: Message queued for delivery')
            logger.info(f"Queued message from={self.mailfrom} to={len(self.rcpttos)} recipient(s)")
        except Exception as e:
            self.send_response('451 4.3.0 Error: Failed to process message')
            logger.error(f"DATA processing error: {e}")
        finally:
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

                signed_bytes = self.tls_manager.sign_raw_message(raw_message, mail_from)

                grouped = defaultdict(list)
                for addr in rcpt_to:
                    try:
                        domain = addr.split('@', 1)[1].lower()
                        if EmailValidator.is_banned_tld(domain) or EmailValidator.is_blocklisted_domain(domain):
                            logger.info(f"Blocked recipient domain: {domain}")
                            continue
                        grouped[domain].append(addr)
                    except Exception:
                        logger.info(f"Invalid recipient skipped: {addr}")

                succ_total, fail_total = 0, 0
                for domain, recipients in grouped.items():
                    mx_list = self.get_mx_servers(domain)
                    if not mx_list:
                        fail_total += len(recipients)
                        continue
                    sent, failed = self.send_via_mx_list(mail_from, recipients, signed_bytes, mx_list)
                    succ_total += len(sent)
                    fail_total += len(failed)

                if succ_total or fail_total:
                    logger.info(f"Delivery result: {succ_total} sent, {fail_total} failed")
            except Exception as e:
                logger.error(f"Queue error: {e}")
                time.sleep(2)

    def ping_mx_server(self, host, port):
        try:
            with socket.create_connection((host, port), timeout=10) as s:
                s.settimeout(5)
                try:
                    banner = s.recv(1024)
                except Exception:
                    banner = b''
                return banner.startswith(b'220')
        except Exception:
            return False

    def get_mx_servers(self, domain):
        if domain in self._mx_cache and (time.time() - self._mx_cache[domain]['ts']) < 3600:
            return self._mx_cache[domain]['list']
        try:
            answers = dns.resolver.resolve(domain, 'MX')
            mx_records = sorted([(r.preference, str(r.exchange).rstrip('.')) for r in answers])
        except Exception:
            mx_records = []
        candidates = []
        valid_ports = [25, 587, 465, 2525]
        for _pref, host in mx_records:
            for port in valid_ports:
                if self.ping_mx_server(host, port):
                    candidates.append(MX_Server(host, port))
        self._mx_cache[domain] = {'ts': time.time(), 'list': candidates}
        return candidates

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
                    break
            except Exception as e:
                logger.info(f"MX {mx.host}:{mx.port} failed: {e}")
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
                try:
                    if 'starttls' in server.esmtp_features:
                        server.starttls(context=ssl.create_default_context())
                        server.ehlo()
                except Exception:
                    pass

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

    def start(self):
        self.running = True
        self.queue_thread = threading.Thread(target=self.process_queue, daemon=True)
        self.queue_thread.start()

        class HandlerFactory:
            def __init__(self, processor):
                self.processor = processor
            def __call__(self, request, client_address, server):
                # Attach the processor so handler can queue messages & log properly
                server.processor = self.processor
                return SMTPRequestHandler(request, client_address, server)

        self.server = PlainTCPServer(('0.0.0.0', SMTP_PORT), HandlerFactory(self))
        logger.info(f"SMTP server listening on 0.0.0.0:{SMTP_PORT}")
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
    logger.info("STARTING EMAIL DAEMON (Plain SMTP + DKIM)")
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
