"""
SMTP Request Handler for processing SMTP commands
"""
import logging
import socket
import time
import re
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr

from ..processors.validator import EmailValidator
from .. import config

logger = logging.getLogger('EmailDaemon')

class SMTPRequestHandler:
    def __init__(self, request, client_address, server):
        self.processor = server.processor
        self.data = b''
        self.mailfrom = None
        self.rcpttos = []
        self.received_data = b''
        self.state = 'COMMAND'
        self.connected = True
        self.client_ip, self.client_port = client_address
        self.session_id = f"{client_ip[0]}:{client_ip[1]}-{int(time.time())}"
        self.validator = EmailValidator()
        
    def setup(self):
        try:
            logger.info(f"🔄 NEW CONNECTION [{self.session_id}] from {self.client_ip}:{self.client_port}")
            
            # Send immediate SMTP greeting
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
        """Process SMTP commands with enhanced HAProxy support"""
        if self.is_haproxy_health_check(line):
            self.handle_haproxy_health_check(line)
            return
            
        if self.state == 'COMMAND':
            self.process_smtp_command_state(line)
        elif self.state == 'DATA':
            self.process_data_line(line)

    def is_haproxy_health_check(self, line):
        """Enhanced HAProxy health check detection"""
        line_upper = line.upper()
        
        # HAProxy health check patterns
        patterns = [
            line_upper == 'EHLO',
            line_upper.startswith('EHLO '),
            line_upper == 'HELO', 
            line_upper.startswith('HELO '),
            line_upper == 'QUIT',
            line_upper == 'NOOP',
            any(domain in line_upper for domain in config.HAPROXY_HEALTH_CHECK_DOMAINS),
            len(line_upper) < 20
        ]
        
        return any(patterns)

    def handle_haproxy_health_check(self, line):
        """Handle HAProxy health check commands with detailed logging"""
        line_upper = line.upper()
        logger.info(f"🏥 [{self.session_id}] HAProxy health check: {line}")
        
        if line_upper == 'QUIT':
            self.send_response('221 2.0.0 Bye')
            self.connected = False
            logger.info(f"✅ [{self.session_id}] Health check completed with QUIT")
            return
            
        elif line_upper == 'NOOP':
            self.send_response('250 2.0.0 OK')
            logger.info(f"✅ [{self.session_id}] Responded to NOOP")
            return
            
        elif line_upper.startswith('EHLO ') or line_upper == 'EHLO':
            self.send_response('250-%s' % socket.getfqdn())
            self.send_response('250-8BITMIME')
            self.send_response('250-PIPELINING')
            self.send_response('250-SIZE 10485760')
            self.send_response('250-AUTH PLAIN LOGIN')
            self.send_response('250-ENHANCEDSTATUSCODES')
            self.send_response('250 HELP')
            logger.info(f"✅ [{self.session_id}] Responded to EHLO health check")
            return
            
        elif line_upper.startswith('HELO ') or line_upper == 'HELO':
            self.send_response('250 %s' % socket.getfqdn())
            logger.info(f"✅ [{self.session_id}] Responded to HELO health check")
            return
            
        else:
            self.send_response('250 2.0.0 OK')
            logger.info(f"✅ [{self.session_id}] Responded to unknown health check")

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
            
        addr = arg[5:].strip()
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