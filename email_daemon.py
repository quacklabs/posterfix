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
    level=logging.DEBUG,  # Changed to DEBUG for more details
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/var/log/email_daemon/email_daemon.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('EmailDaemon')

# Modern TCP server
class ThreadedTCPServer(ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True
    timeout = 5
    
    def __init__(self, server_address, handler_class, processor):
        super().__init__(server_address, handler_class)
        self.processor = processor
        
    def get_request(self):
        socket, addr = super().get_request()
        socket.settimeout(10)
        logger.info(f"New connection from {addr}")
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
        super().__init__(request, client_address, server)

    def setup(self):
        try:
            client_ip, client_port = self.client_address
            logger.info(f"Connection established from {client_ip}:{client_port}")
            
            # Send immediate SMTP greeting
            greeting = '220 %s ESMTP Email Daemon ready\r\n' % socket.getfqdn()
            self.request.sendall(greeting.encode())
            logger.debug("SMTP greeting sent")
            
        except Exception as e:
            logger.error(f"Error in setup: {e}")
            self.connected = False

    def handle(self):
        client_ip, client_port = self.client_address
        logger.info(f"Handling connection from {client_ip}:{client_port}")
        
        if not self.connected:
            return
            
        while self.connected:
            try:
                self.request.settimeout(30.0)  # Longer timeout for HAProxy
                
                data = self.request.recv(1024)
                if not data:
                    logger.info(f"Client {client_ip} disconnected gracefully")
                    break
                    
                logger.debug(f"Received data from {client_ip}: {data.hex()}")
                self.received_data += data
                
                # Process complete lines only
                while b'\r\n' in self.received_data:
                    line_end = self.received_data.find(b'\r\n')
                    line_data = self.received_data[:line_end]
                    
                    try:
                        line = line_data.decode('utf-8').strip()
                    except UnicodeDecodeError:
                        line = line_data.decode('latin-1').strip()
                        
                    self.received_data = self.received_data[line_end + 2:]
                    
                    if line:
                        logger.debug(f"Processing line from {client_ip}: {line}")
                        self.process_line(line)
                    
            except socket.timeout:
                logger.warning(f"Socket timeout with {client_ip}, closing connection")
                break
            except (ConnectionResetError, BrokenPipeError):
                logger.info(f"Client {client_ip} connection reset")
                break
            except Exception as e:
                logger.error(f"Error handling request from {client_ip}: {e}")
                break
        logger.info(f"Ending connection with {client_ip}")

    def process_line(self, line):
        if self.state == 'COMMAND':
            self.process_command(line)
        elif self.state == 'DATA':
            self.process_data_line(line)

    def process_command(self, line):
        if not line:
            self.send_response('500 Error: bad syntax')
            return
            
        # Handle HAProxy health checks specifically
        if line.upper() == 'EHLO' or line.upper().startswith('EHLO '):
            # This is likely HAProxy health check
            logger.info("HAProxy health check detected")
            self.send_response('250-%s' % socket.getfqdn())
            self.send_response('250-8BITMIME')
            self.send_response('250-PIPELINING')
            self.send_response('250-SIZE 10485760')
            self.send_response('250 HELP')
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
            # Your existing DATA processing code
            msg = BytesParser(policy=policy.default).parsebytes(self.data.encode())
            # ... rest of your DATA processing code
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
    """SMTP server for HAProxy connections"""
    
    def __init__(self, host, port, processor):
        self.processor = processor
        self.host = host
        self.port = port
        self.server = None
        
    def start(self):
        """Start the SMTP server"""
        class HandlerFactory:
            def __init__(self, processor):
                self.processor = processor
                
            def __call__(self, *args):
                return SMTPRequestHandler(*args)
        
        class CustomServer(ThreadedTCPServer):
            def __init__(self, server_address, handler_class, processor):
                super().__init__(server_address, handler_class, processor)
                self.processor = processor
        
        handler_factory = HandlerFactory(self.processor)
        
        try:
            self.server = CustomServer((self.host, self.port), handler_factory, self.processor)
            self.server.socket.settimeout(30)
            
            # Get the actual IP and port being listened on
            server_ip, server_port = self.server.server_address
            logger.info(f"HAProxy SMTP server listening on {server_ip}:{server_port}")
            
            # Test that the port is actually open
            test_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            test_socket.settimeout(2)
            result = test_socket.connect_ex((self.host, self.port))
            test_socket.close()
            
            if result == 0:
                logger.info(f"Port {self.port} is open and accessible")
            else:
                logger.warning(f"Port {self.port} may not be accessible from network")
            
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

# ... REST OF YOUR CODE REMAINS THE SAME (RateLimiter, EmailValidator, MX_Server, EmailQueueProcessor classes) ...

# Add network diagnostics
def check_network_configuration():
    """Check network configuration and accessibility"""
    try:
        # Get server IP
        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)
        logger.info(f"Server hostname: {hostname}")
        logger.info(f"Server local IP: {local_ip}")
        
        # Check if port 3000 is open locally
        test_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        test_sock.settimeout(2)
        result = test_sock.connect_ex(('127.0.0.1', 3000))
        test_sock.close()
        
        if result == 0:
            logger.info("Port 3000 is open locally")
        else:
            logger.warning("Port 3000 is not open locally")
            
    except Exception as e:
        logger.error(f"Network configuration check failed: {e}")

# Main execution
if __name__ == "__main__":
    # Run network diagnostics
    check_network_configuration()
    
    processor = EmailQueueProcessor()
    
    try:
        processor.start()
        logger.info("Email daemon started successfully. Waiting for HAProxy connections...")
        
        while True:
            time.sleep(10)
            # Log active connections periodically
            logger.debug("Daemon heartbeat - still running")
            
    except KeyboardInterrupt:
        processor.stop()
    except Exception as e:
        logger.error(f"Fatal error in main: {e}")
        processor.stop()