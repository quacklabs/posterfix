"""
SMTP Server classes for handling connections
"""
import socket
import ssl
import socketserver
import threading
from socketserver import ThreadingMixIn

from ..handlers.smtp_handler import SMTPRequestHandler
from .. import config

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
        
        # Check if this is an SSL connection
        try:
            peek_data = socket.recv(5, socket.MSG_PEEK)
            if len(peek_data) >= 5 and self.is_ssl_handshake(peek_data):
                if self.ssl_context:
                    try:
                        socket = self.ssl_context.wrap_socket(socket, server_side=True)
                    except ssl.SSLError as e:
                        # Fall back to plain TCP
                        pass
            # Always return the socket (SSL or plain)
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
        """Setup SSL context for secure connections"""
        try:
            self.ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            self.ssl_context.load_cert_chain(
                certfile=config.SSL_CERT_PATH,
                keyfile=config.SSL_KEY_PATH
            )
            self.ssl_context.set_ciphers('ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:ECDH+AESGCM:DH+AESGCM:ECDH+AES256:DH+AES256:ECDH+AES128:DH+AES:RSA+AESGCM:RSA+AES:!aNULL:!MD5:!DSS')
            self.ssl_context.check_hostname = False
            self.ssl_context.verify_mode = ssl.CERT_NONE
            
        except Exception as e:
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
            
            self.server_thread = threading.Thread(target=self.server.serve_forever)
            self.server_thread.daemon = True
            self.server_thread.start()
            
        except Exception as e:
            raise
        
    def stop(self):
        if self.server:
            self.server.shutdown()
            self.server.server_close()