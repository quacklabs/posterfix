import ssl
import dkim
from email.utils import formataddr
from config import DKIM_PRIVATE_KEY_PATH, DKIM_SELECTOR, DKIM_DOMAIN

class TLSManager:
    def __init__(self):
        self.private_key = self.load_private_key(DKIM_PRIVATE_KEY_PATH)
    
    def get_tls_context(self):
        """Returns SSL context for secure email connection."""
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE  # Disable cert verification for now (can be adjusted later)
        return context
    
    def sign_email(self, msg):
        """Signs email with DKIM."""
        if not self.private_key:
            raise ValueError("DKIM private key is not loaded.")
        
        # Create DKIM signature headers
        dkim_header = dkim.sign(
            msg.as_bytes(),
            selector=DKIM_SELECTOR,
            domain=DKIM_DOMAIN,
            privkey=self.private_key,
            include_headers=['From', 'To', 'Subject', 'Date', 'Message-ID']
        )
        
        msg['DKIM-Signature'] = dkim_header.decode()  # Add DKIM signature header
        return msg

    def load_private_key(self, path):
        """Loads the DKIM private key."""
        try:
            with open(path, 'rb') as f:
                return f.read()
        except Exception as e:
            raise ValueError(f"Error loading private key: {e}")
