"""
Email validation functionality
"""
import re

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
        return not any(word in text.lower() for word in [
            'viagra', 'casino', 'lottery', 'prize', 'winner', 'free', 'money',
            'credit', 'loan', 'mortgage', 'drug', 'pharmacy', 'prescription'
        ])

    @staticmethod
    def is_banned_tld(domain):
        """Check if domain has banned TLD"""
        return any(domain.endswith(tld) for tld in [
            '.xyz', '.top', '.club', '.info', '.bid', '.win', '.loan', '.work'
        ])

    @staticmethod
    def is_blocklisted_domain(domain):
        """Check if domain is in blocklist"""
        return domain in [
            'example.com', 'test.com', 'spam.com'
        ]