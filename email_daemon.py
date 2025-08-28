#!/usr/bin/env python3
import asyncio
import logging
import signal
import time
import email
from email import policy
from aiosmtpd.controller import Controller
import redis
import daemon
from pid import PidFile

from config import *
from dkim_sign import DKIMSigner
from tls_manager import TLSManager
from queue_processor import EmailQueueProcessor, EmailValidator

class RateLimitedSMTPHandler:
    def __init__(self):
        self.redis_client = redis.Redis(**REDIS_CONFIG)
        self.rate_limit_key = 'email_rate_limit'
        self.queue_key = 'email_queue'
        self.validator = EmailValidator()
        self.queue_processor = EmailQueueProcessor()

    async def handle_RCPT(self, server, session, envelope, address, rcpt_options):
        try:
            # Validate recipient format
            if not self.validator.validate_email_format(address):
                return '550 Invalid email address format'
            
            # Only accept emails for our domain
            if not address.lower().endswith('@' + LOCAL_DOMAIN.lower()):
                return '550 Not relaying to external domains'
            
            # Check recipient limit
            if len(envelope.rcpt_tos) >= MAX_RECIPIENTS_PER_EMAIL:
                return '550 Too many recipients'
            
            envelope.rcpt_tos.append(address.lower())
            return '250 OK'
            
        except Exception as e:
            logging.error(f"RCPT handling error: {e}")
            return '451 Temporary error'

    async def handle_DATA(self, server, session, envelope):
        try:
            # Validate email size
            if len(envelope.content) > MAX_EMAIL_SIZE:
                return '552 Message too large'
            
            # Parse email to extract subject and content
            msg = email.message_from_bytes(envelope.content, policy=policy.default)
            subject = msg.get('Subject', 'No Subject')
            content = self._extract_email_content(msg)
            
            # Prepare email data for queue
            email_data = {
                'recipients': envelope.rcpt_tos,
                'subject': subject,
                'content': content,
                'content_type': 'HTML' if 'html' in content.lower() else 'Text',
                'sender_name': 'System Sender',  # Could extract from From header
                'received_time': time.time(),
                'client_ip': session.peer[0] if hasattr(session, 'peer') else 'unknown'
            }
            
            # Add to Redis queue
            queue_size = self.redis_client.llen(self.queue_key)
            if queue_size < MAX_QUEUE_SIZE:
                self.redis_client.rpush(self.queue_key, str(email_data))
                logging.info(f"Email queued with subject: {subject}, recipients: {len(envelope.rcpt_tos)}")
                return '250 Message accepted for delivery'
            else:
                logging.warning("Queue full, rejecting email")
                return '452 Queue full, try again later'
            
        except Exception as e:
            logging.error(f"DATA handling error: {e}")
            return '451 Temporary processing error'

    def _extract_email_content(self, msg):
        """Extract content from email message"""
        if msg.is_multipart():
            for part in msg.walk():
                if part.get_content_type() == 'text/plain':
                    return part.get_payload(decode=True).decode('utf-8', errors='ignore')
                elif part.get_content_type() == 'text/html':
                    return part.get_payload(decode=True).decode('utf-8', errors='ignore')
        else:
            return msg.get_payload(decode=True).decode('utf-8', errors='ignore')
        return ""

class EmailProcessor:
    def __init__(self):
        self.redis_client = redis.Redis(**REDIS_CONFIG)
        self.rate_limit_key = 'email_rate_limit'
        self.queue_key = 'email_queue'
        self.queue_processor = EmailQueueProcessor()
        self.running = False
        self.stats = {
            'emails_sent': 0,
            'emails_failed': 0,
            'queue_size': 0
        }

    async def process_queue(self):
        """Process emails from the queue"""
        self.queue_processor.start()
        
        while self.running:
            try:
                # Get next batch from queue
                batch_size = 10
                email_data_list = []
                
                for _ in range(batch_size):
                    email_data_str = self.redis_client.lpop(self.queue_key)
                    if email_data_str:
                        try:
                            email_data = eval(email_data_str.decode())
                            email_data_list.append(email_data)
                        except Exception as e:
                            logging.error(f"Error parsing queued email: {e}")
                
                if email_data_list:
                    for email_data in email_data_list:
                        successful, failed = self.queue_processor.process_emails(
                            email_data['recipients'],
                            email_data['subject'],
                            email_data['content'],
                            email_data['content_type'],
                            email_data.get('sender_name', 'System Sender')
                        )
                        
                        self.stats['emails_sent'] += len(successful)
                        self.stats['emails_failed'] += len(failed)
                        
                        logging.info(f"Processed batch: {len(successful)} successful, {len(failed)} failed")
                
                await asyncio.sleep(QUEUE_PROCESSING_INTERVAL)
                
            except Exception as e:
                logging.error(f"Queue processing error: {e}")
                await asyncio.sleep(60)

    async def update_stats(self):
        """Update statistics periodically"""
        while self.running:
            try:
                self.stats['queue_size'] = self.redis_client.llen(self.queue_key)
                await asyncio.sleep(STATS_UPDATE_INTERVAL)
            except Exception as e:
                logging.error(f"Stats update error: {e}")
                await asyncio.sleep(60)

    async def health_check(self):
        """Periodic health check"""
        while self.running:
            try:
                # Test Redis connection
                self.redis_client.ping()
                logging.debug("Health check passed")
            except Exception as e:
                logging.error(f"Health check failed: {e}")
            await asyncio.sleep(HEALTH_CHECK_INTERVAL)

    async def start(self):
        """Start the email processor with all background tasks"""
        self.running = True
        logging.info("Email processor started")
        
        # Start background tasks
        stats_task = asyncio.create_task(self.update_stats())
        health_task = asyncio.create_task(self.health_check())
        queue_task = asyncio.create_task(self.process_queue())
        
        # Wait for all tasks
        await asyncio.gather(stats_task, health_task, queue_task)

    def stop(self):
        """Stop the email processor"""
        self.running = False
        self.queue_processor.stop()
        logging.info("Email processor stopped")

class EmailDaemon:
    def __init__(self):
        self.smtp_controller = None
        self.email_processor = None
        self.running = False

    async def start_services(self):
        """Start both SMTP receiver and email processor"""
        # Start SMTP receiver
        handler = RateLimitedSMTPHandler()
        self.smtp_controller = Controller(
            handler,
            hostname=LISTEN_HOST,
            port=LISTEN_PORT,
            decode_data=True,
            enable_SMTPUTF8=True
        )
        self.smtp_controller.start()
        logging.info(f"SMTP server started on {LISTEN_HOST}:{LISTEN_PORT}")

        # Start email processor
        self.email_processor = EmailProcessor()
        await self.email_processor.start()

    def stop_services(self):
        """Stop all services"""
        if self.smtp_controller:
            self.smtp_controller.stop()
        if self.email_processor:
            self.email_processor.stop()
        logging.info("All services stopped")

    def run(self):
        """Main daemon run method"""
        logging.basicConfig(
            level=LOG_LEVEL,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(LOG_FILE),
                logging.StreamHandler()
            ]
        )

        # Handle signals properly
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        def signal_handler():
            logging.info("Received shutdown signal")
            self.running = False
            self.stop_services()
            loop.stop()

        for sig in [signal.SIGTERM, signal.SIGINT]:
            loop.add_signal_handler(sig, signal_handler)

        try:
            self.running = True
            loop.run_until_complete(self.start_services())
            loop.run_forever()
                
        except Exception as e:
            logging.error(f"Daemon error: {e}")
        finally:
            self.stop_services()
            loop.close()

def main():
    daemon_instance = EmailDaemon()
    
    with daemon.DaemonContext(
        pidfile=PidFile(PID_FILE),
        signal_map={
            signal.SIGTERM: lambda signum, frame: exit(0),
            signal.SIGINT: lambda signum, frame: exit(0)
        }
    ):
        daemon_instance.run()

if __name__ == '__main__':
    main()