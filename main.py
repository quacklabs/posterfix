"""
Main entry point for the Email Daemon
"""
import logging
import time
import sys
import os

# Add the current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from handlers.broadcast_handler import BroadcastHandler
from processors.email_processor import EmailQueueProcessor

# Configure logging
logger = logging.getLogger('EmailDaemon')
logger.setLevel(logging.DEBUG)

# Remove existing handlers
for handler in logger.handlers[:]:
    logger.removeHandler(handler)

# Create handlers
file_handler = logging.FileHandler('/var/log/email_daemon/email_daemon.log')
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

# Global processor instance
processor = None

def start_daemon():
    """Start the email daemon"""
    global processor
    
    logger.info("=" * 60)
    logger.info("🚀 STARTING EMAIL DAEMON")
    logger.info("=" * 60)
    
    try:
        processor = EmailQueueProcessor()
        processor.start()
        logger.info("✅ Email daemon started successfully!")
        logger.info("📡 Waiting for HAProxy connections...")
        logger.info("💡 Messages will be broadcast to all active terminals")
        
        # Keep main thread alive
        while True:
            time.sleep(10)
            # Refresh terminal list periodically
            broadcast_handler.refresh_terminals()
            
    except KeyboardInterrupt:
        logger.info("\n🛑 Shutting down gracefully...")
        stop_daemon()
    except Exception as e:
        logger.error(f"💥 Fatal error: {e}")
        import traceback
        logger.error(traceback.format_exc())
        stop_daemon()

def stop_daemon():
    """Stop the email daemon"""
    global processor
    if processor:
        processor.stop()
    logger.info("🛑 Email daemon stopped")

if __name__ == "__main__":
    start_daemon()