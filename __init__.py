"""
Email Daemon Package
"""
from .main import start_daemon, stop_daemon

__version__ = "1.0.0"
__all__ = ['start_daemon', 'stop_daemon']