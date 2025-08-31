"""
Broadcast logging handler that sends messages to all active terminals
"""
import logging
import os
import fcntl
import termios
import struct
import sys

class BroadcastHandler(logging.Handler):
    def __init__(self):
        super().__init__()
        self.terminals = self.get_active_terminals()
        
    def get_active_terminals(self):
        """Get list of active terminal devices"""
        terminals = []
        try:
            # Check common terminal locations
            for term_dir in ['/dev/pts', '/dev']:
                if os.path.exists(term_dir):
                    for entry in os.listdir(term_dir):
                        if entry.startswith('pts/') or entry.startswith('tty'):
                            term_path = os.path.join(term_dir, entry)
                            if self.is_terminal_active(term_path):
                                terminals.append(term_path)
        except Exception as e:
            pass
        return terminals
    
    def is_terminal_active(self, term_path):
        """Check if terminal is active and writable"""
        try:
            # Try to open the terminal for writing
            with open(term_path, 'w') as f:
                fcntl.ioctl(f, termios.TIOCGWINSZ, struct.pack('HHHH', 0, 0, 0, 0))
            return True
        except:
            return False
    
    def emit(self, record):
        """Broadcast log message to all active terminals"""
        try:
            msg = self.format(record) + '\n'
            for term in self.terminals:
                try:
                    with open(term, 'w') as f:
                        f.write(msg)
                        f.flush()
                except:
                    # Remove terminal if it's no longer accessible
                    if term in self.terminals:
                        self.terminals.remove(term)
        except Exception as e:
            # Fallback to stderr if broadcasting fails
            sys.stderr.write(f"Broadcast error: {e}\n")
    
    def refresh_terminals(self):
        """Refresh the list of active terminals"""
        self.terminals = self.get_active_terminals()