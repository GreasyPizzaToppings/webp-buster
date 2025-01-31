import logging
import sys
from logging.handlers import RotatingFileHandler

class Logger:
    def __init__(self, config):
        """Initialize logger with configuration"""
        self.logger = logging.getLogger()
        self.config = config
        self._setup_logger()
    
    def _setup_logger(self):
        """Configure logging with file and console handlers"""
        level = getattr(logging, self.config.get('logging', 'level').upper())
        self.logger.setLevel(level)

        # Create handlers
        self._add_file_handler()
        self._add_console_handler()

    def _add_file_handler(self):
        """Add rotating file handler"""
        max_size = self.config.get('logging', 'max_size_mb') * 1024 * 1024
        handler = RotatingFileHandler(
            self.config.get_log_path(),
            maxBytes=max_size,
            backupCount=3,
            encoding='utf-8'
        )
        handler.setFormatter(self._get_formatter())
        self.logger.addHandler(handler)

    def _add_console_handler(self):
        """Add console handler with UTF-8 support"""
        if sys.platform == 'win32':
            sys.stdout.reconfigure(encoding='utf-8')
        
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(self._get_formatter())
        self.logger.addHandler(handler)

    def _get_formatter(self):
        """Create standard formatter for all handlers"""
        return logging.Formatter(
            '%(asctime)s - %(levelname)s: %(message)s',
            datefmt='%d-%m-%Y %H:%M'
        )

    def __getattr__(self, name):
        """Delegate logging methods to internal logger"""
        return getattr(self.logger, name)