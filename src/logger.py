"""
Centralized logging configuration for IoT Shodan
"""

import logging
import logging.handlers
from pathlib import Path
from config.settings import LOG_LEVEL, LOG_FORMAT, LOGS_DIR


def setup_logger(name):
    """
    Setup a logger with both file and console handlers
    
    Args:
        name: Logger name (typically __name__)
    
    Returns:
        Configured logger instance
    """
    logger = logging.getLogger(name)
    logger.setLevel(getattr(logging, LOG_LEVEL))
    
    # Avoid duplicate handlers if logger already configured
    if logger.handlers:
        return logger
    
    # Console Handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(getattr(logging, LOG_LEVEL))
    console_formatter = logging.Formatter(LOG_FORMAT)
    console_handler.setFormatter(console_formatter)
    logger.addHandler(console_handler)
    
    # File Handler
    log_file = LOGS_DIR / f"{name.replace('.', '_')}.log"
    file_handler = logging.handlers.RotatingFileHandler(
        log_file,
        maxBytes=10_485_760,  # 10MB
        backupCount=5
    )
    file_handler.setLevel(getattr(logging, LOG_LEVEL))
    file_formatter = logging.Formatter(LOG_FORMAT)
    file_handler.setFormatter(file_formatter)
    logger.addHandler(file_handler)
    
    return logger
