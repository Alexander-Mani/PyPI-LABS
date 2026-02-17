import sys
from pathlib import Path
from loguru import logger

# Prevent double-configuration if imported multiple times
_logger_configured = False

def setup_logger(config):
    """
    Configures loguru based on config.yaml settings.
    """
    global _logger_configured
    if _logger_configured:
        return logger

    # 1. Clear the default handler (which just prints everything)
    logger.remove()

    # 2. Get Settings
    log_path = Path(config['logging']['file'])
    level = config['logging']['level'].upper()
    console_out = config['logging']['console_output']

    # 3. Create parent directory for logs
    log_path.parent.mkdir(parents=True, exist_ok=True)

    # 4. Add the File Sink (Automatic Rotation!)
    # rotation="10 MB" means: Start a new file when this one hits 10MB
    # compression="zip" means: Zip the old log files to save space
    logger.add(
        log_path, 
        level=level, 
        rotation="10 MB", 
        retention="1 week", 
        compression="zip",
        format="{time:YYYY-MM-DD HH:mm:ss} | {level: <8} | {name}:{function}:{line} - {message}"
    )

    # 5. Add the Console Sink (Colored Output)
    if console_out:
        logger.add(
            sys.stderr, 
            level=level, 
            format="<green>{time:HH:mm:ss}</green> | <level>{level: <8}</level> | <cyan>{name}</cyan>:<cyan>{function}</cyan> - <level>{message}</level>"
        )

    _logger_configured = True
    return logger

def get_logger():
    """Returns the global logger instance."""
    return logger

