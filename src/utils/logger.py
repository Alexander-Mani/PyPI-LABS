import sys
from datetime import datetime
from pathlib import Path

from loguru import logger

# Prevent double-configuration if imported multiple times
_logger_configured = False
_active_log_path = None


def _resolve_log_path(config):
    log_path = Path(config["logging"]["file"])
    if not config["logging"].get("per_run", False):
        return log_path

    stamp = datetime.now().strftime("%Y%m%d-%H%M%S-%f")
    return log_path.with_name(f"{log_path.stem}-{stamp}{log_path.suffix}")


def _console_filter(record):
    return not record["extra"].get("file_only", False)


def setup_logger(config):
    """
    Configures loguru based on config.yaml settings.
    """
    global _logger_configured, _active_log_path
    if _logger_configured:
        return logger

    # 1. Clear the default handler (which just prints everything)
    logger.remove()

    # 2. Get Settings
    log_path = _resolve_log_path(config)
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
            filter=_console_filter,
            format="<green>{time:HH:mm:ss}</green> | <level>{level: <8}</level> | <cyan>{name}</cyan>:<cyan>{function}</cyan> - <level>{message}</level>"
        )

    _active_log_path = log_path
    _logger_configured = True
    return logger

def get_logger():
    """Returns the global logger instance."""
    return logger


def get_active_log_path():
    """Return the concrete log file path chosen by setup_logger()."""
    return _active_log_path
