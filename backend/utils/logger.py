import logging
from pathlib import Path
from logging.handlers import RotatingFileHandler
import sys

LOG_DIR = Path("logs")
LOG_DIR.mkdir(exist_ok=True)
LOG_FILE = LOG_DIR / "portscanner.log"


def setup_logger():
    logger = logging.getLogger("PortGuardian")
    logger.setLevel(logging.DEBUG)

    if logger.hasHandlers():
        logger.handlers.clear()

    console_handler = logging.StreamHandler(sys.stdout)
    console_format = logging.Formatter("%(levelname)s: %(message)s")
    console_handler.setFormatter(console_format)
    console_handler.setLevel(logging.WARNING)

    file_handler = RotatingFileHandler(
        LOG_FILE,
        maxBytes=5 * 1024 * 1024,
        backupCount=5,
        encoding="utf-8",
    )
    file_format = logging.Formatter(
        "%(asctime)s | %(name)s | %(levelname)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    file_handler.setFormatter(file_format)
    file_handler.setLevel(logging.DEBUG)

    logger.addHandler(console_handler)
    logger.addHandler(file_handler)

    return logger


logger = setup_logger()


def test_logger():
    logger.debug("Debug message (only in file)")
    logger.info("Info message")
    logger.warning("Warning message (seen in console)")
    logger.error("Error message")
    try:
        x = 1 / 0
    except Exception as e:
        logger.error(f"Operation failed: {e}", exc_info=True)


if __name__ == "__main__":
    test_logger()

