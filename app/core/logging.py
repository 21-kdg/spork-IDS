"""Logging configuration for Spork-IDS."""
import logging
import sys


def setup_logging(debug: bool = False) -> logging.Logger:
    """Configures structured console logging for the Spork-IDS platform."""
    level = logging.DEBUG if debug else logging.INFO
    formatter = logging.Formatter(
        "[%(asctime)s] [%(levelname)s] [%(name)s]: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(formatter)

    logger = logging.getLogger("spork_ids")
    logger.setLevel(level)

    # Avoid duplicate handlers if already added
    if not logger.handlers:
        logger.addHandler(handler)

    return logger


logger = setup_logging()
