""" logger.py
Core Logging Module
"""
import logging
from rich.logging import RichHandler

def setup_logger():
    FORMAT = "%(message)s"
    logging.basicConfig(
        level="INFO",
        format=FORMAT,
        datefmt="[%X]",
        handlers=[RichHandler(rich_tracebacks=True)]
    )
    return logging.getLogger("itk")

log = setup_logger()