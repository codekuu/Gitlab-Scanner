import os
import sys
import logging
from datetime import datetime
from colorama import Style
from colorama import Fore
from .miscs import write_csv

logger = logging.getLogger(__name__)

# Timestamp
now = datetime.now().strftime("%Y-%m-%d_%H-%M")


class ColoredFormatter(logging.Formatter):
    """colored formatter"""

    level_format = {
        logging.DEBUG: Style.DIM + "%(levelname)s" + Style.RESET_ALL,
        logging.INFO: Style.BRIGHT + "%(levelname)s" + Style.RESET_ALL,
        logging.WARNING: Style.BRIGHT + Fore.YELLOW + "%(levelname)s" + Style.RESET_ALL,
        logging.ERROR: Style.BRIGHT + Fore.RED + "%(levelname)s" + Style.RESET_ALL,
        logging.CRITICAL: Style.BRIGHT + Fore.RED + "%(levelname)s" + Style.RESET_ALL,
    }

    def format(self, record):
        level_format = self.level_format.get(record.levelno)
        formatter = logging.Formatter("[" + level_format + "] %(message)s")
        return formatter.format(record)


def configure_logging(create):
    """configure logging and create logfile if specified"""
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)

    if create:
        name = os.path.basename(sys.argv[0])
        file_handler = logging.FileHandler(f"{name}_{now}.log".replace(".py", ""))
        file_formatter = logging.Formatter(
            "%(asctime)s %(processName)s [%(funcName)s] %(levelname)s %(message)s"
        )
        file_handler.setFormatter(file_formatter)
        root_logger.addHandler(file_handler)


def log_message(message, info=False):
    """log message
    mitigate lazy formatting
    """
    if info:
        logger.info(message)
    else:
        logger.debug(message)


def add_stream_handler(stream_handler=None):
    """add stream handler to logging"""
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)
    if not stream_handler:
        stream_handler = logging.StreamHandler()
        stream_formatter = ColoredFormatter()
        stream_handler.setFormatter(stream_formatter)
        stream_handler.setLevel(logging.INFO)
    root_logger.addHandler(stream_handler)
    return stream_handler


def remove_stream_handler(stream_handler):
    """remove stream handler from logging"""
    root_logger = logging.getLogger()
    root_logger.removeHandler(stream_handler)


def check_results(results):
    """check results and write summary"""
    filename = f"Gitlab-Scanner_Result_{now}.csv"
    write_csv(results, filename)
    log_message(
        f"{len(results)} branches scanned - summary report written to '{filename}'",
        info=True,
    )
    if any(result["leaks"] for result in results):
        log_message("gitleaks DID detect hardcoded secrets")
        print(
            f"{Style.BRIGHT + Fore.RED}GITLEAKS SCAN NOT OK - SECRETS DETECTED{Style.RESET_ALL}"
        )
        print("Leaks found:")
        for result in results:
            if result["leaks"]:
                print(result)
        exit(1)
    else:
        log_message("gitleaks DID NOT detect hardcoded secrets")
        print(f"{Style.BRIGHT + Fore.GREEN}GITLEAKS SCAN OK{Style.RESET_ALL}")
        exit(0)
