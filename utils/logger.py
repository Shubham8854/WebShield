import logging
import os

os.makedirs("logs", exist_ok=True)

logging.basicConfig(
    filename="logs/webshield.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)


def log_info(message):
    logging.info(message)


def log_error(message):
    logging.error(message)
