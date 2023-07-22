import logging


def pytest_configure(config):
    # Set up the logging format and level
    logging.basicConfig(level=logging.WARNING, format="%(asctime)s - %(levelname)s - %(message)s")