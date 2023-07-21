import logging


def pytest_configure(config):
    # Set up the logging format and level
    logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")