import logging
import random
import string

import pytest


def pytest_configure(config):
    # Set up the logging format and level
    logging.basicConfig(level=logging.WARNING, format="%(asctime)s - %(levelname)s - %(message)s")


@pytest.fixture
def random_string():
    length = 10
    characters = string.ascii_letters + string.digits
    random_string = ''.join(random.choices(characters, k=length))
    return random_string
@pytest.fixture
def generate_failed_connection(random_string):
    failed_connection = {
        "uri": "localhost",
        "port": "729",
        "database": "stix"+random_string,
        "user": None,
        "password": None
    }
    return failed_connection

@pytest.fixture
def generate_connection(random_string):
    connection = {
        "uri": "localhost",
        "port": "1729",
        "database": "stix" + random_string,
        "user": None,
        "password": None
    }
    return connection