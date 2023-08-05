import logging
import random
import string

import pytest

from stixorm.module.typedb_lib.queries import get_all_databases, delete_database


def pytest_configure(config):
    # Set up the logging format and level
    logging.basicConfig(level=logging.WARNING, format="%(asctime)s - %(levelname)s - %(message)s")

def data_base_prefix():
    return "stix_test_db_"

def data_base_uri():
    return "localhost"

def database_port():
    return "1729"

@pytest.fixture
def random_string():
    length = 10
    characters = string.ascii_letters + string.digits
    random_string = ''.join(random.choices(characters, k=length))
    return random_string
@pytest.fixture
def generate_failed_connection(random_string):
    failed_connection = {
        "uri":  data_base_uri(),
        "port": "729",
        "database": "stix"+random_string,
        "user": None,
        "password": None
    }
    return failed_connection

@pytest.fixture
def generate_connection(random_string):
    connection = {
        "uri":  data_base_uri(),
        "port": database_port(),
        "database": "stix_test_db_" + random_string,
        "user": None,
        "password": None
    }
    return connection

@pytest.fixture(scope="session")
def setup_before_all_tests(request):
    # Put your setup code here
    print("\nClean up before starting")
    all_databases = get_all_databases(data_base_uri(), database_port())
    for database in all_databases:
        if database.name().startswith(data_base_prefix()):
            delete_database(data_base_uri(), database_port(), database.name())