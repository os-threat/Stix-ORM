import os

import pytest


@pytest.fixture
def working_connection():
    return {
    "uri": "localhost",
    "port": "1729",
    "database": "stix",
    "user": None,
    "password": None
}

@pytest.fixture
def failed_connection_port():
    return {
        "uri": "localhost",
        "port": "729",
        "database": "stix",
        "user": None,
        "password": None
    }

@pytest.fixture
def failed_connection_database():
    return {
        "uri": "localhost",
        "port": "1729",
        "database": "unknown",
        "user": None,
        "password": None
    }

@pytest.fixture
def failed_connection_port():
    return {
        "uri": "",
        "port": "",
        "database": "stix",
        "user": None,
        "password": None
    }

# define the database data and import details

