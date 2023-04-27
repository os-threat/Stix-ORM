"""
Test the new feed object....

"""
import json
import logging
import pathlib

import pytest
from stix.module.authorise import import_type_factory
from stix.module.typedb import TypeDBSink
from stix.module.typedb_lib.instructions import ResultStatus

connection = {
    "uri": "localhost",
    "port": "1729",
    "database": "stix",
    "user": None,
    "password": None
}

schema_path = path = str(pathlib.Path(__file__).parents[1])

import_type = import_type_factory.get_attack_import()

@pytest.fixture
def typedb():
    db = TypeDBSink(
        connection=connection,
        clear=True,
        import_type=import_type,
        schema_path=schema_path
    )
    db.clear_db()
    db = TypeDBSink(
        connection=connection,
        clear=True,
        import_type=import_type,
        schema_path=schema_path
    )
    yield db
    db.clear_db()
