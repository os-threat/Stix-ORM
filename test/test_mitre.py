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


@pytest.fixture
def json_data():
    data_standard_path = "data/mitre/"
    top_dir_path = pathlib.Path(__file__).parents[1]
    file_path = str(top_dir_path.joinpath(data_standard_path).joinpath("attack_objects.json"))
    with open(file_path, mode="r", encoding="utf-8") as f:
        json_text = json.load(f)

    if isinstance(json_text, dict):
        json_text = [json_text]

    return json_text


@pytest.fixture
def ics_attack_data():
    data_standard_path = "data/mitre/"
    top_dir_path = pathlib.Path(__file__).parents[1]
    file_path = str(top_dir_path.joinpath(data_standard_path).joinpath("history").joinpath("ics-attack.json"))
    with open(file_path, mode="r", encoding="utf-8") as f:
        json_text = json.load(f)

    if isinstance(json_text, dict):
        json_text = [json_text]

    return json_text


def validate_has_missing_dependencies(results):
    for result in results:
        assert result.status in [ResultStatus.VALID_FOR_DB_COMMIT, ResultStatus.MISSING_DEPENDENCY]

def validate_is_successful(results):
    for result in results:
        assert result.status in [ResultStatus.SUCCESS]



def test_database_initialization(typedb, json_data):
    result = typedb.add(json_data)
    validate_is_successful(result)


def test_ics_attack_database_initialization(typedb, ics_attack_data):

    with pytest.raises(Exception):
        result = typedb.add(ics_attack_data)


