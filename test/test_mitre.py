import json
import logging
import pathlib
from typing import List

import pytest
import requests
from pyinstrument import Profiler

from stixorm.module.authorise import import_type_factory
from stixorm.module.typedb import TypeDBSink
from stixorm.module.typedb_lib.instructions import ResultStatus, Result

import_type = import_type_factory.get_attack_import()


@pytest.fixture
def typedb(generate_connection):
    db = TypeDBSink(
        connection=generate_connection,
        clear=True,
        import_type=import_type,
    )
    db.clear_db()
    db = TypeDBSink(
        connection=generate_connection,
        clear=True,
        import_type=import_type,
    )
    yield db
    db.clear_db()


@pytest.fixture
def json_data():
    data_standard_path = "data/mitre/"
    top_dir_path = pathlib.Path(__file__).parents[0]
    file_path = str(top_dir_path.joinpath(data_standard_path).joinpath("attack_objects.json"))
    with open(file_path, mode="r", encoding="utf-8") as f:
        json_text = json.load(f)

    if isinstance(json_text, dict):
        json_text = [json_text]

    return json_text


@pytest.fixture
def traffic_duplication_json():
    data_standard_path = "data/mitre/"
    top_dir_path = pathlib.Path(__file__).parents[0]
    file_path = str(top_dir_path.joinpath(data_standard_path).joinpath("traffic_duplication.json"))
    with open(file_path, mode="r", encoding="utf-8") as f:
        json_text = json.load(f)

    if isinstance(json_text, dict):
        json_text = [json_text]

    return json_text

@pytest.fixture
def ics_attack_data():
    data_standard_path = "data/mitre/"
    top_dir_path = pathlib.Path(__file__).parents[0]
    file_path = str(top_dir_path.joinpath(data_standard_path).joinpath("history").joinpath("ics-attack.json"))
    with open(file_path, mode="r", encoding="utf-8") as f:
        json_text = json.load(f)

    if isinstance(json_text, dict):
        json_text = [json_text]

    return json_text

def validate_has_error(results):
    for result in results:
        if result.status == ResultStatus.ERROR:
            print("Error " + result.id + " " + result.message)
            raise Exception("failed")

def validate_has_missing_dependencies(results):
    for result in results:
        assert result.status in [ResultStatus.VALID_FOR_DB_COMMIT, ResultStatus.MISSING_DEPENDENCY]

def validate_is_successful(results):
    for result in results:
        assert result.status in [ResultStatus.SUCCESS]

def enterprise_attack_13_1():
    top_dir_path = pathlib.Path(__file__).parents[0]
    file_path = top_dir_path.joinpath("data").joinpath("mitre").joinpath("enterprise-attack-13.1.json")
    with open(str(file_path), "r") as file:
        data = json.load(file)
    return data["objects"]

def attack_data():
    url = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/index.json"

    response = requests.get(url)
    index_data = response.json()
    index_data_collections = index_data["collections"]
    mitre_versions = index_data_collections[0]["versions"]

    result = []
    for mitre_version in mitre_versions:
        result.append(mitre_version["url"])
    return result

@pytest.fixture
def setup_teardown(generate_connection):
    typedb = TypeDBSink(connection=generate_connection,
                        clear=False,
                        import_type=import_type)

    typedb.clear_db()

    yield

    typedb = TypeDBSink(connection=generate_connection,
                        clear=False,
                        import_type=import_type)

    typedb.clear_db()

class TestMitre:


    def validate_successful_result(self,
                                   results: List[Result]):
        for result in results:
            if result.status not in [ ResultStatus.SUCCESS, ResultStatus.ALREADY_IN_DB]:
                message = "" if result.message is None else result.message
                error = "" if result.error is None else result.error
                logging.warning("Unsuccessful results " + result.id + " " + str(result.status) + " " + message + " " + error)
        for result in results:
            assert result.status in [ ResultStatus.SUCCESS, ResultStatus.ALREADY_IN_DB]

    def test_traffic_duplication_json(self, setup_teardown, typedb, traffic_duplication_json):

        profiler = Profiler()
        profiler.start()
        result = typedb.add(traffic_duplication_json)
        validate_is_successful(result)


    def test_database_initialization(self, setup_teardown, typedb, json_data):

        profiler = Profiler()
        profiler.start()
        result = typedb.add(json_data)
        validate_is_successful(result)
        profiler.stop()


        log_filename = "C:\\Users\\denis\\PycharmProjects\\Stix-ORM\\profiler.log"
        log_text = "This is a log message."

        self.write_to_log(log_filename, profiler.output_text())

    def write_to_log(self, log_filename, log_text):
        with open(log_filename, 'w') as log_file:
            log_file.write(log_text + "\n")

    def validate_has_missing_dependencies(self, results):
        for result in results:
            assert result.status in [ResultStatus.VALID_FOR_DB_COMMIT, ResultStatus.MISSING_DEPENDENCY]

    def test_load_enterprise_attack_13_1_first_object(self, setup_teardown, typedb):
        top_dir_path = pathlib.Path(__file__).parents[0]
        file_path = top_dir_path.joinpath("data").joinpath("mitre").joinpath("enterprise-attack-13.1.json")
        with open(str(file_path), "r") as file:
            data = json.load(file)

        profiler = Profiler()
        profiler.start()
        try:
            result = typedb.add([data["objects"][0]])
        except Exception as e:
            print(e)
        profiler.stop()

        log_filename = "C:\\Users\\denis\\PycharmProjects\\Stix-ORM\\profiler.log"
        log_text = "This is a log message."

        self.write_to_log(log_filename, profiler.output_text())

    def test_load_enterprise_attack_13_1(self, setup_teardown, typedb):
        top_dir_path = pathlib.Path(__file__).parents[0]
        file_path = top_dir_path.joinpath("data").joinpath("mitre").joinpath("enterprise-attack-13.1.json")
        with open(str(file_path), "r") as file:
            data = json.load(file)

        result = typedb.add([data["objects"][1831]])
        self.validate_successful_result(result)

    @pytest.mark.skip(reason="This will be added later")
    @pytest.mark.parametrize("url", attack_data())
    def test_load_attack_stix_data(self, setup_teardown, typedb, url):
        response = requests.get(url)
        data = response.json()

        result = typedb.add([data])
        #validate_is_successful(result)

    def test_ics_attack_database_initialization(self, setup_teardown, typedb, ics_attack_data):

        with pytest.raises(Exception):
            result = typedb.add(ics_attack_data)


