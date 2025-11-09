import json
import logging
import os
import pathlib
from typing import List

import pytest
from stix2 import Bundle

from stixorm.module.authorise import import_type_factory
from stixorm.module.parsing.parse_objects import parse
from stixorm.module.typedb import TypeDBSink, TypeDBSource

import_type = import_type_factory.get_default_import()

logger = logging.getLogger(__name__)

def top_path():
    return pathlib.Path(__file__).parents[0]

def aaa_identity_path() -> str:
    data_standard_path = "data/standard/"
    top_dir_path = top_path()
    return str(top_dir_path.joinpath(data_standard_path).joinpath("aaa_identity.json"))

def report_path() -> str:
    data_standard_path = "data/standard/fragments"
    top_dir_path = top_path()
    return str(top_dir_path.joinpath(data_standard_path).joinpath("report.json"))

def get_all_poison_ivy() -> str:
    data_standard_path = "data/threat_reports"
    top_dir_path = top_path()
    file_path = str(top_dir_path.joinpath(data_standard_path).joinpath("poisonivy.json"))
    if not pathlib.Path(file_path).is_file():
        pytest.skip(f"Missing test data: {file_path}", allow_module_level=True)
    json_text = get_json_from_file(file_path)
    return json_text[0]["objects"]

def get_poison_ivy() -> str:
    data_standard_path = "data/threat_reports"
    top_dir_path = top_path()
    file_path = str(top_dir_path.joinpath(data_standard_path).joinpath("poisonivy.json"))
    if not pathlib.Path(file_path).is_file():
        pytest.skip(f"Missing test data: {file_path}", allow_module_level=True)
    json_text = get_json_from_file(file_path)
    return json_text[0]


def get_human_trigger() -> str:
    data_standard_path = "data/os-threat/incident"
    top_dir_path = top_path()
    file_path = str(top_dir_path.joinpath(data_standard_path).joinpath("human_trigger.json"))
    json_text = get_json_from_file(file_path)
    return json_text[0]['objects']

def standard_data_file_path() -> List[str]:

    top_dir_path = top_path()
    data_standard_path = top_dir_path.joinpath("data/standard/")

    standard_data_file_list = []

    for root, dirs, files in os.walk(data_standard_path):
        for file in files:
            if file.endswith(".json") and file != "translation_campaign.json":
                standard_data_file_list.append(os.path.join(root, file))
            else:
                logger.debug("Excluding from test: " + file)

    return standard_data_file_list


def get_json_from_file(file_path: str) -> List[dict]:
        assert pathlib.Path(file_path).is_file()
        print(f'I am about to history {file_path}')
        with open(file_path, mode="r", encoding="utf-8") as f:
            json_text = json.load(f)

        if isinstance(json_text, dict):
            json_text = [json_text]

        return json_text


def get_all_mitre():
    top_dir_path = pathlib.Path(__file__).parents[0]
    file_path = top_dir_path.joinpath("data").joinpath("mitre").joinpath("enterprise-attack-13.1.json")
    if not file_path.is_file():
        pytest.skip(f"Missing test data: {file_path}", allow_module_level=True)
    with open(str(file_path), "r") as file:
        data = json.load(file)
    return data["objects"]

# TODO: Fix failing
@pytest.mark.parametrize("json_data", get_human_trigger())
def test_serialise_human_trigger(json_data):
    import_type = import_type_factory.get_all_imports()
    #json_text = get_json_from_file(file_path)

    if json_data["id"] not in ["incident--1a074418-9248-4a21-9918-a79d0f1dbc5b",
                              "identity--023d105b-752e-4cc c-941c-7d3f3cb15e9e",
                              "task--1ffe4af4-3b18-4ee2-8279-0d1264efd0fe",
                              "task--2d254737-fbf8-4969-adb3-80ac5c293f57",
                              "task--2d254737-fbf8-4969-addd-80ac5c293f57",
                              "relationship--7aebe2f0-28d6-48a2-9c3e-b0aaa6026666",
                              "task--56d81e7e-69b6-41aa-88cc-2b64b7896463",
                                "task--2d254737-fbff-4969-bbbb-80ac5c293f57",
                                "task--2d254737-fbff-4969-addd-80ac5c293f57",
                                "task--2d254737-fbbb-4969-addd-80ac5c293f57",
                                "evidence--2d2541111-fbf8-4969-addd-80ac5c293f57",
                                "evidence--2d2542222-fbf8-4969-addd-80ac5c293f57",
                                "evidence--2d2541111-fbf8-4969-addd-80ac5c293f57",
                                "evidence--2d2543333-fbf8-4969-addd-80ac5c293f57",
                                "indicator--d81f86b9-975b-4c0b-875e-810c5ad45a4f",
                                "impact--1032f48b-28d1-451f-970e-78b736db8e13",
                                "report--f66c52bc-cb78-4657-894f-a4c2902b1c30"
                              ]:
        identity = parse(json_data, False, import_type)
        identity.serialize()



def test_serialise_feed(setup_teardown, generate_connection):
    file_path = aaa_identity_path()
    json_text = get_json_from_file(file_path)
    identity = parse(json_text[0])
    identity.serialize()

@pytest.mark.parametrize("json_data", get_all_poison_ivy())
def test_serialise_poison_ivy_objects(json_data):
    import_type = import_type_factory.get_all_imports()

    parsed = parse(json_data, False, import_type)
    serialized = parsed.serialize()
    print(serialized)


def test_serialise_poison_ivy(setup_teardown, generate_connection):
    json_data = get_poison_ivy()
    import_type = import_type_factory.get_all_imports()
    typedb_sink = TypeDBSink(connection=generate_connection,
                                 clear=True,
                                 import_type=import_type,
                                 strict_failure=True)

    typedb_sink.add(json_data)
    typedb_source = TypeDBSource(connection=generate_connection, import_type=import_type)

    report = typedb_source.get("report--f2b63e80-b523-4747-a069-35c002c690db")
    serialised_report = report.serialize()
    print(serialised_report)


def test_serialise_report(setup_teardown, generate_connection):
    file_path = report_path()
    json_text = get_json_from_file(file_path)
    identity = parse(json_text[0])
    identity.serialize()


@pytest.mark.parametrize("file_path", standard_data_file_path())
def test_each_stix_file_will_parse(file_path):
    json_text = get_json_from_file(file_path)
    for text in json_text:
        parsed = parse(text)

@pytest.mark.parametrize("file_path", standard_data_file_path())
def test_each_stix_file_will_serialise(file_path):
    json_text = get_json_from_file(file_path)
    for text in json_text:
        parsed = parse(text)
        parsed.serialize()


@pytest.mark.parametrize("json_data", get_all_mitre())
def test_each_attack_13_1_file_will_parse(json_data):
    import_type = import_type_factory.get_attack_import()
    parse(json_data, import_type=import_type)


@pytest.mark.parametrize("json_data", get_all_mitre())
def test_each_attack_13_1_file_will_parse(json_data):
    import_type = import_type_factory.get_attack_import()
    parsed_object = parse(json_data, import_type=import_type)
    parsed_object.serialize()


def test_serialize_bundle():
    # Create STIX objects
    json_data = {
        "type": "indicator",
        "spec_version": "2.1",
        "id": "indicator--a862ff86-68d9-42e5-8095-cd80c040e112",
        "created": "2020-06-24T15:04:40.048932Z",
        "modified": "2020-06-24T15:04:40.048932Z",
        "name": "File hash for malware variant",
        "pattern": "[file:hashes.md5 = 'd41d8cd98f00b204e9800998ecf8427e']",
        "pattern_type": "stix",
        "pattern_version": "2.1",
        "valid_from": "2020-06-24T15:04:40.048932Z"
    }

    # Create a STIX Indicator object
    indicator = parse(json_data)

    json_data = {
        "type": "malware",
        "spec_version": "2.1",
        "id": "malware--389c934c-258c-44fb-ae4b-14c6c12270f6",
        "created": "2020-06-24T14:53:20.156644Z",
        "modified": "2020-06-24T14:53:20.156644Z",
        "name": "Poison Ivy",
        "is_family": False
    }

    malware = parse(json_data)

    json_data = {
        "type": "relationship",
        "spec_version": "2.1",
        "id": "relationship--2f6a8785-e27b-487e-b870-b85a2121502d",
        "created": "2020-06-24T15:05:18.250605Z",
        "modified": "2020-06-24T15:05:18.250605Z",
        "relationship_type": "indicates",
        "source_ref": "indicator--a862ff86-68d9-42e5-8095-cd80c040e112",
        "target_ref": "malware--389c934c-258c-44fb-ae4b-14c6c12270f6"
    }

    relationship = parse(json_data)

    # Create a STIX bundle
    bundle = Bundle(objects=[indicator, malware, relationship])
    bundle.serialize()