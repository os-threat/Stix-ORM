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
def database():
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

from stix.module.definitions.os_threat.classes import ThreatReference,ThreatSubObject,Feed,Feeds
from stix2.v21.common import ExternalReference,MarkingDefinition,StatementMarking
from stix2.v21 import Identity,ObservedData,Indicator,IPv4Address,File,Bundle

@pytest.fixture
def empty_feed_list():

    info = ExternalReference(source_name="Phishing Database ACTIVE",
                             external_id="phishing-IPs-ACTIVE.txt",
                             url="https://github.com/mitchellkrogza/Phishing.Database/blob/master/phishing-IPs-ACTIVE.txt")

    marking_def_statement = MarkingDefinition(
        id="marking-definition--d81f86b9-975b-4c0b-875e-810c5ad45a4f",
        created="2017-04-14T13:07:49.812Z",
        definition_type="statement",
        definition=StatementMarking("Copyright (c) Stark Industries 2017.")
    )


    a_feed = Feed(name='phishing-db',
                  description="the phishing database",
                  paid=False,
                  free=False,
                  labels=[],
                  lang="en",
                  external_references=[info],
                  object_marking_refs = [marking_def_statement],
                  contents=[])

    return [info,marking_def_statement,a_feed]

@pytest.fixture
def empty_feed_bundle():

    info = ExternalReference(source_name="Phishing Database ACTIVE",
                             external_id="phishing-IPs-ACTIVE.txt",
                             url="https://github.com/mitchellkrogza/Phishing.Database/blob/master/phishing-IPs-ACTIVE.txt")

    marking_def_statement = MarkingDefinition(
        id="marking-definition--d81f86b9-975b-4c0b-875e-810c5ad45a4f",
        created="2017-04-14T13:07:49.812Z",
        definition_type="statement",
        definition=StatementMarking("Copyright (c) Stark Industries 2017.")
    )


    a_feed = Feed(name='phishing-db',
                  description="the phishing database",
                  paid=False,
                  free=False,
                  labels=[],
                  lang="en",
                  external_references=[info],
                  object_marking_refs = [marking_def_statement],
                  contents=[])

    return Bundle(info,marking_def_statement,a_feed,allow_custom=True)

@pytest.fixture
def simple_feed():

    info = ExternalReference(source_name="Phishing Database ACTIVE",
                             external_id="phishing-IPs-ACTIVE.txt",
                             url="https://github.com/mitchellkrogza/Phishing.Database/blob/master/phishing-IPs-ACTIVE.txt")

    identity = Identity(
        id="identity--611d9d41-dba5-4e13-9b29-e22488058ffc",
        created="2017-04-14T13:07:49.812Z",
        modified="2017-04-14T13:07:49.812Z",
        name="Stark Industries",
        contact_information="info@stark.com",
        identity_class="organization",
        sectors=["defense"]
    )

    marking_def_amber = MarkingDefinition(
        id="marking-definition--f88d31f6-486f-44da-b317-01333bde0b82",
        created="2017-01-20T00:00:00.000Z",
        definition_type="tlp",
        definition={
            "tlp": "amber"
        }
    )

    marking_def_statement = MarkingDefinition(
        id="marking-definition--d81f86b9-975b-4c0b-875e-810c5ad45a4f",
        created="2017-04-14T13:07:49.812Z",
        definition_type="statement",
        definition=StatementMarking("Copyright (c) Stark Industries 2017.")
    )

    indicator = Indicator(
        id="indicator--33fe3b22-0201-47cf-85d0-97c02164528d",
        created_by_ref="identity--611d9d41-dba5-4e13-9b29-e22488058ffc",
        name="Known malicious IP Address",
        pattern_type="stix",
        description="Detected malicious activity from this address",
        indicator_types=["malicious-activity"],
        pattern="[ipv4-addr:value = '10.0.0.0']",
        object_marking_refs=[marking_def_amber, marking_def_statement]
    )

    fileMalicious = File(
        hashes={
            "MD5": "1717b7fff97d37a1e1a0029d83492de1",
            "SHA-1": "c79a326f8411e9488bdc3779753e1e3489aaedea"
        },
        name="resume.pdf",
        size=83968
    )

    threat_sub_object = ThreatSubObject(
        created="2017-02-27T21:37:11.213Z",
        modified="2017-02-27T21:37:11.213Z",
        object_ref=fileMalicious.id
    )

    a_feed = Feed(name='phishing-db',
                  description="the phishing database",
                  paid=False,
                  free=False,
                  labels=[],
                  lang="en",
                  external_references=[info],
                  object_marking_refs = [marking_def_statement],
                  contents=[threat_sub_object])

    return [info,identity,marking_def_statement,marking_def_amber,fileMalicious,threat_sub_object,a_feed]

def test_database_initialization(database:TypeDBSink):
    '''
    First initialize the database...
    Args:
        database:

    Returns:

    '''
    pass


def test_create_feed(database:TypeDBSink,empty_feed_bundle:Bundle):
    '''

    Now create the feed for the first time, there is no content to begin with...
    Args:
        database:
        simple_feed:

    Returns:

    '''
    result = database.add(empty_feed_bundle)
    print(result)

def test_create_feed_list(database:TypeDBSink,empty_feed_list):
    '''

    Now create the feed for the first time, there is no content to begin with...
    Args:
        database:
        simple_feed:

    Returns:

    '''
    result = database.add(empty_feed_list)
    print(result)