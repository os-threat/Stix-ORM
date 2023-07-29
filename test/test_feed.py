"""
Test the new feed object....

"""
import json
from datetime import datetime
from pathlib import Path

import pytest
from stix2 import parse
from stixorm.module.authorise import import_type_factory
from stixorm.module.typedb import TypeDBSink
from stixorm.module.typedb_lib.instructions import ResultStatus

import_type = import_type_factory.get_all_imports()


def validate_successful_result(results):
    for result in results:
        assert result.status in [ResultStatus.SUCCESS, ResultStatus.ALREADY_IN_DB]

def create_feed(local_list, typedb_sink, loc_datetime):
    ips = []
    observed = []
    threatsubobj = []
    for ipaddr in local_list:
        ip = IPv4Address(value=ipaddr)
        ips.append(ip)
        obs = ObservedData(
            first_observed=loc_datetime,
            last_observed=loc_datetime,
            number_observed=1,
            object_refs =[ip.id]
        )
        observed.append(obs)
        sub = ThreatSubObject(
            object_ref=obs.id,
            created=loc_datetime,
            modified=loc_datetime
        )
        threatsubobj.append(sub)

    feed = Feed(
        name="OS Threat Feed",
        description="OS Threat Test Feed",
        created=loc_datetime,
        contents=[
            threatsubobj[0],
            threatsubobj[1],
            threatsubobj[2],
            threatsubobj[3]
        ]
    )
    add_list = ips + observed + [feed]
    result = typedb_sink.add(add_list)
    return result

@pytest.fixture
def database(generate_connection):
    db = TypeDBSink(
        connection=generate_connection,
        clear=True,
        import_type=import_type,
    )
    db.clear_db()
    db = TypeDBSink(
        connection=generate_connection,
        clear=True,
        import_type=import_type
    )
    yield db
    db.clear_db()

from stixorm.module.definitions.os_threat.classes import ThreatReference,ThreatSubObject,Feed,Feeds
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

    return [marking_def_statement,a_feed]

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

    bundle = Bundle(marking_def_statement,
                    a_feed)
    return bundle

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

    return [identity,marking_def_statement,marking_def_amber,fileMalicious,threat_sub_object,a_feed]

class TestFeed:

    def setUp(self, generate_connection):
        self.clean_db(generate_connection)

    def tearDown(self, generate_connection):
        self.clean_db(generate_connection)

    def clean_db(self, generate_connection):
        """ Get all stix-ids and delete them

        """
        typedb = TypeDBSink(connection=generate_connection,
                            clear=False,
                            import_type=import_type)

        typedb.clear_db()

    def test_database_initialization(self, database:TypeDBSink):
        '''
        First initialize the database...
        Args:
            database:

        Returns:

        '''
        pass


    def test_create_feed_1(self,
                           database:TypeDBSink,
                           empty_feed_bundle:Bundle):
        '''

        Now create the feed for the first time, there is no content to begin with...
        Args:
            database:
            simple_feed:

        Returns:

        '''
        result = database.add(empty_feed_bundle)
        validate_successful_result(result)

    def test_create_feed_list(self, database:TypeDBSink,
                              empty_feed_list):
        '''

        Now create the feed for the first time, there is no content to begin with...
        Args:
            database:
            simple_feed:

        Returns:

        '''
        result = database.add(empty_feed_list)
        print(result)


    def test_create_feed_2(self, database:TypeDBSink, generate_connection):
        current_file_path = Path(__file__)
        directory = current_file_path.parent
        example = directory.joinpath("data/os-threat/feed-example/example.json")
        assert example.exists()
        osthreat = str(example)
        datetime1 = datetime.fromisoformat("2020-10-19T01:01:01.000")
        datetime2 = datetime.fromisoformat("2020-10-20T01:01:01.000")
        datetime3 = datetime.fromisoformat("2020-10-21T01:01:01.000")

        typedb_sink = TypeDBSink(generate_connection, True, import_type)

        with open(osthreat, mode="r", encoding="utf-8") as f:
            json_text = json.load(f)
            result = create_feed(json_text[0], typedb_sink, datetime1)
            validate_successful_result(result)


    def test_create_bundle(self):
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