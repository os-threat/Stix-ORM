import json
import os
import pathlib
import unittest
from parameterized import parameterized
from typedb.client import *

import logging

from stix.module.typedb import TypeDBSink
from stix.module.typedb_lib.instructions import ResultStatus

logging.basicConfig(level=logging.INFO, format='[%(asctime)s] %(levelname)s [%(name)s:%(lineno)s] %(message)s')
logger = logging.getLogger(__name__)

failed_connection = {
    "uri": os.getenv("TYPEDB_HOST"),
    "port": "729",
    "database": "stix",
    "user": None,
    "password": None
}

# define the database data and import details
connection = {
    "uri": os.getenv("TYPEDB_HOST"),
    "port": os.getenv("TYPEDB_PORT"),
    "database": "stix",
    "user": None,
    "password": None
}

import_type = {
    "STIX21": True,
    "CVE": False,
    "identity": False,
    "location": False,
    "rules": False,
    "ATT&CK": False,
    "ATT&CK_Versions": ["12.0"],
    "ATT&CK_Domains": ["enterprise-attack", "mobile-attack", "ics-attack"],
    "CACAO": False
}

import_type_attack = {
    "STIX21": False,
    "CVE": False,
    "identity": False,
    "location": False,
    "rules": False,
    "ATT&CK": True,
    "ATT&CK_Versions": ["12.0"],
    "ATT&CK_Domains": ["enterprise-attack", "mobile-attack", "ics-attack"],
    "CACAO": False
}

marking =["marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",
          "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da",
          "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82",
          "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed"]

get_ids = 'match $ids isa stix-id;'


marking_id = "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da"
file_id = 'file--364fe3e5-b1f4-5ba3-b951-ee5983b3538d'


schema_path = path = str(pathlib.Path(__file__).parents[1])


def variables_id_list():
    return ['file--94ca-5967-8b3c-a906a51d87ac',
            'file--5a27d487-c542-5f97-a131-a8866b477b46',
            'email-message--72b7698f-10c2-565a-a2a6-b4996a2f2265',
            'email-message--cf9b4b7f-14c8-5955-8065-020e0316b559',
            'intrusion-set--0c7e22ad-b099-4dc3-b0df-2ea3f49ae2e6',
            'attack-pattern--7e33a43e-e34b-40ec-89da-36c9bb2cacd5',
            'autonomous-system--f720c34b-98ae-597f-ade5-27dc241e8c74']


def mitre_path():
    data_mitre_path = "data/mitre"
    top_dir_path = pathlib.Path(__file__).parents[1]
    return str(top_dir_path.joinpath(data_mitre_path).joinpath("enterprise-attack.json"))

def variables_failing_standard_data_file_paths() -> List[str]:
    data_standard_path = "data/standard/"

    standard_data_file_list = [
        'grouping.json']

    top_dir_path = pathlib.Path(__file__).parents[1]

    paths = []
    for file in standard_data_file_list:
        path = top_dir_path.joinpath(data_standard_path).joinpath(file)
        paths.append(str(path))

    return paths


def variables_standard_data_file_paths_missing() -> List[str]:
    data_standard_path = "data/standard/"

    standard_data_file_list = [
        "aaa_indicator.json",
        "attack-campaign.json",
        "course_action.json",
        'grouping.json'
    ]
    top_dir_path = pathlib.Path(__file__).parents[1]

    paths = []
    for file in standard_data_file_list:
        path = top_dir_path.joinpath(data_standard_path).joinpath(file)
        paths.append(str(path))

    return paths

def variables_standard_data_file_paths_success() -> List[str]:
    data_standard_path = "data/standard/"

    standard_data_file_list = [
        "aaa_attack_pattern.json",
        "aaa_identity.json",
        "aaa_malware.json",
        "artifact_basic.json",
        "artifact_encrypted.json",
        "autonomous.json",
        "directory.json",
        "domain.json",
        "email_basic_addr.json",
        "email_headers.json",
        "email_mime.json",
        "email_simple.json",
        'file_archive_unencrypted.json',
        'file_basic.json',
        'file_basic_encoding.json',
        'file_basic_parent.json',
        'file_binary.json',
        'file_image_simple.json',
        'file_ntfs_stream.json',
        'file_pdf_basic.json',
    ]
    top_dir_path = pathlib.Path(__file__).parents[1]

    paths = []
    for file in standard_data_file_list:
        path = top_dir_path.joinpath(data_standard_path).joinpath(file)
        paths.append(str(path))

    return paths

def variables_standard_data_file_paths() -> List[str]:

    top_dir_path = pathlib.Path(__file__).parents[1]
    data_standard_path = top_dir_path.joinpath("data/standard/")

    standard_data_file_list = []

    for root, dirs, files in os.walk(data_standard_path):
        for file in files:
            if file.endswith(".json"):
                standard_data_file_list.append(os.path.join(root, file))

    return standard_data_file_list

def aaa_grouping_path() -> str:
    data_standard_path = "data/standard/"
    top_dir_path = pathlib.Path(__file__).parents[1]
    return str(top_dir_path.joinpath(data_standard_path).joinpath("grouping.json"))

def aaa_indicator_path() -> str:
    data_standard_path = "data/standard/"
    top_dir_path = pathlib.Path(__file__).parents[1]
    return str(top_dir_path.joinpath(data_standard_path).joinpath("aaa_indicator.json"))

def x509_path() -> str:
    data_standard_path = "data/standard/"
    top_dir_path = pathlib.Path(__file__).parents[1]
    return str(top_dir_path.joinpath(data_standard_path).joinpath("x509_cert_v3_ext.json"))

def aaa_identity_path() -> str:
    data_standard_path = "data/standard/"
    top_dir_path = pathlib.Path(__file__).parents[1]
    return str(top_dir_path.joinpath(data_standard_path).joinpath("aaa_identity.json"))


def variable_all_standard_data_filepaths() -> List[str]:
    top_dir_path = pathlib.Path(__file__).parents[1]
    standard_data_path = top_dir_path.joinpath("data/standard/")
    paths = []

    files_in_dir = list(standard_data_path.iterdir())
    for file in files_in_dir:
        if file.exists() and file.is_file():
            paths.append(str(file))

    return [paths[0]]

def cert_filepaths() -> List[str]:
    paths = []

    cert_root = "data/stix_cert_data"

    cert_list = [
        "attack_pattern_sharing",
        "campaign_sharing",
        "confidence_sharing",
        "course_of_action_sharing",
        "data_marking_sharing",
        "grouping_sharing",
        "indicator_sharing",
        "infrastructure_sharing",
        "intrusion_set_sharing",
        "location_sharing",
        "malware_analysis_sharing",
        "malware_sharing",
        "note_sharing",
        "observed_data_sharing",
        "opinion_sharing",
        "report_sharing",
        "sighting_sharing",
        "threat_actor_sharing",
        "tool_sharing",
        "versioning",
        "vulnerability_sharing"
    ]

    cert_folders = ["consumer_example",
                    "consumer_test",
                    "producer_example",
                    "producer_test"]

    top_dir_path = pathlib.Path(__file__).parents[1]
    stix_data_path = top_dir_path.joinpath(cert_root)

    for folder in cert_list:
        for sub_folder in cert_folders:

            folder_path = stix_data_path.joinpath(folder).joinpath(sub_folder)
            if not folder_path.exists() or not folder_path.is_dir():
                print("Skipping because it does not exist: " + str(folder_path))
                continue

            files_in_dir = list(folder_path.iterdir())
            for file in files_in_dir:
                if file.exists() and file.is_file():
                    paths.append(str(file))
                else:
                    print("Skipping because it does not exist or not a file: " + str(file))

    return [paths[0]]



def cert_grouped_filepaths() -> List[List[str]]:
    paths = []

    cert_root = "data/stix_cert_data"

    cert_list = [
        "attack_pattern_sharing",
        "campaign_sharing",
        "confidence_sharing",
        "course_of_action_sharing",
        "data_marking_sharing",
        "grouping_sharing",
        "indicator_sharing",
        "infrastructure_sharing",
        "intrusion_set_sharing",
        "location_sharing",
        "malware_analysis_sharing",
        "malware_sharing",
        "note_sharing",
        "observed_data_sharing",
        "opinion_sharing",
        "report_sharing",
        "sighting_sharing",
        "threat_actor_sharing",
        "tool_sharing",
        "versioning",
        "vulnerability_sharing"
    ]

    cert_folders = ["consumer_example",
                    "consumer_test",
                    "producer_example",
                    "producer_test"]

    top_dir_path = pathlib.Path(__file__).parents[1]
    stix_data_path = top_dir_path.joinpath(cert_root)

    for folder in cert_list:
        for sub_folder in cert_folders:
            folder_path = stix_data_path.joinpath(folder).joinpath(sub_folder)
            if not folder_path.exists() or not folder_path.is_dir():
                continue

            files_in_dir = list(folder_path.iterdir())
            grouped_paths = []
            for file in files_in_dir:
                if file.exists() and file.is_file():
                    grouped_paths.append(str(file))
            paths.append(grouped_paths)
    return paths

class TestTypeDB(unittest.TestCase):

    def get_json_from_file(self,
                           file_path: str) -> List[dict]:
        assert pathlib.Path(file_path).is_file()
        print(f'I am about to load {file_path}')
        with open(file_path, mode="r", encoding="utf-8") as f:
            json_text = json.load(f)

        if isinstance(json_text, dict):
            json_text = [json_text]

        return json_text

    def test_initialise(self):
        """ Test the database initialisation function

        """
        TypeDBSink(connection=connection,
                   clear=True,
                   import_type=import_type,
                   schema_path=schema_path)


    def test_failed_initialise(self):
        """ Test the database initialisation function

        """
        with self.assertRaises(Exception) as context:
            TypeDBSink(connection=failed_connection,
                       clear=True,
                       import_type=import_type,
                       schema_path=schema_path)

        self.assertTrue('Client Error: Unable to connect to TypeDB server.' in str(context.exception))


    def setUp(self):
        self.clean_db()

    def tearDown(self):
        self.clean_db()

    def clean_db(self):
        """ Get all stix-ids and delete them

        """
        typedb = TypeDBSink(connection=connection,
                            clear=False,
                            import_type=import_type,
                            schema_path=schema_path)

        typedb.clear_db()


    def test_delete_dir(self):
        """ Load an entire directory and delete all files except marking objects

        """
        file_paths = variable_all_standard_data_filepaths()
        typedb_sink = TypeDBSink(connection=connection,
                                 clear=True,
                                 import_type=import_type,
                                 schema_path=schema_path)
        for file_path in file_paths:
            json_text = self.get_json_from_file(file_path)
            typedb_sink.add(json_text)

        stix_id_list = typedb_sink.get_stix_ids()
        typedb_sink.delete(stix_id_list)


    @parameterized.expand(variables_standard_data_file_paths_success())
    def test_delete(self, file_path: str):
        """ Load a single file and delete it

        Args:
            file_path (): the path and file name
        """
        typedb = TypeDBSink(connection=connection,
                            clear=True,
                            import_type=import_type,
                            schema_path=schema_path)
        json_text = self.get_json_from_file(file_path)
        typedb.add(json_text)

        local_list = typedb.get_stix_ids()
        result = typedb.delete(local_list)
        self.validate_successful_result(result)

    @parameterized.expand(cert_grouped_filepaths())
    def check_dir(self, file_paths: List[str]):
        """ Open a directory and load all the files, optionally printing them

        Args:
            dirpath ():
        """

        for file_path in file_paths:
            typedb_sink = TypeDBSink(connection=connection,
                                     clear=True,
                                     import_type=import_type,
                                     schema_path=schema_path)
            json_text = self.get_json_from_file(file_path)
            typedb_sink.add(json_text)

    @parameterized.expand(cert_filepaths())
    def test_cert(self, cert_file: str):

        json_text = self.get_json_from_file(cert_file)

        local_list1 = []
        for l in json_text:
            local_list1.append(l["id"])

        typedb = TypeDBSink(connection=connection,
                            clear=True,
                            import_type=import_type,
                            schema_path=schema_path)
        typedb.add(json_text)

        local_list_prior = typedb.get_stix_ids()
        typedb.delete(local_list_prior)

        local_list_post = typedb.get_stix_ids()


    def test_add_grouping_path(self):
        typedb_sink = TypeDBSink(connection=connection,
                                 clear=True,
                                 import_type=import_type,
                                 schema_path=schema_path)
        json_text = self.get_json_from_file(aaa_grouping_path())

        result = typedb_sink.add(json_text)
        self.validate_has_missing_dependencies(result)


    def test_add_files(self):


        typedb_sink = TypeDBSink(connection=connection,
                                 clear=True,
                                 import_type=import_type,
                                 schema_path=schema_path)
        files = variables_standard_data_file_paths()

        combined = []
        for file in files:
            json_text = self.get_json_from_file(file)

            combined = combined + json_text
        result = typedb_sink.add(combined)
        # TODO: Fix failing test
        #
        self.validate_successful_result(result)


    def test_add_x509_path(self):
        typedb_sink = TypeDBSink(connection=connection,
                                 clear=True,
                                 import_type=import_type,
                                 schema_path=schema_path)
        json_text = self.get_json_from_file(x509_path())

        result = typedb_sink.add(json_text)
        self.validate_successful_result(result)

    def test_add_indicator_path(self):
        typedb_sink = TypeDBSink(connection=connection,
                                 clear=True,
                                 import_type=import_type,
                                 schema_path=schema_path)
        json_text = self.get_json_from_file(aaa_indicator_path())

        result = typedb_sink.add(json_text)
        self.validate_has_missing_dependencies(result)

    def validate_contains_error(self,
                                results):
        count = 0
        for result in results:
            if result.status in [ ResultStatus.ERROR]:
                count = count + 1

        assert count == 1

    def validate_successful_result(self,
                                   results):
        for result in results:
            assert result.status in [ ResultStatus.SUCCESS, ResultStatus.ALREADY_IN_DB]

    def validate_has_missing_dependencies(self,
                                   results):
        for result in results:
            assert result.status in [ResultStatus.VALID_FOR_DB_COMMIT, ResultStatus.MISSING_DEPENDENCY]

    def test_add_identity_path(self):
        typedb_sink = TypeDBSink(connection=connection,
                                 clear=True,
                                 import_type=import_type,
                                 schema_path=schema_path)
        json_text = self.get_json_from_file(aaa_identity_path())

        result = typedb_sink.add(json_text)
        self.validate_successful_result(result)

    # TODO: Fix this
    @unittest.skip("Look at this test")
    def test_add_mitre(self):
        typedb_sink = TypeDBSink(connection=connection,
                                 clear=True,
                                 import_type=import_type,
                                 schema_path=schema_path)
        json_text = self.get_json_from_file(mitre_path())

        result = typedb_sink.add(json_text)
        self.validate_successful_result(result)

    def test_get_ids(self):
        typedb_sink = TypeDBSink(connection=connection,
                                 clear=True,
                                 import_type=import_type,
                                 schema_path=schema_path)
        json_text = self.get_json_from_file(aaa_identity_path())

        typedb_sink.add(json_text)

        my_id_list = typedb_sink.get_stix_ids()
        self.assertTrue(set(my_id_list) == {'identity--e5f1b90a-d9b6-40ab-81a9-8a29df4b6b65',
                                   'identity--f431f809-377b-45e0-aa1c-6a4751cae5ff'})

    @parameterized.expand(variables_standard_data_file_paths_success())
    def test_get_all_ids_loaded(self, path):
        variables_id_list()
        typedb_sink = TypeDBSink(connection=connection,
                                 clear=True,
                                 import_type=import_type,
                                 schema_path=schema_path)
        json_text = self.get_json_from_file(path)
        typedb_sink.add(json_text)

        stix_ids_list = typedb_sink.get_stix_ids()
        my_id_list = []
        for doc in json_text:
            id = doc['id']
            if isinstance(id, list):
                my_id_list = my_id_list + id
            else:
                my_id_list.append(id)

        self.assertTrue(set(my_id_list) == set(stix_ids_list))

    @parameterized.expand(variables_standard_data_file_paths())
    def test_all_ids_loaded_success(self, path):
        variables_id_list()
        typedb_sink = TypeDBSink(connection=connection,
                                 clear=True,
                                 import_type=import_type,
                                 schema_path=schema_path)
        json_text = self.get_json_from_file(path)

        result = typedb_sink.add(json_text)

        self.validate_successful_result(result)

    @parameterized.expand(variables_standard_data_file_paths())
    def test_all_ids_loaded_missing_dependencies(self, path):
        variables_id_list()
        typedb_sink = TypeDBSink(connection=connection,
                                 clear=True,
                                 import_type=import_type,
                                 schema_path=schema_path)
        json_text = self.get_json_from_file(path)


        result = typedb_sink.add(json_text)
        self.validate_has_missing_dependencies(result)


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG,
                        filename="test.log")
    loader = unittest.TestLoader()
    unittest.main()
