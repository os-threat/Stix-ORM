import json
import os
import pathlib
from typing import List

import pytest
from typedb.client import *
import logging
from stixorm.module.authorise import import_type_factory
from stixorm.module.typedb import TypeDBSink
from stixorm.module.typedb_lib.instructions import ResultStatus

logging.basicConfig(level=logging.INFO, format='[%(asctime)s] %(levelname)s [%(name)s:%(lineno)s] %(message)s')
logger = logging.getLogger(__name__)

failed_connection = {
    "uri": "localhost",
    "port": "729",
    "database": "stix",
    "user": None,
    "password": None
}

# define the database data and import details
connection = {
    "uri": "localhost",
    "port": "1729",
    "database": "stix",
    "user": None,
    "password": None
}

import_type = import_type_factory.get_default_import()



marking =["marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",
          "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da",
          "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82",
          "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed"]

get_ids = 'match $ids isa stix-id;'


marking_id = "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da"
file_id = 'file--364fe3e5-b1f4-5ba3-b951-ee5983b3538d'



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
    top_dir_path = pathlib.Path(__file__).parents[0]
    return str(top_dir_path.joinpath(data_mitre_path).joinpath("enterprise-attack.json"))



def standard_data_files_with_dependencies() -> List[str]:


    standard_data_file_list = [
        "aaa_indicator.json",
        "standard_campaign.json",
        "standard_grouping.json",
        "standard_incident.json",
        "standard_intrusion_set.json",
        "standard_locations.json",
        "standard_note.json",
        "standard_observed.json",
        "standard_opinion.json",
        "standard_process_basic.json",
        "process_ext_win_service.json",
        "threat_actor.json",
        "tool.json",
        "vulnerability.json",
        "note.json",
        "report.json",
        "sighting.json",
        "sighting_no_observed.json",
        "sighting_with_observed.json",
        "network_tunnel_basic.json",
        "network_tunnel_DNS.json"
    ]

    return standard_data_file_list


def excluded_files() -> List[str]:
    return [
        'course_action.json',
        'translation_campaign.json'
    ]


def all_standard_data_file_paths() -> List[str]:

    top_dir_path = pathlib.Path(__file__).parents[0]
    data_standard_path = top_dir_path.joinpath("data/standard/")

    standard_data_file_list = []

    for root, dirs, files in os.walk(data_standard_path):
        for file in files:
            if file.endswith(".json") and file not in excluded_files():
                standard_data_file_list.append(os.path.join(root, file))
            else:
                logger.debug("Excluding from test: " + file)

    return standard_data_file_list



def standard_data_file_paths_with_dependencies() -> List[str]:

    top_dir_path = pathlib.Path(__file__).parents[0]
    data_standard_path = top_dir_path.joinpath("data/standard/")

    standard_data_file_list = []

    for root, dirs, files in os.walk(data_standard_path):
        for file in files:
            if file.endswith(".json") and file not in excluded_files() and file in standard_data_files_with_dependencies() :
                standard_data_file_list.append(os.path.join(root, file))
            else:
                logger.debug("Excluding from test: " + file)

    return standard_data_file_list

def standard_data_file_paths_with_no_dependencies() -> List[str]:

    top_dir_path = pathlib.Path(__file__).parents[0]
    data_standard_path = top_dir_path.joinpath("data/standard/")

    standard_data_file_list = []

    for root, dirs, files in os.walk(data_standard_path):
        for file in files:
            if file.endswith(".json") and file not in excluded_files() and file not in standard_data_files_with_dependencies() :
                standard_data_file_list.append(os.path.join(root, file))
            else:
                logger.debug("Excluding from test: " + file)

    return standard_data_file_list


def artifact_basic_path() -> str:
    data_standard_path = "data/standard/"
    top_dir_path = pathlib.Path(__file__).parents[0]
    return str(top_dir_path.joinpath(data_standard_path).joinpath("artifact_basic.json"))

def aaa_grouping_path() -> str:
    data_standard_path = "data/standard/"
    top_dir_path = pathlib.Path(__file__).parents[0]
    return str(top_dir_path.joinpath(data_standard_path).joinpath("grouping.json"))

def aaa_indicator_path() -> str:
    data_standard_path = "data/standard/"
    top_dir_path = pathlib.Path(__file__).parents[0]
    return str(top_dir_path.joinpath(data_standard_path).joinpath("aaa_indicator.json"))

def translation_campaign_path() -> str:
    data_standard_path = "data/standard/"
    top_dir_path = pathlib.Path(__file__).parents[0]
    return str(top_dir_path.joinpath(data_standard_path).joinpath("issues").joinpath("translation_campaign.json"))


def x509_path() -> str:
    data_standard_path = "data/standard/"
    top_dir_path = pathlib.Path(__file__).parents[0]
    return str(top_dir_path.joinpath(data_standard_path).joinpath("x509_cert_v3_ext.json"))

def aaa_identity_path() -> str:
    data_standard_path = "data/standard/"
    top_dir_path = pathlib.Path(__file__).parents[0]
    return str(top_dir_path.joinpath(data_standard_path).joinpath("aaa_identity.json"))

def network_tunnel_dns_path() -> str:
    data_standard_path = "data/standard/issues"
    top_dir_path = pathlib.Path(__file__).parents[0]
    return str(top_dir_path.joinpath(data_standard_path).joinpath("network_tunnel_DNS.json"))

def aaa_attack_path() -> str:
    data_standard_path = "data/standard/"
    top_dir_path = pathlib.Path(__file__).parents[0]
    return str(top_dir_path.joinpath(data_standard_path).joinpath("aaa_attack_pattern.json"))

def variable_all_standard_data_filepaths() -> List[str]:
    top_dir_path = pathlib.Path(__file__).parents[0]
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

    top_dir_path = pathlib.Path(__file__).parents[0]
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

    top_dir_path = pathlib.Path(__file__).parents[0]
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


@pytest.fixture
def setup_teardown():
    typedb = TypeDBSink(connection=connection,
                        clear=False,
                        import_type=import_type)

    typedb.clear_db()

    yield

    typedb = TypeDBSink(connection=connection,
                        clear=False,
                        import_type=import_type)

    typedb.clear_db()

class TestTypeDB:

    def get_json_from_file(self,
                           file_path: str) -> List[dict]:
        assert pathlib.Path(file_path).is_file()
        print(f'I am about to history {file_path}')
        with open(file_path, mode="r", encoding="utf-8") as f:
            json_text = json.load(f)

        if isinstance(json_text, dict):
            json_text = [json_text]

        return json_text

    def test_initialise(self, setup_teardown):
        """ Test the database initialisation function

        """
        TypeDBSink(connection=connection,
                   clear=True,
                   import_type=import_type)


    def test_failed_initialise(self, setup_teardown):
        """ Test the database initialisation function

        """
        with pytest.raises(Exception):
            TypeDBSink(connection=failed_connection,
                       clear=True,
                       import_type=import_type)

        #  TODO: add error type
        #assert ('Client Error: Unable to connect to TypeDB server.' in str(context.exception))

    def test_delete_identity_pattern(self, setup_teardown):
        file_path = aaa_identity_path()

        typedb = TypeDBSink(connection=connection,
                            clear=True,
                            import_type=import_type)
        json_text = self.get_json_from_file(file_path)
        typedb.add(json_text)

        local_list = typedb.get_stix_ids()
        result = typedb.delete(local_list)
        self.validate_successful_result(result)

    def test_artifact_basic(self, setup_teardown):
        file_path = artifact_basic_path()

        typedb = TypeDBSink(connection=connection,
                            clear=True,
                            import_type=import_type)
        json_text = self.get_json_from_file(file_path)
        typedb.add(json_text)

        local_list = typedb.get_stix_ids()
        result = typedb.delete(local_list)
        self.validate_successful_result(result)


    def test_delete_attack_pattern(self, setup_teardown):
        file_path = aaa_attack_path()

        typedb = TypeDBSink(connection=connection,
                            clear=True,
                            import_type=import_type)
        json_text = self.get_json_from_file(file_path)
        typedb.add(json_text)

        local_list = typedb.get_stix_ids()
        result = typedb.delete(local_list)
        self.validate_successful_result(result)


    def test_delete_dir(self, setup_teardown):
        """ Load an entire directory and delete all files except marking objects

        """
        file_paths = variable_all_standard_data_filepaths()
        typedb_sink = TypeDBSink(connection=connection,
                                 clear=True,
                                 import_type=import_type)
        for file_path in file_paths:
            json_text = self.get_json_from_file(file_path)
            typedb_sink.add(json_text)

        stix_id_list = typedb_sink.get_stix_ids()
        typedb_sink.delete(stix_id_list)




    @pytest.mark.parametrize("file_path", standard_data_file_paths_with_no_dependencies())
    def test_delete(self, setup_teardown, file_path: str):
        """ Load a single file and delete it

        Args:
            file_path (): the path and file name
        """
        typedb = TypeDBSink(connection=connection,
                            clear=True,
                            import_type=import_type)
        json_text = self.get_json_from_file(file_path)
        typedb.add(json_text)

        local_list = typedb.get_stix_ids()
        result = typedb.delete(local_list)
        self.validate_successful_result(result)

    @pytest.mark.parametrize("file_paths", cert_grouped_filepaths())
    def check_dir(self, setup_teardown, file_paths: List[str]):
        """ Open a directory and history all the files, optionally printing them

        Args:
            dirpath ():
        """

        for file_path in file_paths:
            typedb_sink = TypeDBSink(connection=connection,
                                     clear=True,
                                     import_type=import_type)
            json_text = self.get_json_from_file(file_path)
            typedb_sink.add(json_text)

    @pytest.mark.parametrize("cert_file", cert_filepaths())
    def test_cert(self, setup_teardown, cert_file: str):

        json_text = self.get_json_from_file(cert_file)

        local_list1 = []
        for l in json_text:
            local_list1.append(l["id"])

        typedb = TypeDBSink(connection=connection,
                            clear=True,
                            import_type=import_type)
        typedb.add(json_text)

        local_list_prior = typedb.get_stix_ids()
        typedb.delete(local_list_prior)

        local_list_post = typedb.get_stix_ids()


    def test_add_grouping_path(self, setup_teardown):
        typedb_sink = TypeDBSink(connection=connection,
                                 clear=True,
                                 import_type=import_type)
        json_text = self.get_json_from_file(aaa_grouping_path())

        result = typedb_sink.add(json_text)
        self.validate_has_missing_dependencies(result)


    def test_add_files(self, setup_teardown):


        typedb_sink = TypeDBSink(connection=connection,
                                 clear=True,
                                 import_type=import_type)
        files = all_standard_data_file_paths()

        combined = []
        for file in files:
            json_text = self.get_json_from_file(file)

            combined = combined + json_text
        result = typedb_sink.add(combined)
        self.validate_successful_result(result)

    def test_translation_campaign(self, setup_teardown):
        typedb_sink = TypeDBSink(connection=connection,
                                 clear=True,
                                 import_type=import_type)
        json_text = self.get_json_from_file(translation_campaign_path())

        result = typedb_sink.add(json_text)
        self.validate_successful_result(result)


    def test_add_x509_path(self, setup_teardown):
        typedb_sink = TypeDBSink(connection=connection,
                                 clear=True,
                                 import_type=import_type)
        json_text = self.get_json_from_file(x509_path())

        result = typedb_sink.add(json_text)
        self.validate_successful_result(result)

    def test_add_attack_path(self, setup_teardown):
        typedb_sink = TypeDBSink(connection=connection,
                                 clear=True,
                                 import_type=import_type)
        json_text = self.get_json_from_file(aaa_attack_path())

        result = typedb_sink.add(json_text)
        self.validate_successful_result(result)

    def test_add_indicator_path(self, setup_teardown):
        typedb_sink = TypeDBSink(connection=connection,
                                 clear=True,
                                 import_type=import_type)
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

    def test_add_identity_path(self, setup_teardown):
        typedb_sink = TypeDBSink(connection=connection,
                                 clear=True,
                                 import_type=import_type)
        json_text = self.get_json_from_file(aaa_identity_path())

        result = typedb_sink.add(json_text)
        self.validate_successful_result(result)

    def test_network_tunnel_dns_path(self, setup_teardown):
        typedb_sink = TypeDBSink(connection=connection,
                                 clear=True,
                                 import_type=import_type)
        json_text = self.get_json_from_file(network_tunnel_dns_path())

        result = typedb_sink.add(json_text)
        self.validate_successful_result(result)


    def test_get_ids(self, setup_teardown):
        typedb_sink = TypeDBSink(connection=connection,
                                 clear=True,
                                 import_type=import_type)
        json_text = self.get_json_from_file(aaa_identity_path())

        typedb_sink.add(json_text)

        my_id_list = typedb_sink.get_stix_ids()
        assert (set(my_id_list) == {'identity--e5f1b90a-d9b6-40ab-81a9-8a29df4b6b65',
                                   'identity--f431f809-377b-45e0-aa1c-6a4751cae5ff'})

    @pytest.mark.parametrize("path", standard_data_file_paths_with_no_dependencies())
    def test_get_all_ids_loaded(self, setup_teardown, path):
        variables_id_list()
        typedb_sink = TypeDBSink(connection=connection,
                                 clear=True,
                                 import_type=import_type)
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

        assert (set(my_id_list) == set(stix_ids_list))

    @pytest.mark.parametrize("path", standard_data_file_paths_with_no_dependencies())
    def test_all_ids_loaded_success(self,setup_teardown, path):
        variables_id_list()
        typedb_sink = TypeDBSink(connection=connection,
                                 clear=True,
                                 import_type=import_type)
        json_text = self.get_json_from_file(path)

        result = typedb_sink.add(json_text)

        self.validate_successful_result(result)

    @pytest.mark.parametrize("path", standard_data_file_paths_with_dependencies())
    def test_all_ids_loaded_missing_dependencies(self, setup_teardown, path):
        variables_id_list()
        typedb_sink = TypeDBSink(connection=connection,
                                 clear=True,
                                 import_type=import_type)
        json_text = self.get_json_from_file(path)


        result = typedb_sink.add(json_text)
        self.validate_has_missing_dependencies(result)


