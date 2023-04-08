import json
import logging
import pathlib
import unittest
from typing import List

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

def test_path() -> str:
    data_standard_path = "data/mitre/"
    top_dir_path = pathlib.Path(__file__).parents[1]
    return str(top_dir_path.joinpath(data_standard_path).joinpath("attack_objects.json"))

def ice_attack_path() -> str:
    data_standard_path = "data/mitre/"
    top_dir_path = pathlib.Path(__file__).parents[1]
    return str(top_dir_path.joinpath(data_standard_path).joinpath("ics-attack.json"))

class TestMitre(unittest.TestCase):

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

    def get_json_from_file(self,
                           file_path: str) -> List[dict]:
        assert pathlib.Path(file_path).is_file()

        with open(file_path, mode="r", encoding="utf-8") as f:
            json_text = json.load(f)

        if isinstance(json_text, dict):
            json_text = [json_text]

        return json_text

    def validate_has_missing_dependencies(self,
                                   results):
        for result in results:
            assert result.status in [ResultStatus.VALID_FOR_DB_COMMIT, ResultStatus.MISSING_DEPENDENCY]

    def test_test_json(self):
        """ Test the database initialisation function

        """
        file_path = test_path()
        typedb = TypeDBSink(connection=connection,
                   clear=True,
                   import_type=import_type,
                   schema_path=schema_path)
        json_text = self.get_json_from_file(file_path)
        result = typedb.add(json_text)
        self.validate_has_missing_dependencies(result)


    def test_ics_attack(self):
        """ Test the database initialisation function

        """
        file_path = ice_attack_path()
        typedb = TypeDBSink(connection=connection,
                   clear=True,
                   import_type=import_type,
                   schema_path=schema_path)
        json_text = self.get_json_from_file(file_path)
        result = typedb.add(json_text)
        self.validate_has_missing_dependencies(result)

if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG,
                        filename="test.log")
    loader = unittest.TestLoader()
    unittest.main()