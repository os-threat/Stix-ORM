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



import_type = import_type_factory.get_all_imports()

def variable_all_standard_data_filepaths() -> List[str]:
    top_dir_path = pathlib.Path(__file__).parents[1]
    standard_data_path = top_dir_path.joinpath("data/os-threat/")
    paths = []

    files_in_dir = list(standard_data_path.iterdir())
    for file in files_in_dir:
        if file.exists() and file.is_file():
            paths.append(str(file))

    return [paths[0]]
class TestOSThreat(unittest.TestCase):

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

if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG,
                        filename="test.log")
    loader = unittest.TestLoader()
    unittest.main()