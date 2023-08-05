import json
import pathlib
from typing import List

import pytest

from stixorm.module.authorise import import_type_factory
from stixorm.module.typedb import TypeDBSink
from stixorm.module.typedb_lib.instructions import ResultStatus


import_type = import_type_factory.create_import(stix_21=True,
                                                os_threat=True)

def variable_all_standard_data_filepaths() -> List[str]:
    top_dir_path = pathlib.Path(__file__).parents[0]
    standard_data_path = top_dir_path.joinpath("data/os-threat/")
    paths = []

    files_in_dir = list(standard_data_path.iterdir())
    for file in files_in_dir:
        if file.exists() and file.is_file():
            paths.append(str(file))

    return [paths[0]]
@pytest.fixture
def typedb_sink(generate_connection):

    schema_path = "path/to/schema.json"
    typedb = TypeDBSink(connection=generate_connection, clear=True, import_type=import_type)
    yield typedb
    typedb.clear_db()

class TestOSThreat:
    def test_delete_dir(self, typedb_sink):
        file_paths = variable_all_standard_data_filepaths()
        for file_path in file_paths:
            json_text = self.get_json_from_file(file_path)
            result = typedb_sink.add(json_text)

        stix_id_list = typedb_sink.get_stix_ids()
        typedb_sink.delete(stix_id_list)

    def get_json_from_file(self, file_path):
        assert pathlib.Path(file_path).is_file()

        with open(file_path, mode="r", encoding="utf-8") as f:
            json_text = json.load(f)

        if isinstance(json_text, dict):
            json_text = [json_text]

        return json_text

    def validate_has_missing_dependencies(self, results):
        for result in results:
            assert result.status in [ResultStatus.VALID_FOR_DB_COMMIT, ResultStatus.MISSING_DEPENDENCY]