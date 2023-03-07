import logging
import pathlib
from stix.module.authorise import import_type_factory
from stix.module.typedb import TypeDBSink
from stix.module.typedb_lib.instructions import ResultStatus
import json

logging.basicConfig(level=logging.INFO, format='[%(asctime)s] %(levelname)s [%(name)s:%(lineno)s] %(message)s')
logger = logging.getLogger(__name__)

# define the database data and import details
connection = {
    "uri": "localhost",
    "port": "1729",
    "database": "stix",
    "user": None,
    "password": None
}

import_type = import_type_factory.get_default_import()

schema_path = str(pathlib.Path(__file__).parents[3]/"stix"/"module")
print(schema_path)
typedb = TypeDBSink(connection=connection,
                    clear=True,
                    import_type=import_type,
                    schema_path=schema_path)

with open('./data/threat_actor_identity.json','r') as file:
    bundle_dict = json.load(file)
    result = typedb.add(bundle_dict)
    print(result)

