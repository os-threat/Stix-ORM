# Python API
This is a tutorial to follow the API for the python language.

The interface is compatible with the DataStore API defined by 
the official [STIX2 library](https://stix2.readthedocs.io/en/latest/guide/datastore.html).

# Basic use cases

## Inserting a STIX Bundle

In this example we add a simple STIX2.1 bundle and then retrieve each single object in the bundle.

```python
import logging
from stixorm.module.authorise import import_type_factory
from stixorm.module.typedb import TypeDBSink,TypeDBSource
from stixorm.module.typedb_lib.instructions import ResultStatus
import json

logger = logging.getLogger()

# define the database data and import details
connection = {
    "uri": "localhost",
    "port": "1729",
    "database": "stix",
    "user": None,
    "password": None
}
import_type = import_type_factory.get_default_import()

sink = TypeDBSink(connection=connection,
                    clear=True,
                    import_type=import_type)

source = TypeDBSource(connection=connection,import_type=import_type)

with open('./data/threat_actor_identity.json','r') as file:
    bundle_dict = json.load(file)
    results = sink.add(bundle_dict)
    ins_ids = []
    for result in results:
        logger.info(f"Inserted object {result.id}")
        logger.info(f"Status {result.status}")
        ins_ids.append(result.id)
    # now retrieve the objects inserted
    for id in ins_ids:
        obj = source.get(id)
        logger.info(f"STIX type = {obj.type} and id = {obj.id}")


```
