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

## Retrieving all STIX ids in the database

```get_stix_ids()```

This returns a list of all STIX ids in the database, excluding the markings:
* TLP_WHITE
* TLP_GREEN
* TLP_AMBER
* TLP_RED

```
>>> sink.get_stix_ids()
[
    'identity--733c5838-34d9-4fbf-949c-62aba761184c', 
    'relationship--a2e3efb5-351d-4d46-97a0-6897ee7c77a0', 
    'threat-actor--dfaa8d77-07e2-4e28-b2c8-92e9f7b04428'
]
```

## Retrieving a single STIX object with the ID

```get(stix_id: str)```

If you know there is only one object with a specific STIX id, you can use the `get()` method which returns the object directly:

```
>>> source.get_stix('threat-actor--dfaa8d77-07e2-4e28-b2c8-92e9f7b04428')
ThreatActor(
    type='threat-actor',
    spec_version='2.1',
    id='threat-actor--dfaa8d77-07e2-4e28-b2c8-92e9f7b04428',
    created='2014-11-19T23:39:03.893Z',
    modified='2014-11-19T23:39:03.893Z',
    name='Disco Team Threat Actor Group',
    description='This organized threat actor group operates to create profit from all types of crime.',
    threat_actor_types=['crime-syndicate'],
    aliases=['Equipo del Discoteca'],
    roles=['agent'],
    goals=['Steal Credit Card Information'],
    sophistication='expert',
    resource_level='organization',
    primary_motivation='personal-gain',
    revoked=False
)
```

If there are no results that match the ID, `get()` will raise an `Exception`.

<!-- Not implemented yet -->
<!-- ## Making queries

```query(query: List[str], version: str)```

Retrieves a list of STIX objects based on the query -->

## Deleting a STIX Bundle

```delete(stixid_list: List[str])```

This method deletes the list of STIX objects and returns a list of STIX objects and the status of the delete operation
```
>>> sink = TypeDBSink(
    connection=connection,
    clear=True,
    import_type=import_type,
)
>>> local_list = sink.get_stix_ids()  # retrieves all stix-ids in the database
>>> local_list
[
    'identity--733c5838-34d9-4fbf-949c-62aba761184c',
    'relationship--a2e3efb5-351d-4d46-97a0-6897ee7c77a0',
    'threat-actor--dfaa8d77-07e2-4e28-b2c8-92e9f7b04428'
]
>>> sink.delete(local_list)
[
    Result(
        id='relationship--a2e3efb5-351d-4d46-97a0-6897ee7c77a0',
        status=<ResultStatus.SUCCESS: 'success'>,
        error=None,
        message=None
    ),
    Result(
        id='threat-actor--dfaa8d77-07e2-4e28-b2c8-92e9f7b04428',
        status=<ResultStatus.SUCCESS: 'success'>,
        error=None,
        message=None
    ),
    Result(
        id='identity--733c5838-34d9-4fbf-949c-62aba761184c',
        status=<ResultStatus.SUCCESS: 'success'>,
        error=None,
        message=None
    ),
    Result(
        id='cleanup-1',
        status=<ResultStatus.SUCCESS: 'success'>,
        error=None,
        message=None
    ),
    Result(
        id='cleanup-2',
        status=<ResultStatus.SUCCESS: 'success'>, 
        error=None,
        message=None
    )
]
```
