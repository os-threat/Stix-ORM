# Installation

## Install the database
The first step is to install the TypeDB database.
Follow the instructions [here](https://docs.vaticle.com/docs/running-typedb/install-and-run) 
for your operating system or Docker.


You can also install the [TypeDB studio](https://docs.vaticle.com/docs/studio/overview) in case you want to perform native queries directly into the database
or for debugging purposes.

![image](https://docs.vaticle.com/docs/images/studio/studio.png)


## Install the python env
We advise you to use a python environment such as pyenv or pipenv or poetry.

```
    pyenv install 3.10.0
    pyenv virtualenv 3.10.0 stixorm
    pyenv activate stixorm
    pip install stixorm
```

If you want to install the latest version of the library you can also do directly
from this repository


```pip install https://github.com/os-threat/Stix-ORM```

## Initialize the database

The ORM is divided into 2 components:

* A sink: for reading only data
* A source: for writing only data

which fulfills the requirements of the Data Store [API](https://stix2.readthedocs.io/en/latest/guide/datastore.html).

The code snippet below shows how a Sink object should be created


```python
from stix.module.authorise import import_type_factory
from stix.module.typedb import TypeDBSink
from stix.module.typedb_lib.instructions import ResultStatus
import pathlib

import_type = import_type_factory.get_attack_import()
schema_path = path = str(pathlib.Path(__file__).parents[1])

connection = {
    "uri": "localhost",
    "port": "1729",
    "database": "stix",
    "user": None,
    "password": None
}

typedb = TypeDBSink(connection=connection,
                    clear=False,
                    import_type=import_type,
                    schema_path=schema_path)

typedb.clear_db()


```

The connection dictionary contains the parameters to connect to the TypeDB instance and the
import_type dictionary is used to choose between the following models:
* stix_models: the standard [STIX2.1](https://oasis-open.github.io/cti-documentation/stix/intro.html)
* attack_models: the MITRE [ATT&CK framework](https://attack.mitre.org/)
* os_threat: our custom objects
* cacao_models: the [CACAO standard](https://docs.oasis-open.org/cacao/security-playbooks/v1.0/security-playbooks-v1.0.html)
* kestrel_models: the [Kestrel](https://kestrel.readthedocs.io/en/stable/) language objects

You can mix various models with the create import method like so:

```python
import_type = import_type_factory.create_import(stix_21=True,attack=False,cacao=False,kestrel=False,os_intel=False,os_hunt=False)
```

The first time you initialize the database you should set the clear flag to true:

```python
typedb = TypeDBSink(connection=connection,
                    clear=True,
                    import_type=import_type,
                    schema_path=schema_path)

```

In the future sessions you should remember to disable the flag otherwise all data will be lost.


```python
typedb = TypeDBSink(connection=connection,
                    clear=False,
                    import_type=import_type,
                    schema_path=schema_path)

```

You are now ready to read and write STIX objects into your database.

Check the interaction [tutorials](https://github.com/cloud-accelerator/Stix-ORM/blob/brett-attack/docs/interactions/python_api/overview.md).
