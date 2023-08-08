"""
Test loading data

"""
import json
from datetime import datetime
from pathlib import Path
import requests
import pytest
from stix2 import parse
from stixorm.module.authorise import import_type_factory
from stixorm.module.typedb import TypeDBSink,TypeDBSource
from stixorm.module.typedb_lib.instructions import ResultStatus

import_type = import_type_factory.get_default_import()

def test_campaign_data():
    url = "https://raw.githubusercontent.com/os-threat/Stix-ORM/main/test/data/standard/campaign.json"

    response = requests.get(url)
    if response.status_code==200:

        data = response.json()

        connection = {
            "uri": "localhost",
            "port": "1729",
            "database": "stixorm",
            "user": None,
            "password": None
        }

        db_write = TypeDBSink(
            connection=connection,
            clear=True,
            import_type=import_type,
        )

        db_read = TypeDBSource(
            connection=connection,
            import_type=import_type,
        )
        if type(data)==list:
            print('Ready to load ....')
            print(data)

            db_write.add(data)

            for obj in data:
                ret = db_read.get(stix_id=obj['id'])

                print(ret)

        db_write.clear_db()