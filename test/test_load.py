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
import stix2

import_type = import_type_factory.get_default_import()

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

def test_campaign_data():
    url1 = "https://raw.githubusercontent.com/os-threat/Stix-ORM/main/test/data/standard/aaa_identity.json"
    url2 = "https://raw.githubusercontent.com/os-threat/Stix-ORM/main/test/data/standard/campaign.json"
    # Insert the identities first
    response = requests.get(url1)

    if response.status_code==200:

        identities = response.json()

        if type(identities)==list:
            print('Ready to load ....')

            inserts = db_write.add(identities)

            for result in inserts:
                assert result.message is None
                assert result.error is None
            for obj in identities:
                found = db_read.get(stix_id=obj['id'])

                assert type(found)==stix2.v21.sdo.Identity
                print("Object was found!")

        # insert the campaigns later

        url2 = "https://raw.githubusercontent.com/os-threat/Stix-ORM/main/test/data/standard/campaign.json"

        response = requests.get(url2)

        if response.status_code == 200:
            data = response.json()
            campaigns = []
            for campaign in data:
                #fix the identity
                campaign['created_by_ref']=identities[0]['id']
                campaigns.append(campaign)
            # missing dependencies here but why I just inserted the identiy before....
            inserts = db_write.add(campaigns)

            for result in inserts:
                assert result.message is None
                assert result.error is None

        db_write.clear_db()