#
# Copyright (C) 2022 Vaticle
#
# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.
#

from typedb.client import *
from loguru import logger

@logger.catch
def initialise_database(uri, port, database, user, password, clear=False):
    url = uri + ":" + port
    with TypeDB.core_client(url) as client:
        if client.databases().contains(database):
            if clear:
                client.databases().get(database).delete()
            else:
                raise ValueError(f"Database '{database}' already exists")
        client.databases().create(database)
        # Stage 1: Create the schema
        with client.session(database, SessionType.SCHEMA) as session:
            # Load schema from file
            with open("stix/schema/cti-schema-v2.tql", "r") as schema_file:
                schema = schema_file.read()
            # Load rules from file
            with open("stix/schema/cti-rules.tql", "r") as rules_file:
                rules = rules_file.read()
            print('.....')
            print('Inserting schema ...')
            print('.....')
            with session.transaction(TransactionType.WRITE) as write_transaction:
                write_transaction.query().define(schema)
                write_transaction.commit()
            print('Inserting rules...')
            print('.....')
            # with session.transaction(TransactionType.WRITE) as write_transaction:
            #    write_transaction.query().define(rules)
            #    write_transaction.commit()
            print('.....')
            print('Successfully committed schema!')
            print('.....')
            session.close()
        
        
        with client.session(database, SessionType.DATA) as session:
            with session.transaction(TransactionType.WRITE) as write_transaction:
                for mark_list in initial_markings:
                    type_ql = " insert "
                    for line in mark_list:
                        type_ql += line
                        
                    print(f'--------------------------------------------------------------------------------')
                    print(f'{type_ql}')
                    write_transaction.query().insert(type_ql)
                
                write_transaction.commit()
            
            print('Successfully committed white, green, amber and red markings!')
            print('.....')
            print(f'--------------------------- Initialisation Phase Complete -----------------------------------------------------')
            session.close()
 
 

# make sure the four TLP Markings are loaded when the database initialises
initial_markings = [[
     '$mark isa tlp-white, has stix-type "marking-definition"', 
     ', has stix-id "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9"',
     ', has spec-version "2.1", has created 2017-01-20T00:00:00.000;'
 ], [
     '$mark isa tlp-green, has stix-type "marking-definition"', 
     ', has stix-id "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da"',
     ', has spec-version "2.1", has created 2017-01-20T00:00:00.000;'
 ], [
     '$mark isa tlp-amber, has stix-type "marking-definition"', 
     ', has stix-id "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82"',
     ', has spec-version "2.1", has created 2017-01-20T00:00:00.000;'
 ], [
     '$mark isa tlp-red, has stix-type "marking-definition"', 
     ', has stix-id "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed"',
     ', has spec-version "2.1", has created 2017-01-20T00:00:00.000;'
 ],
                     ]


# if this file is run directly, then start here
if __name__ == '__main__':
    # define the localhost and default stix2 setup
    data = {
        "uri": "localhost",
        "port": "1729",
        "database": "stix2",
        "user" : None,
        "password" : None,
        "clear": True
    }
    
    initialise_database(data["uri"], data["port"], data["database"], data["user"], data["password"], data["clear"])