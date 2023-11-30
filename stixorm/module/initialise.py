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
import os
from typing import Dict
from typedb.driver import *
import logging
from typing import Dict, List

from typedb.api.connection.session import SessionType
from typedb.api.connection.transaction import TransactionType
from typedb.driver import TypeDB

logger = logging.getLogger(__name__)


attack_raw = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/index.json"

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
]]
tlp_ids = ["marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",
                   "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da",
                   "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82",
                   "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed"]

def setup_database(stix_connection: Dict[str, str], clear: bool):
    url = stix_connection["uri"] + ":" + stix_connection["port"]
    with TypeDB.core_driver(url) as driver:
        logger.debug(f'Database Clearing is [{clear}]')
        if driver.databases.contains(stix_connection["database"]):
            if clear:
                driver.databases.get(stix_connection["database"]).delete()
                driver.databases.create(stix_connection["database"])
            else:
                return
                # raise ValueError(f"Database '{database}' already exists")
        else:
            driver.databases.create(stix_connection["database"])

        logger.debug('.......................... clear complete')


def load_schema(stix_connection: Dict[str, str], rel_path=None, schema_type: str = "schema"):
    logger.debug(f'{stix_connection}')
    logger.debug(rel_path)
    logger.debug(schema_type)
    assert rel_path is not None, "Need a path to history a schema"
    assert os.path.exists(rel_path), "File path needs to exist"

    url = stix_connection["uri"] + ":" + stix_connection["port"]
    with TypeDB.core_driver(url) as driver:
        # Stage 1: Create the schema
        with driver.session(stix_connection["database"], SessionType.SCHEMA) as session:
            # Load schema from file
            with open(rel_path, "r") as schema_file:
                schema = schema_file.read()
            logger.debug('.....')
            logger.debug(f'Inserting {schema_type} ...')
            logger.debug('.....')
            with session.transaction(TransactionType.WRITE) as write_transaction:
                write_transaction.query.define(schema)
                write_transaction.commit()
            logger.debug('.....')
            logger.debug('Successfully committed schema!')
            logger.debug('.....')
            session.close()


def load_markings(stix_connection: Dict[str, str]):
    type_ql_list = []
    logger.info(f"========================== Database initialisation ============================")
    for mark_list in initial_markings:
        type_ql = " insert "
        for line in mark_list:
            type_ql += line
        type_ql_list.append(type_ql)
    load_typeql_data(type_ql_list, stix_connection)
    logger.info(f"===============================================================================\n\n")
    return_list = tlp_ids
    return return_list


def load_typeql_data(data_list, stix_connection: Dict[str, str]):
    url = stix_connection["uri"] + ":" + stix_connection["port"]
    with TypeDB.core_driver(url) as driver:
        # Stage 1: Create the schema
        with driver.session(stix_connection["database"], SessionType.DATA) as session:
            with session.transaction(TransactionType.WRITE) as write_transaction:
                logger.debug(f'Loading TLP markings')
                for data in data_list:
                    logger.debug(f'\n\n{data}\n\n')
                    insert_iterator = write_transaction.query.insert(data)

                    logger.debug(f'insert_iterator response ->\n{insert_iterator}')
                    for result in insert_iterator:
                        logger.info(f'typedb response ->\n{result}')

                write_transaction.commit()




def sort_layers(layers,
                cyclical,
                indexes: List[str],
                missing: List[str],
                dep_obj, add_or_del='del'):
    """ Sort the layers depending on whether they are "add" or "del" layers

    Args:
        layers ():
        cyclical ():
        indexes ():
        missing ():
        dep_obj ():
        add_or_del ():

    Returns:

    """
    # logger.debug(
    #     f"################################### enter sort_layers {add_or_del} ###############################################")
    # logger.debug(f'\nlayers -> {layers}\ncyclical indexes -> {cyclical}\nindexes -> {indexes}\nmissing -> {missing}')
    # logger.debug(f'add_or_del -> {add_or_del}\ndep_obj -> {dep_obj}')
    # logger.debug("-------------------------------  ------------------------------------------------")
    # Stage 1 - Initialise Variables
    # 1. Setup key variables
    loc_id = dep_obj['id']
    loc_list = dep_obj["dep_list"]
    locset = set(loc_list)
    mset = set(missing)
    iset = set(indexes)
    intset = locset.intersection(iset)
    diffset = locset.difference(intset)
    # Stage 2 - Analyse Choices
    # 2. check whether the object has dependencies in its dep_list
    if not loc_list:
        # 2.a empty depedency list
        dep_list_items = False
        logger.debug('### There are no dependencies')
    else:
        # 2.b dependency list has indexes in it
        dep_list_items = True
        logger.debug('### There are some dependencies')
    # 3. check whether the object id is in the missing list
    if loc_id in mset:
        id_in_missing = True
        logger.debug('### Current is the missing dependency of an existing record')
    else:
        id_in_missing = False
        logger.debug('### Current is not a missing dependency of an existing record')
    # 4. check whether any id in the object dependency list is not already loaded
    if not diffset:
        dep_id_not_loaded = False
        logger.debug('### No dependencies need to be added to missing')
    else:
        dep_id_not_loaded = True
        mset = mset | diffset
        logger.debug('### Missing - Some dependencies need to be added to missing')

    # Stage 3 - Execute Choices
    # 5. No dependencies and not in missing, append only
    if not dep_list_items and not id_in_missing:
        logger.debug('### Append object and return')
        if add_or_del == 'del':
            layers.append(dep_obj)
            indexes.append(loc_id)
        elif add_or_del == 'add':
            layers.insert(0, dep_obj)
            indexes.insert(0, loc_id)
        #logger.debug(f'layers -> {layers}\nindexes -> {indexes}\nmset -> {mset}')
        logger.debug(
            f"################################## end of  sort_layers {add_or_del} ####################################################")
        return layers, indexes, list(mset), cyclical
    # 6. There are no dependencies but id is in missing, delete from missing,follow the tree and reorder
    if not dep_list_items and id_in_missing:
        logger.debug('### delete from missing,follow the tree and reorder')
        mset.remove(loc_id)
        tree, circular = follow_the_tree(layers, dep_obj)
        cyclical = cyclical + circular
        logger.debug(f' tree -> {tree}')
        layers, indexes = reorder(layers, indexes, tree, dep_obj, add_or_del)
        #logger.debug(f'layers -> {layers}\nindexes -> {indexes}\nmset -> {mset}')
        logger.debug(
            f"################################## end of  sort_layers {add_or_del} ####################################################")
        return layers, indexes, list(mset), cyclical
    # 7 There are dependencies, object is not in missing, insert at front
    if dep_list_items and not id_in_missing:
        logger.debug('### Add current to the front of the record')
        if add_or_del == 'del':
            layers.insert(0, dep_obj)
            indexes.insert(0, loc_id)
        elif add_or_del == 'add':
            layers.append(dep_obj)
            indexes.append(loc_id)
        #logger.debug(f'layers -> {layers}\nindexes -> {indexes}\nmset -> {mset}')
        logger.debug(
            f"################################## end of  sort_layers {add_or_del} ####################################################")
        return layers, indexes, list(mset), cyclical
    # 8 There are dependencies, object is in missing , delete from missing,follow the tree and reorder
    if dep_list_items and id_in_missing:
        logger.debug(f'### delete from missing,follow the tree and reorder')
        mset.remove(loc_id)
        tree, circular = follow_the_tree(layers, dep_obj)
        cyclical = cyclical + circular
        logger.debug(f' tree -> {tree}')
        layers, indexes = reorder(layers, indexes, tree, dep_obj, add_or_del)
        #logger.debug(f'layers -> {layers}\nindexes -> {indexes}\nmset -> {mset}')
        logger.debug(
            f"################################## end of  sort_layers {add_or_del} ####################################################")
        return layers, indexes, list(mset), cyclical

    logger.debug("theres a massive problem")
    return layers, indexes, list(mset), cyclical



def reorder(layers, indexes, tree, dep_obj, add_or_del):
    """ Reorder the layers list of objects based on dependencies
    Args:
        layers (): ordered list of layers
        indexes (): list of indexes in the same order as layers
        tree (): list of indexes, based on finding a hierarchy depdnent on this record
        dep_obj (): a dependency object containing the new layer element to be added
        add_or_del (): a flag on whether the records represent insert or delete operations (order)
    Returns:
        layers (): ordered list of layers now including the dep_object
        indexes (): ordered list of stix ids to match the layers
    """
    front_layers = []
    front_indexes = []
    dep_layers = []
    dep_indexes = []
    dtree = []
    loc_list = dep_obj["dep_list"]
    tree = list(set(tree))
    logger.debug("%%%%%%%%%%%%%%% reorder 1 %%%%%%%%%%%%%%%%%%")
    #logger.debug(f'\n orig indexes -> {indexes}\n orig layers, {layers}\n dep_obj , {dep_obj}')
    logger.debug("%%%%%%%%%%%%%%% reorder 2 %%%%%%%%%%dep_obj%%%%%%%%")
    # 1. Copy elements from layers and indexes so they are in the order we want them
    if add_or_del == 'del':
        up_tree = reversed(tree)
    elif add_or_del == 'add':
        up_tree = tree
    for t in up_tree:
        front_layers.append(layers[t])
        front_indexes.append(indexes[t])
    # 1.B Handle the dep_list linkages
    for d in loc_list:
        for index, i in enumerate(indexes):
            if d == i:
                dtree.append(index)
                dep_layers.append(layers[index])
                dep_indexes.append(layers[index]['id'])
    # 2. Now order the tree in reverse numeric order, biggest first
    total_tree = tree + dtree
    total_tree.sort(reverse=True)
    # 3. Now delete the elements from layers and indexes
    # TODO: Error here for test_add_files
    for t in total_tree:
        layers.pop(t)
        indexes.pop(t)
    # 4. Add the dep_obj to the new lists
    if add_or_del == 'del':
        front_indexes.append(dep_obj['id'])
        front_layers.append(dep_obj)
        layers = front_layers + dep_layers + layers
        indexes = front_indexes + dep_indexes + indexes
    elif add_or_del == 'add':
        front_layers.insert(0, dep_obj)
        front_indexes.insert(0, dep_obj['id'])
        layers = dep_layers + front_layers + layers
        indexes = dep_indexes + front_indexes + indexes
    # 5. Assemble the final lists
    #logger.debug(f'\nfront_indexes -> {front_indexes}\n\nfront_layers, {front_layers}\n\n old layers, {layers}\n\nold indexes -> {indexes}')
    logger.debug("-------------------------------------------------------------------------------------")
    logger.debug("%%%%%%%%%%%%%%% end reorder %%%%%%%%%%%%%%%%%%")
    return layers, indexes


def follow_the_tree(layers, dep_obj):
    """ Follow the tree of dependencies and report back the list and any cyclical id's

    Args:
        layers ():
        dep_obj ():

    Returns:
        tree: a ist of imdexes numbers
        cyclical: a list of stix-ds in a cyclical relationship (error condition)

    """
    tree = []
    cyclical = []
    loc_id = dep_obj['id']
    loc_ids = [loc_id]
    loc_dep = dep_obj['dep_list']
    found = True
    found, ret_indexes, ret_ids, circular = find_id(loc_ids, loc_dep, layers)
    logger.debug(f'### Following First Level Tree, found {found},index {ret_indexes}, loc_id {ret_ids}')
    if found:
        tree = tree + ret_indexes
        loc_ids = ret_ids
        cyclical = circular
    while found:
        found, ret_indexes, ret_ids, circular = find_id(loc_ids, loc_dep, layers)
        logger.debug(f'### Following Tree, found {found},index {ret_indexes}, loc_id {ret_ids}')
        if found:
            tree = tree + ret_indexes
            loc_ids = ret_ids
    return tree, cyclical


def find_id(loc_ids, loc_dep, layers):
    """ Compare a list of ids, and find which layers are dependent on this list

    Args:
        loc_ids (list): one or more stix ids describing the record
        loc_dep (list): a list of stix ids that this record is dependent on

    Returns:
        found (boolean): whether the stix-ids were found in the depednency's of the layers
        indexes (list): a list of the index numbers that are dependencies
        ids (list): a list of layer stix-ids that are dependent on this record
    """
    cyclical = []
    found = False
    indexes = []
    ids = []
    for loc_id in loc_ids:
        for index, lay in enumerate(layers):
            if loc_id in lay['dep_list']:
                if lay['id'] in loc_dep:
                    cyclical.append(lay['id'])
                    cyclical.append(loc_id)
                found = True
                indexes.append(index)
                ids.append(lay['id'])

    return found, indexes, ids, cyclical


# if this file is run directly, then start here
if __name__ == '__main__':
    # define the localhost and default stix2 setup
    connection = {
        "uri": "localhost",
        "port": "1729",
        "database": "stix2",
        "user": None,
        "password": None,
        "clear": True
    }

    import_type = {
        "STIX21": True,
        "CVE": False,
        "identity": False,
        "location": False,
        "rules": False,
        "ATT&CK": True,
        "ATT&CK_Versions": ["12.0"],
        "ATT&CK_Domains": ["enterprise-attack", "mobile-attack", "ics-attack"],
        "CACAO": False
    }
