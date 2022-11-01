"""Python STIX2 TypeDB Source/Sink"""
import errno
import io
import json
import os
import re
import stat
from typedb.client import *

#from .stql import stix2_to_typeql, get_embedded_match, raw_stix2_to_typeql, convert_ans_to_stix
from .import_stix_to_typeql import raw_stix2_to_typeql, stix2_to_match_insert
from .delete_stix_to_typeql import delete_stix_object, add_delete_layers
from .import_stix_utilities import get_embedded_match
from .export_intermediate_to_stix import convert_ans_to_stix

from stix2 import v21
from stix2.base import _STIXBase
from stix2.datastore import (
    DataSink, DataSource, DataSourceError, DataStoreMixin,
)
from stix2.datastore.filters import Filter, FilterSet, apply_common_filters
from stix2.parsing import parse
from stix2.serialization import fp_serialize
from stix2.utils import is_sdo, is_sco, is_sro

from stix.schema.initialise import initialise_database

import sys

import logging

#logging.basicConfig(level=logging.INFO, format='[%(asctime)s] %(levelname)s [%(name)s:%(lineno)s] %(message)s')

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

marking =["marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",
          "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da",
          "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82",
          "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed"]


class TypeDBSink(DataSink):
    """Interface for adding/pushing STIX objects to TypeDB.

    Can be paired with a TypeDBSource, together as the two
    components of a TypeDBStore.

    Args:
        - connection is a dict, containing:
            - uri (str): URI to TypeDB.
            - port (int): Port to TypeDB.
            - db (str): Name of TypeDB database.
            - user (str): Username for TypeDB, if cluster, otherwise None
            - password (str): Password for TypeDB, if cluster, otherwise None
        - clear (bool): If True, clear the TypeDB before adding objects.
        - import_type (str): It forces the parser to use either the stix2.1, or mitre att&ck

    """
    def __init__(self, connection, clear=False, import_type="STIX21", **kwargs):	
        super(TypeDBSink, self).__init__()
        logger.debug(f'TypeDBSink: {connection}')
        self._stix_connection = connection
        self.uri = connection["uri"]
        self.port = connection["port"]
        self.database = connection["database"]
        self.user = connection["user"]
        self.password = connection["password"]
        self.clear = clear
        self.import_type = import_type
        if self.import_type == "STIX21":
            self.allow_custom = False
        else:
            self.allow_custom = True
        
        try:
            initialise_database(self.uri, self.port, self.database, self.user, self.password, self.clear)
            
        except Exception as e:
            logger.error(f'Initialise TypeDB Error: {e}')                    

    @property
    def stix_connection(self):
        return self._stix_connection

    def get_stix_ids(self):
        """ Get all the stix-ids in a database, should be moved to typedb file

        Returns:
            id_list : list of the stix-ids in the database
        """
        get_ids_tql = 'match $ids isa stix-id;'
        g_uri = self.uri + ':' + self.port
        id_list = []
        with TypeDB.core_client(g_uri) as client:
            with client.session( self.database, SessionType.DATA) as session:
                with session.transaction(TransactionType.READ) as read_transaction:
                    answer_iterator = read_transaction.query().match(get_ids_tql)
                    ids = [ans.get("ids") for ans in answer_iterator]
                    for sid_obj in ids:
                        sid = sid_obj.get_value()
                        if sid in marking:
                            continue
                        else:
                            id_list.append(sid)
        return id_list

    def delete(self, stixid_list):
        """ Delete a list of STIX objects from the typedb server. Must include all related objects and relations

        Args:
            stixid_list (): The list of Stix-id's of the object's to delete
        """
        clean = 'match $a isa attribute; not { $b isa thing; $b has $a;}; delete $a isa attribute;'
        cleandict = {'delete': clean}
        cleanup = [cleandict]
        connection = {'uri': self.uri, 'port': self.port, 'database': self.database, 'user':self.user, 'password':self.password}
        try:
            typedb = TypeDBSource(connection, "STIX21")
            layers = []
            indexes = []
            missing = []

            for stixid in stixid_list:
                local_obj = typedb.get(stixid)
                dep_match, dep_insert, indep_ql, core_ql, dep_obj = raw_stix2_to_typeql(local_obj, self.import_type)
                del_match, del_tql = delete_stix_object(local_obj, dep_match, dep_insert, indep_ql, core_ql, self.import_type)
                logger.debug(' ---------------------------Delete Object----------------------')
                logger.debug(f'dep_match -> {dep_match}')
                logger.debug(f'dep_insert -> {dep_insert}')
                logger.debug(f'indep_ql -> {indep_ql}')
                logger.debug(f'dep_obj -> {dep_obj}')
                logger.debug("=========================== delete typeql below ====================================")
                logger.debug(f'del_match -> {del_match}')
                logger.debug(f'del_tql -> {del_tql}')
                if del_match == '' and del_tql == '':
                    continue
                dep_obj["delete"] = del_match + '\n' + del_tql
                if len(layers) == 0:
                    missing = dep_obj['dep_list']
                    indexes.append(dep_obj['id'])
                    layers.append(dep_obj)
                else:
                    layers, indexes, missing = add_delete_layers(layers, dep_obj, indexes, missing)
                logger.debug(' ---------------------------Object Delete----------------------')

            logger.debug("=========================== dependency indexes ====================================")
            logger.debug(f'indexes -> {indexes}')
            logger.debug("=========================== dependency indexes ====================================")
            ordered = layers + cleanup + cleanup
            for layer in ordered:
                logger.debug("666666666666666 delete 6666666666666666666666666666666666")
                logger.debug(f'del query -> {layer["delete"]}')
            logger.debug(f'\nordered -> {ordered}')
            with TypeDB.core_client(connection["uri"] + ":" + connection["port"]) as client:
                with client.session(connection["database"], SessionType.DATA) as session:
                    for layer in ordered:
                        with session.transaction(TransactionType.WRITE) as write_transaction:
                            logger.debug("77777777777777777 delete 777777777777777777777777777777777")
                            logger.debug(f'del query -> {layer["delete"]}')
                            query_future = write_transaction.query().delete(layer["delete"])
                            logger.debug(f'typedb delete response ->\n{query_future.get()}')
                            logger.debug("7777777777777777777777777777777777777777777777777777777777")
                            write_transaction.commit()
                    logger.debug(' ---------------------------Object Delete----------------------')


        except Exception as e:
            logger.error(f'Stix Object Deletion Error: {e}')
            if 'dep_match' in locals(): logger.error(f'dep_match -> {dep_match}')
            if 'dep_insert' in locals(): logger.error(f'dep_insert -> {dep_insert}')
            if 'indep_ql' in locals():logger.error(f'indep_ql -> {indep_ql}')
            if 'core_ql' in locals(): logger.error(f'core_ql -> {core_ql}')
            raise


    def add(self, stix_data=None, import_type="STIX21"):
        """Add STIX objects to the typedb server.

        Args:
            stix_data (STIX object OR dict OR str OR list): valid STIX 2.0 content
                in a STIX object (or list of), dict (or list of), or a STIX 2.0
                json encoded string.
            import_type (str): It forces the parser to use either the stix2.1,
                or the mitre attack typeql description. Values can be either:
                        - "STIX21"
                        - "mitre"

        Note:
            ``stix_data`` can be a Bundle object, but each object in it will be
            saved separately; you will be able to retrieve any of the objects
            the Bundle contained, but not the Bundle itself.

        """
        url = self.uri + ":" + self.port
        with TypeDB.core_client(url) as client:
            with client.session(self.database, SessionType.DATA) as session:
                logger.debug(f'------------------------------------ TypeDB Sink Session Start --------------------------------------------')
                self._separate_objects(stix_data, self.import_type, session)
                session.close()
                logger.debug(f'------------------------------------ TypeDB Sink Session Complete ---------------------------------')
    
    def _separate_objects(self, stix_data, import_type, session):
        """
          the details for the add details, checking what import_type of data object it is
        """
        logger.debug('----------------------------------------')
        logger.debug(f'going into separate objects function {stix_data}')
        logger.debug('-----------------------------------------------------')
        
        if isinstance(stix_data, (v21.Bundle)):
            logger.debug(f'isinstance Bundle')
            # recursively add individual STIX objects
            for stix_obj in stix_data.get("objects", []):
                self._separate_objects(stix_obj, import_type=import_type, session=session)

        elif isinstance(stix_data, _STIXBase):
            logger.debug(f'isinstance _STIXBase')
            # adding python STIX object
            self._submit_Stix_object(stix_data, import_type=import_type, session=session)

        elif isinstance(stix_data, (str, dict)):
            logger.debug(f'isinstance dict')
            parsed_data = parse(stix_data, allow_custom=self.allow_custom)
            if isinstance(parsed_data, _STIXBase):
                logger.debug(f'isinstance STIX Base')
                self._separate_objects(parsed_data, import_type=import_type, session=session)
            else:
                # custom unregistered object import_type
                self._submit_Stix_object(parsed_data, import_type=import_type, session=session)

        elif isinstance(stix_data, list):
            logger.debug(f'isinstance list')
            # recursively add individual STIX objects
            for stix_obj in stix_data:
                self._separate_objects(stix_obj, import_type=import_type, session=session)

        else:
            raise TypeError(
                "stix_data must be a STIX object (or list of), "
                "JSON formatted STIX (or list of), "
                "or a JSON formatted STIX bundle",
            )    
            
            
    def _submit_Stix_object(self, stix_obj, import_type, session):
        """Write the given STIX object to the TypeDB database.
        """
        try:
            logger.debug(f'----------------------------- Load {stix_obj.type} Object -----------------------------')
            logger.debug(stix_obj.serialize(pretty=True))
            logger.debug(f'----------------------------- TypeQL Statements -----------------------------')
            match_tql, insert_tql, dep_obj = stix2_to_match_insert(stix_obj, import_type)
            logger.debug(f'match_tql string?-> {match_tql}')
            logger.debug(f'insert_tql string?-> {insert_tql}')
            logger.debug(f'dep_obj string?-> {dep_obj}')
            logger.debug(f'----------------------------- Get Ready to Load Object -----------------------------')
            typeql_string = match_tql + insert_tql
            if not insert_tql:
                logger.warning(f'Marking Object type {stix_obj.type} already exists')
                return
            #logger.debug(typeql_string)
            logger.debug('=============================================================')
            with session.transaction(TransactionType.WRITE) as write_transaction:
                logger.debug(f'inside session and ready to load')
                insert_iterator = write_transaction.query().insert(typeql_string)

                logger.debug(f'insert_iterator response ->\n{insert_iterator}')
                for result in insert_iterator:
                    logger.debug(f'typedb response ->\n{result}')
                
                write_transaction.commit()
                logger.debug(f'----------------------------- write_transaction.commit -----------------------------')
                
        except Exception as e:
            logger.error(f'Stix Object Submission Error: {e}')
            logger.error(f'Query: {insert_tql}')
            raise
        
        
class TypeDBSource(DataSource):
    """Interface for searching/retrieving STIX objects from a TypeDB Database.

    Can be paired with a TypeDBSink, together as the two
    components of a TypeDBStore.

    Args:
        - connection is a dict, containing:
            - uri (str): URI to TypeDB.
            - port (int): Port to TypeDB.
            - db (str): Name of TypeDB database.
            - user (str): Username for TypeDB, if cluster, otherwise None
            - password (str): Password for TypeDB, if cluster, otherwise None
        - import_type (str): It forces the parser to use either the stix2.1, or mitre att&ck

    """
    def __init__(self, connection, import_type="STIX21", **kwargs):	
        super(TypeDBSource, self).__init__()
        logger.debug(f'TypeDBSource: {connection}')
        self._stix_connection = connection
        self.uri = connection["uri"]
        self.port = connection["port"]
        self.database = connection["database"]
        self.user = connection["user"]
        self.password = connection["password"]
        self.import_type = import_type
        if self.import_type == "STIX21":
            self.allow_custom = False
        else:
            self.allow_custom = True

    @property
    def stix_connection(self):
        return self._stix_connection

    def get(self, stix_id, _composite_filters=None):
        """Retrieve STIX object from file directory via STIX ID.

        Args:
            stix_id (str): The STIX ID of the STIX object to be retrieved.
            _composite_filters (FilterSet): collection of filters passed from the parent
                CompositeDataSource, not user supplied

        Returns:
            (STIX object): STIX object that has the supplied STIX ID.
                The STIX object is loaded from its json file, parsed into
                a python STIX object and then returned

        """
        try:
            obj_var, type_ql = get_embedded_match(stix_id)
            match = 'match ' + type_ql
            logger.debug(f' typeql -->: {match}')
            g_uri = self.uri + ':' + self.port
            with TypeDB.core_client(g_uri) as client:
                with client.session(self.database, SessionType.DATA) as session:
                    with session.transaction(TransactionType.READ) as read_transaction:
                        answer_iterator = read_transaction.query().match(match)
                        #logger.debug((f'have read the query -> {answer_iterator}'))
                        stix_dict = convert_ans_to_stix(answer_iterator, read_transaction, 'STIX21')
                        stix_obj = parse(stix_dict)
                        logger.debug(f'stix_obj -> {stix_obj}')
                        with open("export_final.json", "w") as outfile:  
                            json.dump(stix_dict, outfile)
                
        except Exception as e:
            logger.error(f'Stix Object Retrieval Error: {e}')
            stix_obj = None
        
        return stix_obj

    def query(self, query=None, version=None, _composite_filters=None):
        """Search and retrieve STIX objects based on the complete query.

        A "complete query" includes the filters from the query, the filters
        attached to this FileSystemSource, and any filters passed from a
        CompositeDataSource (i.e. _composite_filters).

        Args:
            query (list): list of filters to search on
            _composite_filters (FilterSet): collection of filters passed from
                the CompositeDataSource, not user supplied
            version (str): If present, it forces the parser to use the version
                provided. Otherwise, the library will make the best effort based
                on checking the "spec_version" property.

        Returns:
            (list): list of STIX objects that matches the supplied
                query. The STIX objects are loaded from their json files,
                parsed into a python STIX objects and then returned.

        """
        pass
    
    def all_versions(self, stix_id, version=None, _composite_filters=None):
        """Retrieve STIX object from file directory via STIX ID, all versions.

        Note: Since FileSystem sources/sinks don't handle multiple versions
        of a STIX object, this operation is unnecessary. Pass call to get().

        Args:
            stix_id (str): The STIX ID of the STIX objects to be retrieved.
            _composite_filters (FilterSet): collection of filters passed from
                the parent CompositeDataSource, not user supplied
            version (str): If present, it forces the parser to use the version
                provided. Otherwise, the library will make the best effort based
                on checking the "spec_version" property.

        Returns:
            (list): of STIX objects that has the supplied STIX ID.
                The STIX objects are loaded from their json files, parsed into
                a python STIX objects and then returned

        """
        pass
            