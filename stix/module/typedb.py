"""Python STIX2 TypeDB Source/Sink"""
import errno
import io
import json
import os
import re
import stat
from typedb.client import *

#from .stql import stix2_to_typeql, get_embedded_match, raw_stix2_to_typeql, convert_ans_to_stix
from .stix2typeql import stix2_to_typeql, raw_stix2_to_typeql
from .py2typeql import get_embedded_match, convert_ans_to_stix

from stix2 import v21
from stix2.base import _STIXBase
from stix2.datastore import (
    DataSink, DataSource, DataSourceError, DataStoreMixin,
)
from stix2.datastore.filters import Filter, FilterSet, apply_common_filters
from stix2.parsing import parse
from stix2.serialization import fp_serialize
from stix2.utils import format_datetime, get_type_from_id, parse_into_datetime

from stix.schema.initialise import initialise_database

import sys

import logging
logger = logging.getLogger(__name__)

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
    def __init__(self, connection, clear=False, import_type="stix21", **kwargs):	
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
        if self.import_type == "stix21":
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
    

    def add(self, stix_data=None, import_type="stix21"):
        """Add STIX objects to the typedb server.

        Args:
            stix_data (STIX object OR dict OR str OR list): valid STIX 2.0 content
                in a STIX object (or list of), dict (or list of), or a STIX 2.0
                json encoded string.
            import_type (str): It forces the parser to use either the stix2.1,
                or the mitre attack typeql description. Values can be either:
                        - "stix21"
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
        
        if isinstance(stix_data, (v21.Bundle)):
            # recursively add individual STIX objects
            for stix_obj in stix_data.get("objects", []):
                self._separate_objects(stix_obj, import_type=import_type, session=session)

        elif isinstance(stix_data, _STIXBase):
            # adding python STIX object
            self._submit_Stix_object(stix_data, import_type=import_type, session=session)

        elif isinstance(stix_data, (str, dict)):
            parsed_data = parse(stix_data, allow_custom=self.allow_custom)
            if isinstance(parsed_data, _STIXBase):
                print(f'dict pathway')
                self._separate_objects(parsed_data, import_type=import_type, session=session)
            else:
                # custom unregistered object import_type
                self._submit_Stix_object(parsed_data, import_type=import_type, session=session)

        elif isinstance(stix_data, list):
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
            match_tql, insert_tql = raw_stix2_to_typeql(stix_obj, import_type)
            logger.debug(f'{match_tql+insert_tql}')
            logger.debug(f'----------------------------- Object Loaded -----------------------------')
            with session.transaction(TransactionType.WRITE) as write_transaction:
                if match_tql =='':
                    insert_iterator = write_transaction.query().insert(insert_tql) 
                    
                else:
                    insert_iterator = write_transaction.query().insert(match_tql+insert_tql)                    
                     
                for result in insert_iterator:
                    logger.debug(f'typedb response ->\n{result}')
                
                write_transaction.commit()
                
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
    def __init__(self, connection, import_type="stix21", **kwargs):	
        super(TypeDBSource, self).__init__()
        print(f'TypeDBSink: {connection}')
        self._stix_connection = connection
        self.uri = connection["uri"]
        self.port = connection["port"]
        self.database = connection["database"]
        self.user = connection["user"]
        self.password = connection["password"]
        self.import_type = import_type
        if self.import_type == "stix21":
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
            print(f' typeql -->: {match}')
            g_uri = self.uri + ':' + self.port
            with TypeDB.core_client(g_uri) as client:
                with client.session(self.database, SessionType.DATA) as session:
                    with session.transaction(TransactionType.READ) as read_transaction:
                        answer_iterator = read_transaction.query().match(match)
                        #logger.debug((f'have read the query -> {answer_iterator}'))
                        stix_obj = convert_ans_to_stix(answer_iterator, read_transaction, 'Stix21')
                        #logger.debug(f'stix_obj -> {stix_obj}')
                        with open("export_final.json", "w") as outfile:  
                            json.dump(stix_obj, outfile) 
                
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
            