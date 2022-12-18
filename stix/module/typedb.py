"""Python STIX2 TypeDB Source/Sink"""
import json
import pathlib

from returns._internal.pipeline.managed import managed
from returns.io import impure_safe, IOResult
from returns.pipeline import flow, is_successful
from returns.pointfree import bind
#from returns.pointfree import bind, bind_optional, bind_result
from returns.result import safe, Result
from returns.unsafe import unsafe_perform_io
from typedb.client import *

from .import_stix_to_typeql import raw_stix2_to_typeql, stix2_to_match_insert
from .delete_stix_to_typeql import delete_stix_object, add_delete_layers
from .import_stix_utilities import get_embedded_match
from .export_intermediate_to_stix import convert_ans_to_stix
from .initialise import setup_database, load_schema, sort_layers, load_markings, check_stix_ids

from stix2 import v21
from stix2.base import _STIXBase
from stix2.datastore import (
    DataSink, DataSource, )
from stix2.datastore.filters import FilterSet
from stix2.parsing import parse

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
    def __init__(self,
                 connection: Dict[str, str],
                 clear=False,
                 import_type=None,
                 schema_path :Optional[str] =None, **kwargs):
        super(TypeDBSink, self).__init__()
        logger.debug(f'TypeDBSink: {connection}')

        assert connection["uri"] is not None
        assert connection["port"] is not None
        assert connection["database"] is not None

        self._stix_connection = connection
        self.uri: str = connection["uri"]
        self.port: str = connection["port"]
        self.database: str = connection["database"]
        self.user: str = connection["user"]
        self.password: str = connection["password"]
        self.clear: bool = clear

        self.schema_path = schema_path
        self.import_type = import_type

        result = self.__initialise()
        if not is_successful(result):
            logger.error(str(result.failure()))
            raise Exception(str(result.failure()))

    @safe
    def __initialise(self):
        self.__assign_schemas()
        self.__assign_import_type()

        # Validate database can be connected
        self.__validate_connect_to_db()

        # 1. Setup database
        setup_database(self._stix_connection, self.clear)

        # 2. Load the Stix schema
        self.__load_stix_schema()
        # 3. Check for Stix Rules
        self.__check_stix_rules()
        # 3. Load the Stix Markings,
        self.__load_stix_markings()
        # 3. Check for Stix Rules
        self.__check_for_stix_rules_cacao()

    @safe
    def __validate_connect_to_db(self):
        logger.debug("Attempting DB Connection")
        result: Result[TypeDBClient, Exception] = self.__get_core_client()
        result.bind(lambda client: client.databases().all())
        logger.debug("DB Connection Successful")


    @safe
    def __check_for_stix_rules_cacao(self):
        if self.clear and self.import_type["CACAO"]:
            logger.debug("cacao")
            load_schema(self._stix_connection, str(self.cti_schema_rules_path), "Stix 2.1 Rules")
            logger.debug("moving past load schema")
        else:
            logger.debug("ignoring check stix rule for cacao")

    @safe
    def __load_stix_markings(self):
        if self.clear and self.import_type["ATT&CK"]:
            logger.debug("attack")
            load_schema(self._stix_connection, str(self.cti_schema_path), "Stix 2.1 Schema ")
            logger.debug("moving past load schema")
        else:
            logger.debug("ignoring load  stix markings")

    @safe
    def __check_stix_rules(self):
        if self.clear and self.import_type["rules"]:
            logger.debug("rules")
            load_schema(self._stix_connection, str(self.cti_schema_rules_path), "Stix 2.1 Rules")
            logger.debug("moving past load rules")
        else:
            logger.debug("ignoring check of stix rules")

    @safe
    def __load_stix_schema(self):
        if self.clear:
            load_schema(self._stix_connection, str(self.cti_schema_path), "Stix 2.1 Schema ")
            self.loaded = load_markings(self._stix_connection)
            logger.debug("moving past load Stix schema")
        else:
            logger.debug("ignoring load stix schema")

    @safe
    def __assign_schemas(self):
        if self.schema_path is None:
            self.schema_path = str(pathlib.Path.parent)

        self.cti_schema_path = pathlib.Path(self.schema_path).joinpath("stix/schema/cti-schema-v2.tql")
        assert self.cti_schema_path.is_file(), "The schema does not exist: " + str(self.cti_schema_path)

        self.cti_schema_rules_path = pathlib.Path(self.schema_path).joinpath("stix/schema/cti-rules.tql")
        assert self.cti_schema_rules_path.is_file(), "The schema does not exist: " + str(self.cti_schema_rules_path)

    @safe
    def __assign_import_type(self):
        if self.import_type is None:
            self.import_type = {"STIX21": True, "CVE": False, "identity": False, "location": False, "rules": False}
            self.import_type.update({"ATT&CK": False, "ATT&CK_Versions": ["12.0"],
                                "ATT&CK_Domains": ["enterprise-attack", "mobile-attack", "ics-attack"], "CACAO": False})

    @property
    def stix_connection(self):
        return self._stix_connection


    @impure_safe
    def __delete_database(self,
           session):
        return session.map(lambda s: s.database().delete())

    @impure_safe
    def __close_session(self,
           session):
        session.map(lambda s: s.close())

    def clear_db(self) -> bool:

        result = self.__get_datatype_session() \
            .map(lambda session: (session, self.__delete_database(session))) \
            .map(lambda v: self.__close_session(v[0]))


        if is_successful(result):
            logger.debug("Successfully cleared database")
            return True
        else:
            logger.debug("Failed to clear cleared database")
            logger.warning(str(result.failure()))
            return False


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

    def delete(self, stixid_list: List[str]) -> bool:
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
                logger.debug(f'dep_match -> {dep_match}\n dep_insert -> {dep_insert}')
                logger.debug(f'indep_ql -> {indep_ql}\n dep_obj -> {dep_obj}')
                logger.debug("=========================== delete typeql below ====================================")
                logger.debug(f'del_match -> {del_match}\n del_tql -> {del_tql}')
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

    @safe
    def __get_core_client(self):
        typedb_url = self.uri + ":" + self.port
        return TypeDB.core_client(typedb_url)

    @impure_safe
    def __get_datatype_session(self) -> TypeDBSession:
        type_db_client = self.__get_core_client()
        return type_db_client.map(lambda client : client.session(self.database, SessionType.DATA))

    @impure_safe
    def __get_read_transaction(self,
                               session: TypeDBSession) -> TypeDBTransaction:
        return session.transaction(TransactionType.READ)

    def get_stix_ids(self):
        """ Get all the stix-ids in a database, should be moved to typedb file

        Returns:
            id_list : list of the stix-ids in the database
        """
        id_list: List[str] = []
        get_ids = 'match $ids isa stix-id;'

        with self.__get_core_client() as client:
            with client.session(self.database, SessionType.DATA) as session:
                with session.transaction(TransactionType.READ) as read_transaction:
                    answer_iterator = read_transaction.query().match(get_ids)
                    ids = [ans.get("ids") for ans in answer_iterator]
                    for sid_obj in ids:
                        sid: str = sid_obj.get_value()
                        if sid in marking:
                            continue
                        else:
                            id_list.append(sid)
        return id_list

    @safe
    def add(self, stix_data: Optional[List[dict]] = None) -> bool:
        """Add STIX objects to the typedb server.
            1. Gather objects into a list
            2. For each object
                a. get raw stix to tql
                b. add object to an ordered list
                c. return the ordered list
            3. Add each object in the ordered list
        Args:
            stix_data (STIX object OR Bundle OR dict OR list): valid STIX 2.1 content
                in a STIX object (or list of), dict (or list of), or a STIX 2.1
                json encoded string.
            import_type (dict): It forces the parser to use either the stix2.1,
                or the mitre attack typeql description. Values can be either:
                        - "STIX21"
                        - "mitre"
        Note:
            ``stix_data`` can be a Bundle object, but each object in it will be
            saved separately; you will be able to retrieve any of the objects
            the Bundle contained, but not the Bundle itself.
        """
        layers = []
        indexes = []
        missing = []
        cyclical = []
        try:
            # 1. gather objects into a list
            obj_list = self._gather_objects(stix_data)
            logger.debug(f'\n\n object list is  {obj_list}')
            # 2. for stix ibject in list
            for stix_dict in obj_list:
                # 3. Parse stix objects and get typeql and dependency
                stix_obj = parse(stix_dict)
                dep_match, dep_insert, indep_ql, core_ql, dep_obj = raw_stix2_to_typeql(stix_obj, self.import_type)
                dep_obj["dep_match"] = dep_match
                dep_obj["dep_insert"] = dep_insert
                dep_obj["indep_ql"] = indep_ql
                dep_obj["core_ql"] = core_ql
                # 4. Order the list of stix objects, and collect errors
                logger.debug(f'\ndep object {dep_obj}')
                if len(layers) == 0:
                    # 4a. For the first record to order
                    missing = dep_obj['dep_list']
                    indexes.append(dep_obj['id'])
                    layers.append(dep_obj)
                else:
                    # 4b. Add up and return the layers, indexes, missing and cyclical lists
                    add = 'add'
                    layers, indexes, missing, cyclical = sort_layers(layers, cyclical, indexes, missing, dep_obj, add)
                    logger.debug(f'\npast sort {layers}')

            # 5. If missing then check to see if the records are in the database, or raise an error
            mset = set(missing)
            logger.debug(f'missing stuff {len(missing)} - {len(set(missing))}')
            logger.debug(f'mset {mset}')
            if mset:
                list_in_database = check_stix_ids(list(mset), self._stix_connection)
                real_missing = list(mset.difference(set(list_in_database)))
                logger.debug(f'\nmissing {missing}\n\n loaded {real_missing}')
                if real_missing:
                    raise Exception(f'Error: Missing Stix deopendencies, id={real_missing}')
            # 6. If cyclicla, just raise an error for the moment
            if cyclical:
                raise Exception(f'Error: Cyclical Stix Dependencies, id={cyclical}')
            # 7. Else go ahead and add the records to the database
            url = self.uri + ":" + self.port
            logger.debug(f'url {url}')
            with TypeDB.core_client(url) as client:
                with client.session(self.database, SessionType.DATA) as session:
                    logger.debug(f'------------------------------------ TypeDB Sink Session Start --------------------------------------------')
                    for lay in layers:
                        logger.debug(f'------------------------------------ Load Object --------------------------------------------')
                        logger.debug(f' lay {lay}')
                        self._submit_Stix_object(lay, session)
                    session.close()
                    logger.debug(f'------------------------------------ TypeDB Sink Session Complete ---------------------------------')

        except Exception as e:
            logger.error(f'Stix Add Object Function Error: {e}')

    def _gather_objects(self, stix_data):
        """
          the details for the add details, checking what import_type of data object it is
        """
        logger.debug(f" gethering ...{stix_data}")
        logger.debug('----------------------------------------')
        logger.debug(f'going into separate objects function {stix_data}')
        logger.debug('-----------------------------------------------------')



        if isinstance(stix_data, (v21.Bundle)):
            logger.debug(f'isinstance Bundle')
            # recursively add individual STIX objects
            logger.debug(f'obects are {stix_data["objects"]}')
            return stix_data.get("objects", [])


        elif isinstance(stix_data, _STIXBase):
            logger.debug("base")
            logger.debug(f'isinstance _STIXBase')
            temp_list = []
            return temp_list.append(stix_data)

        elif isinstance(stix_data, (str, dict)):
            if stix_data.get("type", '') == 'bundle':
                return stix_data.get("objects", [])
            else:
                logger.debug("dcit")
                logger.debug(f'isinstance dict')
                temp_list = []
                return temp_list.append(stix_data)

        elif isinstance(stix_data, list):
            logger.debug(f'isinstance list')
            # recursively add individual STIX objects
            return stix_data

        else:
            raise TypeError(
                "stix_data must be a STIX object (or list of), "
                "JSON formatted STIX (or list of), "
                "or a JSON formatted STIX bundle",
            )
            
    def _submit_Stix_object(self, layer, session):
        """Write the given STIX object to the TypeDB database.
        """
        try:
            dep_match = layer["dep_match"]
            dep_insert = layer["dep_insert"]
            indep_ql = layer["indep_ql"]
            if dep_match == '':
                match_tql = ''
            else:
                match_tql = 'match ' + dep_match
            if indep_ql == '' and dep_insert == '':
                insert_tql = ''
            else:
                insert_tql = 'insert ' + indep_ql + dep_insert
            logger.debug(f'match_tql string?-> {match_tql}')
            logger.debug(f'insert_tql string?-> {insert_tql}')
            logger.debug(f'----------------------------- Get Ready to Load Object -----------------------------')
            typeql_string = match_tql + insert_tql
            if not insert_tql:
                logger.warning(f'Marking Object type {layer["type"]} already exists')
                return
            #logger.debug(typeql_string)
            logger.debug('=============================================================')
            with session.transaction(TransactionType.WRITE) as write_transaction:
                logger.debug(f'inside session and ready to load')
                insert_iterator = write_transaction.query().insert(typeql_string)
                logger.debug(f'insert_iterator response ->\n{insert_iterator}')
                # Capture error here
                # log it - object id
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
    def __init__(self, connection: Dict[str, str], import_type=None, **kwargs):
        super(TypeDBSource, self).__init__()
        logger.debug(f'TypeDBSource: {connection}')

        assert connection["uri"] is not None
        assert connection["port"] is not None
        assert connection["database"] is not None

        self._stix_connection = connection
        self.uri = connection["uri"]
        self.port = connection["port"]
        self.database = connection["database"]
        self.user = connection["user"]
        self.password = connection["password"]
        self.import_type = self.__default_import_type() if import_type is None else import_type

    def __default_import_type(self):
        import_type = {"STIX21": True,
                       "CVE": False,
                       "identity": False,
                       "location": False,
                       "rules": False}
        import_type.update({"ATT&CK": False, "ATT&CK_Versions": ["12.0"],
                            "ATT&CK_Domains": ["enterprise-attack",
                                               "mobile-attack",
                                               "ics-attack"],
                            "CACAO": False})
        return import_type

    @property
    def stix_connection(self):
        return self._stix_connection

    def get(self, stix_id: str, _composite_filters=None):
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
            