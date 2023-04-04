"""Python STIX2 TypeDB Source/Sink"""
import os.path
import pathlib
import traceback
from dataclasses import dataclass
from returns._internal.pipeline.pipe import pipe
from returns.methods import unwrap_or_failure
from returns.pipeline import is_successful
from returns.pointfree import bind
from returns.result import safe, Result, Failure, Success
from returns.unsafe import unsafe_perform_io
from typedb.client import *
from stix.module.orm.import_objects import raw_stix2_to_typeql
from stix.module.orm.delete_object import delete_stix_object, add_delete_layers
from stix.module.orm.export_object import convert_ans_to_stix
from stix.module.parsing.parse_objects import parse
from .authorise import authorised_mappings
from .initialise import setup_database, load_schema, load_markings
import networkx as nx
from stix2 import v21
from stix2.base import _STIXBase
from stix2.datastore import (
    DataSink, DataSource, )
from stix2.datastore.filters import FilterSet

import logging

from stix.module.typedb_lib.handlers import handle_result
from stix.module.typedb_lib.logging import log_delete_instruction, log_delete_instruction_update_layer, log_delete_layers
from stix.module.typedb_lib.queries import delete_database, match_query, query_ids, delete_layers, build_match_id_query,\
    build_insert_query, query_id, add_instructions_to_typedb
from stix.module.typedb_lib.file import write_to_file
from stix.module.typedb_lib.instructions import Instructions, Status, AddInstruction, TypeQLObject
from .typedb_lib.import_type_factory import ImportType, ImportTypeFactory

# logging.basicConfig(level=logging.INFO, format='[%(asctime)s] %(levelname)s [%(name)s:%(lineno)s] %(message)s')

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


@dataclass
class TransactionObject:
    transaction: TypeDBTransaction
    session: TypeDBSession



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
                 import_type: Optional[ImportType]=None,
                 schema_path: Optional[str] = None,
                 strict_failure: bool = False, **kwargs):
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
        self.strict_failure = strict_failure

        self.schema_path = schema_path
        self.import_type: ImportType = import_type

        result = self.__initialise()
        if not is_successful(result):
            logging.exception("\n".join(traceback.format_exception(result.failure())))
            raise Exception(str(result.failure()))

    @safe
    def __initialise(self):
        assign_result = self.__assign_schemas()
        handle_result(assign_result, "assign result", self.strict_failure)

        assign_import_result = self.__assign_import_type()
        handle_result(assign_import_result, "assign import result", self.strict_failure)

        # Validate database can be connected
        validate_connection = self.__validate_connect_to_db()
        handle_result(validate_connection, "validate connection result", self.strict_failure)

        # 1. Setup database
        setup_database(self._stix_connection, self.clear)

        # 2. Load the Schema's
        # A. Load the Stix Schema
        schema_result = self.__load_stix_schema()
        handle_result(schema_result, "load schema result", self.strict_failure)
        # B. Load Stix Rules Schema
        rules_result = self.__load_stix_rules()
        handle_result(rules_result, "load stix rules result", self.strict_failure)
        # C. Load the Attack Schema
        attack_result = self.__load_attack_schema()
        handle_result(attack_result, "load attack result", self.strict_failure)
        # D. Load the OS-Hunt Schema
        markings_result = self.__load_stix_os_hunt()
        handle_result(markings_result, "load os hunt result", self.strict_failure)

        # 3. Load the Objects
        # Still to do

    @safe
    def __validate_connect_to_db(self):
        logger.debug("Attempting DB Connection")
        result: Result[TypeDBClient, Exception] = self.__get_core_client()
        result.bind(lambda client: client.databases().all())
        logger.debug("DB Connection Successful")

    @safe
    def __load_attack_schema(self):
        if self.clear and self.import_type.ATTACK:
            logger.debug("ATT&CK")
            load_schema(self._stix_connection, str(self.cti_schema_attack), "ATT&CK Schema")
            logger.debug("moving past load schema")
        else:
            logger.debug("ignoring load ATT&CK schema")

    @safe
    def __load_stix_os_hunt(self):
        if self.clear and self.import_type.os_hunt:
            logger.debug("attack")
            load_schema(self._stix_connection, str(self.cti_schema_os_hunt), "os-hunt Schema ")
            logger.debug("we have loaded os-threat schema")
        else:
            logger.debug("ignoring load  os hunt")

    @safe
    def __load_stix_rules(self):
        if self.clear and self.import_type.rules:
            logger.debug("rules")
            load_schema(self._stix_connection, str(self.cti_schema_stix_rules), "Stix 2.1 Rules")
            logger.debug("we have loaded Stix rules")
        else:
            logger.debug("ignoring check of stix rules")

    @safe
    def __load_stix_schema(self):
        if self.clear:
            load_schema(self._stix_connection, str(self.cti_schema_stix), "Stix 2.1 Schema ")
            self.loaded = load_markings(self._stix_connection)
            logger.debug("we have loaded Stix schema")
        else:
            logger.debug("ignoring load stix schema")

    @safe
    def __assign_schemas(self):
        if self.schema_path is None:
             self.schema_path = str(pathlib.Path(__file__).parents[2])

        # If relative paths are used it will depend upon the entry point i.e. working directory will need to be same level as typedb.py
        self.cti_schema_stix = pathlib.Path(self.schema_path).joinpath("stix/module/definitions/stix21/schema/cti-schema-v2.tql")
        assert os.path.isfile(self.cti_schema_stix)
        self.cti_schema_stix_rules = pathlib.Path(self.schema_path).joinpath("stix/module/definitions/stix21/schema/cti-rules.tql")
        assert os.path.isfile(self.cti_schema_stix_rules)
        self.cti_schema_os_intel = pathlib.Path(self.schema_path).joinpath("stix/module/definitions/os_threat/schema/cti-os-intel.tql")
        assert os.path.isfile(self.cti_schema_os_intel)
        self.cti_schema_os_hunt = pathlib.Path(self.schema_path).joinpath("stix/module/definitions/os_threat/schema/cti-os-hunt.tql")
        assert os.path.isfile(self.cti_schema_os_hunt)
        self.cti_schema_attack = pathlib.Path(self.schema_path).joinpath("stix/module/definitions/attack/schema/cti-attack.tql")
        assert os.path.isfile(self.cti_schema_attack)
        # if self.schema_path is None:
        #     self.schema_path = str(pathlib.Path.parent)
        #
        # self.cti_schema_path = pathlib.Path(self.schema_path).joinpath("stix/schema/cti-schema-v2.tql")
        # assert self.cti_schema_path.is_file(), "The schema does not exist: " + str(self.cti_schema_path)
        #
        # self.cti_schema_rules_path = pathlib.Path(self.schema_path).joinpath("stix/schema/cti-rules.tql")
        # assert self.cti_schema_rules_path.is_file(), "The schema does not exist: " + str(self.cti_schema_rules_path)

    @safe
    def __assign_import_type(self):
        if self.import_type is None:
            self.import_type = {"STIX21": True, "CVE": False, "identity": False, "location": False, "rules": False}
            self.import_type.update({"ATT&CK": False, "ATT&CK_Versions": ["12.0"],
                                     "ATT&CK_Domains": ["enterprise-attack", "mobile-attack", "ics-attack"],
                                     "CACAO": False})

    @property
    def stix_connection(self):
        return self._stix_connection

    def clear_db(self) -> bool:

        result = delete_database(self.uri, self.port, self.database)

        if is_successful(result):
            logger.debug("Successfully cleared database")
            return True
        else:
            logger.debug("Failed to clear cleared database")
            logger.warning(str(result.failure()))
            return False

    @safe
    def __filter_markings(self, stix_ids: List[StringAttribute]) -> List[str]:
        marking = ["marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",
                   "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da",
                   "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82",
                   "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed"]

        filtered_list = list(filter(lambda x: x.get_value() not in marking, stix_ids))
        return self.__string_attibute_to_string(filtered_list)

    def __string_attibute_to_string(self,
                                    string_attributes: List[StringAttribute]):
        return [stix_id.get_value() for stix_id in string_attributes]

    def __query_stix_ids(self):
        get_ids_tql = 'match $ids isa stix-id;'
        data_query = query_ids
        query_data = match_query(self.uri,
                                 self.port,
                                 self.database,
                                 get_ids_tql,
                                 data_query)
        if not is_successful(query_data):
            logging.exception("\n".join(traceback.format_exception(query_data.failure())))
            return Failure(query_data.failure())
        extracted_output = unsafe_perform_io(query_data)
        return Success(unwrap_or_failure(extracted_output))

    def get_stix_ids(self):
        """ Get all the stix-ids in a database, should be moved to typedb_lib file

        Returns:
            id_list : list of the stix-ids in the database
        """
        stix_ids_query = self.__query_stix_ids()

        transaction = pipe(
            bind(self.__filter_markings)
        )

        result = transaction(stix_ids_query)
        if is_successful(result):
            return result.unwrap()
        else:
            logging.exception("\n".join(traceback.format_exception(result.failure())))
            raise Exception(str(result.failure()))

    @safe
    def __retrieve_stix_id(self,
                           stix_id: str):
        type_db_source = unwrap_or_failure(self.__get_source_client())
        return type_db_source.get(stix_id)

    @safe
    def __delete_instruction(self,
                             stixid: str):

        stix_obj = self.__retrieve_stix_id(stixid)
        dep_match, dep_insert, indep_ql, core_ql, dep_obj = stix_obj.bind(
            lambda x: raw_stix2_to_typeql(x, self.import_type))
        del_match, del_tql = stix_obj.bind(
            lambda x: delete_stix_object(x, dep_match, dep_insert, indep_ql, core_ql, self.import_type))
        dep_obj["delete"] = del_match + '\n' + del_tql

        log_delete_instruction(del_match, dep_insert, indep_ql, dep_obj, del_match, del_tql)
        if del_match == '' and del_tql == '':
            return None
        else:
            return dep_obj

    @safe
    def __update_delete_layers(self,
                               layers,
                               indexes,
                               missing,
                               dep_obj):
        if dep_obj is None:
            return layers, indexes, missing
        if len(layers) == 0:
            missing = dep_obj['dep_list']
            indexes.append(dep_obj['id'])
            layers.append(dep_obj)
        else:
            layers, indexes, missing = add_delete_layers(layers, dep_obj, indexes, missing)
        return layers, indexes, missing

    @safe
    def __retrieve_delete_instructions(self,
                                       stixids: List[str]) -> Instructions:

        layers = []
        indexes = []
        missing = []

        instructions = Instructions()

        for stixid in stixids:
            del_result = self.__delete_instruction(stixid)
            update_result = del_result.bind(
                lambda dep_obj: self.__update_delete_layers(layers, indexes, missing, dep_obj))
            if is_successful(update_result):
                layers, indexes, missing = update_result.unwrap()
            else:
                instructions.insert_delete_instruction_error(stixid, update_result.failure())
                log_delete_instruction_update_layer(update_result)

        for layer in layers:
            instructions.insert_delete_instruction(layer['id'], layer)
        return instructions

    @safe
    def __order_delete_instructions(self,
                                    delete_instructions: Instructions):
        layer = {}
        layer['delete'] = 'match $a isa attribute; not { $b isa thing; $b has $a;}; delete $a isa attribute;'
        delete_instructions.insert_delete_instruction(
            "cleanup-1", layer
        )
        delete_instructions.insert_delete_instruction(
            "cleanup-2", layer
        )
        return delete_instructions

    def delete(self, stixid_list: List[str]) -> Instructions:
        """ Delete a list of STIX objects from the typedb_lib server. Must include all related objects and relations

        Args:
            stixid_list (): The list of Stix-id's of the object's to delete
        """

        delete_instruction_result = self.__retrieve_delete_instructions(stixid_list)
        order_instruction_result = delete_instruction_result.bind(lambda x: self.__order_delete_instructions(x))
        delete_from_database_result = order_instruction_result.bind(lambda order_instruction: delete_layers(self.uri,
                                                                                                            self.port,
                                                                                                            self.database,
                                                                                                            order_instruction))
        log_delete_layers(delete_from_database_result)
        if not is_successful(delete_from_database_result):
            logging.exception("\n".join(traceback.format_exception(delete_from_database_result.failure())))
            raise Exception(delete_from_database_result.failure())

        instructions = unsafe_perform_io(delete_from_database_result.unwrap())

        return instructions.convert_to_result()


    @safe
    def __get_core_client(self) -> TypeDBClient:
        typedb_url = self.uri + ":" + self.port
        return TypeDB.core_client(typedb_url)

    @safe
    def __get_source_client(self):
        connection = {'uri': self.uri,
                      'port': self.port,
                      'database': self.database,
                      'user': self.user,
                      'password': self.password}

        return TypeDBSource(connection, "STIX21")



    @safe
    def __generate_typeql_object(self, stix_dict: dict) -> TypeQLObject:

        logger.debug(f"\n================================================================\nim about to parse \n")
        stix_obj = parse(stix_dict, False, self.import_type)
        logger.debug(f'\n-------------------------------------------------------------\n i have parsed\n')
        dep_match, dep_insert, indep_ql, core_ql, dep_obj = raw_stix2_to_typeql(stix_obj, self.import_type)
        logger.debug(f'\ndep_match {dep_match} \ndep_insert {dep_insert} \nindep_ql {indep_ql} \ncore_ql {core_ql}')
        typeql_obj = TypeQLObject(
            dep_match=dep_match,
            dep_insert=dep_insert,
            indep_ql=indep_ql,
            core_ql=core_ql,
            dep_list=dep_obj['dep_list']
        )

        return typeql_obj

    @safe
    def __generate_instructions(self,
                                obj_list) -> Instructions:
        instructions = Instructions()
        for stix_dict in obj_list:

            typeql_object_result = self.__generate_typeql_object(stix_dict)

            if not is_successful(typeql_object_result):
                instructions.insert_instruction_error(stix_dict['id'], typeql_object_result.failure())
            else:
                typeql_object: TypeQLObject = typeql_object_result.unwrap()
                instructions.insert_add_instruction(stix_dict['id'], typeql_object)
                #typeql_object: TypeQLObject = typeql_object_result.unwrap()
               # is_missing = len(typeql_object.dep_list) == 0
                #if is_missing:
                #    instructions.insert_add_insert_missing_dependency(stix_dict['id'], typeql_object)
                #else:


        return instructions

    @safe
    def __create_instruction_dependency_graph(self,
                                              instructions: Instructions):
        directed_graph = nx.DiGraph()
        instruction: AddInstruction
        for instruction in instructions.instructions.values():

            if instruction.status in [Status.ERROR]:
                logging.debug("Skipping error " + instruction.id)
                continue

            dependencies = instruction.typeql_obj.dep_list

            this_node = instruction.id
            if not directed_graph.has_node(this_node):
                # logging.info("Already has node id " + this_node)
                # logging.info("Inserting dependency node " + this_node)
                directed_graph.add_node(this_node)

            for dependency_node in dependencies:
                if not directed_graph.has_node(dependency_node):
                   # logging.info("Already has dependency node id " + this_node)

                   # logging.info("Dependency node does not exist id " + this_node)
                    directed_graph.add_node(this_node)
                directed_graph.add_edge(dependency_node, this_node)
        instructions.add_dependencies(directed_graph)
        return instructions


    @safe
    def __generate_queries(self,
                           instructions: Instructions):
        result = instructions.create_insert_queries(build_insert_query)
        if is_successful(result):
            return instructions
        else:
            logging.exception("\n".join(traceback.format_exception(result.failure())))
            raise Exception(result.failure)


    def __check_missing_dependencies(self,
                                     instructions: Instructions):
        missing_ids_from_tree = instructions.missing_dependency_ids()

        if len(missing_ids_from_tree) == 0:
            return Success(instructions)

        query_result = build_match_id_query(missing_ids_from_tree)

        data_result = query_result.bind(lambda query: match_query(uri=self.uri,
                                                                  port=self.port,
                                                                  database=self.database,
                                                                  query=query,
                                                                  data_query=query_id,
                                                                  import_type=None))

        if not is_successful(data_result):
            return Failure(unsafe_perform_io(data_result.failure()))

        missing_ids_found_in_db = unsafe_perform_io(data_result.unwrap())
        # ids with no record in db and in dependency tree
        ids_missing = list(set(missing_ids_from_tree) - set(missing_ids_found_in_db))
        instructions.register_missing_dependencies(ids_missing)

        return Success(instructions)


    @safe
    def __reorder_instructions(self,
                               instructions: Instructions):
        order = list(nx.topological_sort(instructions.dependencies))
        instructions.add_insertion_order(order)
        return instructions




    def add(self, stix_data: Optional[List[dict]] = None) -> bool:
        """Add STIX objects to the typedb_lib server.
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
        logger.debug("1. starting in add")
        obj_result = self._gather_objects(stix_data)
        if not is_successful(obj_result):
            logging.exception("\n".join(traceback.format_exception(obj_result.failure())))


        generate_instructions_result = obj_result.bind(lambda obj_list: self.__generate_instructions(obj_list))
        logger.info("\n##########################################################################################################################################################\n")
        #print(f"generate instructions is {generate_instructions_result}")
        instruction_dependency_graph_result = generate_instructions_result.bind(lambda results: self.__create_instruction_dependency_graph(results))
        check_missing_dependency_result = instruction_dependency_graph_result.bind(lambda result: self.__check_missing_dependencies(result))

        # check missing results
        if not is_successful(check_missing_dependency_result):
            logging.exception("\n".join(traceback.format_exception(check_missing_dependency_result.failure())))
            raise Exception("failed to check missing dependencies")
        instructions: Instructions = check_missing_dependency_result.unwrap()
        if instructions.exist_missing_dependencies():
            return instructions.convert_to_result()
        if instructions.cyclical_ids():
            raise Exception("Missing dependencies")

        reorder_result = self.__reorder_instructions(instructions)

        queries_result = reorder_result.bind(lambda result: self.__generate_queries(result))

        add_to_database_result = queries_result.bind(lambda result: add_instructions_to_typedb(self.uri,
                                                                                               self.port,
                                                                                               self.database,
                                                                                               result))
        if not is_successful(add_to_database_result):
            logging.exception("\n".join(traceback.format_exception(add_to_database_result.failure())))
            raise Exception(add_to_database_result.failure())

        instructions = unsafe_perform_io(add_to_database_result).unwrap()

        return instructions.convert_to_result()


    @safe
    def _gather_objects(self, stix_data):
        """
          the details for the add details, checking what import_type of data object it is
        """
        #logger.debug(f" gethering ...{stix_data}")
        #logger.debug('----------------------------------------')
        #logger.debug(f'going into separate objects function {stix_data}')
        #logger.debug('-----------------------------------------------------')

        if isinstance(stix_data, (v21.Bundle)):
            logger.debug(f'isinstance Bundle')
            # recursively add individual STIX objects
            logger.debug(f'obects are {stix_data["objects"]}')
            return stix_data.get("objects", [])


        elif isinstance(stix_data, _STIXBase):
            logger.debug("base")
            logger.debug(f'isinstance _STIXBase')
            temp_list = []
            temp_list.append(stix_data)
            return temp_list

        elif isinstance(stix_data, (str, dict)):
            if stix_data.get("type", '') == 'bundle':
                return stix_data.get("objects", [])
            else:
                logger.debug("dcit")
                logger.debug(f'isinstance dict')
                temp_list = []
                temp_list.append(stix_data)
                return temp_list

        elif isinstance(stix_data, list):
            item_list = []
            for item in stix_data:
                if item.get("type", '') == 'bundle':
                    item_list = item_list + item.get("objects", [])
                else:
                    item_list.append(item)

            logger.debug(f'isinstance list')
            # recursively add individual STIX objects
            return item_list

        else:
            raise TypeError(
                "stix_data must be a STIX object (or list of), "
                "JSON formatted STIX (or list of), "
                "or a JSON formatted STIX bundle",
            )


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
        self.import_type: ImportType = self.__default_import_type() if import_type is None else import_type

    def __default_import_type(self):
        return ImportTypeFactory.get_default_import()

    @property
    def stix_connection(self):
        return self._stix_connection

    @safe
    def __retrieve_stix_object(self,
                               stix_id: str):
        logger.debug(f'__retrieve_stix_object: {stix_id}')
        obj_var, type_ql = get_embedded_match(stix_id, self.import_type)
        query = 'match ' + type_ql
        logger.debug(f'query is {query}')

        import_type = self.__default_import_type()

        data = match_query(uri=self.uri,
                           port=self.port,
                           database=self.database,
                           query=query,
                           data_query=convert_ans_to_stix,
                           import_type=self.import_type)

        logger.debug(f'data is -> {data}')
        stix_obj = unwrap_or_failure(data).bind(lambda x: parse(data=x, import_type=self.import_type))

        result = write_to_file("stix/module/orm/export_final.json", stix_obj)
        if not is_successful(result):
            logging.exception("\n".join(traceback.format_exception(result.failure())))
            logger.error(str(result.failure()))

        return stix_obj

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

        result = self.__retrieve_stix_object(stix_id)
        if is_successful(result):
            return result.unwrap()
        else:
            logging.exception("\n".join(traceback.format_exception(result.failure())))
            raise Exception(str(result.failure()))

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



def get_embedded_match(source_id, import_type):
    """
        Assemble the typeql variable and match statement given the stix-id, and the increment
    Args:
        source_id (): stix-id to use
        i (): number of times this type of object has been used
    Returns:
        source_var, the typeql string of the variable
        match, the typeql match statement
    """
    source_type = get_source_type(source_id, import_type)
    source_var = '$' + source_type
    if source_type == 'relationship':
        source_type = 'stix-core-relationship'
    match = f' {source_var} isa {source_type}, has stix-id "{source_id}";\n'
    return source_var, match

def get_source_type(source_id, import_type):
    """
        Get the type of the source_id
    Args:
        source_id (): stix-id to use
    Returns:
        source_type, the type of the source_id
    """
    auth = authorised_mappings(import_type)
    tmp_source = source_id.split('--')[0]
    source = ""
    for model in auth["conv"]["sdo"]:
        if model["type"] == tmp_source:
            source = model["typeql"]
            return source
    for model in auth["conv"]["sro"]:
        if model["type"] == tmp_source:
            source = model["typeql"]
            return source
    for model in auth["conv"]["sco"]:
        if model["type"] == tmp_source:
            source = model["typeql"]
            return source
    for model in auth["conv"]["meta"]:
        if model["type"] == tmp_source:
            source = model["typeql"]
            return source
    return source