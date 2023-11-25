"""Python STIX2 TypeDB Source/Sink"""
import os.path
import pathlib
import traceback
from typing import Dict
from dataclasses import dataclass
from typedb.driver import *
from typing import List, Optional, Dict
from typedb.api.connection.driver import TypeDBDriver
from typedb.api.connection.session import TypeDBSession
from typedb.api.connection.transaction import TypeDBTransaction
from typedb.driver import TypeDB
from stixorm.module.orm.import_objects import raw_stix2_to_typeql
from stixorm.module.orm.delete_object import delete_stix_object, add_delete_layers
from stixorm.module.orm.export_object import convert_ans_to_stix
from stixorm.module.parsing.parse_objects import parse
from .authorise import authorised_mappings, import_type_factory
from .initialise import setup_database, load_schema, load_markings
import networkx as nx
from stix2 import v21
from stix2.base import _STIXBase
from stix2.datastore import (
    DataSink, DataSource, )
from stix2.datastore.filters import FilterSet

import logging

from stixorm.module.typedb_lib.handlers import handle_result
from stixorm.module.typedb_lib.logging import log_delete_instruction, log_delete_instruction_update_layer, log_delete_layers
from stixorm.module.typedb_lib.queries import delete_database, match_query, query_ids, delete_layers, build_match_id_query,\
    build_insert_query, query_id, add_instructions_to_typedb
from stixorm.module.typedb_lib.file import write_to_file
from stixorm.module.typedb_lib.instructions import Instructions, Status, AddInstruction, TypeQLObject, Result
from stixorm.module.typedb_lib.factories.import_type_factory import ImportType, ImportTypeFactory
from stixorm.module.typedb_lib.factories.auth_factory import get_auth_factory_instance
from stixorm.module.parsing.conversion_decisions import get_embedded_match, get_source_from_id

# logging.basicConfig(level=logging.INFO, format='[%(asctime)s] %(levelname)s [%(name)s:%(lineno)s] %(message)s')

logger = logging.getLogger(__name__)
logging.basicConfig(filename="typedb_log.txt",
                    filemode='a',
                    format='%(asctime)s,%(msecs)d %(name)s %(levelname)s %(message)s',
                    datefmt='%H:%M:%S',
                    level=logging.INFO)


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

        self.__initialise()



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
        handle_result(schema_result, "history schema result", self.strict_failure)
        # B. Load Stix Rules Schema
        rules_result = self.__load_stix_rules()
        handle_result(rules_result, "history stix rules result", self.strict_failure)
        # C. Load the Attack Schema
        attack_result = self.__load_attack_schema()
        handle_result(attack_result, "history attack result", self.strict_failure)
        # D. Load the OS-Threat Schema
        os_threat_result = self.__load_os_threat_schema()
        handle_result(os_threat_result, "history os threat result", self.strict_failure)

        # 3. Load the Objects
        # Still to do

    def __validate_connect_to_db(self):
        logger.debug("Attempting DB Connection")
        self.__get_core_client()
        logger.debug("DB Connection Successful")


    def __load_attack_schema(self):
        if self.clear and self.import_type.ATTACK:
            logger.debug("ATT&CK")
            load_schema(self._stix_connection, str(self.cti_schema_attack), "ATT&CK Schema")
            logger.info("we have loaded ATT&CK schema")
        else:
            logger.debug("ignoring history ATT&CK schema")


    def __load_os_threat_schema(self):
        if self.clear and self.import_type.os_threat:
            logger.debug("os-threat")
            load_schema(self._stix_connection, str(self.cti_schema_os_threat), "os-threat Schema ")
            logger.info("we have loaded os-threat schema")
        else:
            logger.debug("ignoring history  os hunt")


    def __load_stix_rules(self):
        if self.clear and self.import_type.rules:
            logger.debug("rules")
            load_schema(self._stix_connection, str(self.cti_schema_stix_rules), "Stix 2.1 Rules")
            logger.info("we have loaded Stix rules")
        else:
            logger.debug("ignoring check of stix rules")


    def __load_stix_schema(self):
        if self.clear:
            load_schema(self._stix_connection, str(self.cti_schema_stix), "Stix 2.1 Schema ")
            self.loaded = load_markings(self._stix_connection)
            logger.info("we have loaded Stix schema")
        else:
            logger.debug("ignoring history stix schema")


    def __assign_schemas(self):
        if self.schema_path is None:
             self.schema_path = str(pathlib.Path(__file__).parent)

        # If relative paths are used it will depend upon the entry point i.e. working directory will need to be same level as typedb.py
        self.cti_schema_stix = pathlib.Path(self.schema_path).joinpath("definitions/stix21/schema/cti-schema-v2.tql")
        assert os.path.isfile(self.cti_schema_stix)
        self.cti_schema_stix_rules = pathlib.Path(self.schema_path).joinpath("definitions/stix21/schema/cti-rules.tql")
        assert os.path.isfile(self.cti_schema_stix_rules)
        self.cti_schema_os_threat = pathlib.Path(self.schema_path).joinpath("definitions/os_threat/schema/cti-os-threat.tql")
        assert os.path.isfile(self.cti_schema_os_threat)
        self.cti_schema_os_hunt = pathlib.Path(self.schema_path).joinpath("definitions/os_threat/schema/cti-os-hunt.tql")
        assert os.path.isfile(self.cti_schema_os_hunt)
        self.cti_schema_attack = pathlib.Path(self.schema_path).joinpath("definitions/attack/schema/cti-attack.tql")
        assert os.path.isfile(self.cti_schema_attack)
        # if self.schema_path is None:
        #     self.schema_path = str(pathlib.Path.parent)
        #
        # self.cti_schema_path = pathlib.Path(self.schema_path).joinpath("stix/schema/cti-schema-v2.tql")
        # assert self.cti_schema_path.is_file(), "The schema does not exist: " + str(self.cti_schema_path)
        #
        # self.cti_schema_rules_path = pathlib.Path(self.schema_path).joinpath("stix/schema/cti-rules.tql")
        # assert self.cti_schema_rules_path.is_file(), "The schema does not exist: " + str(self.cti_schema_rules_path)

    def __assign_import_type(self):
        if self.import_type is None:
            self.import_type = import_type_factory.get_default_import()

    @property
    def stix_connection(self):
        return self._stix_connection

    def clear_db(self):

        result = delete_database(self.uri, self.port, self.database)
        logger.debug("Successfully cleared database")


    def __filter_markings(self, stix_ids: List[str]) -> List[str]:
        marking = ["marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",
                   "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da",
                   "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82",
                   "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed"]

        filtered_list = list(filter(lambda x: x.get_value() not in marking, stix_ids))
        return self.__string_attibute_to_string(filtered_list)

    def __string_attibute_to_string(self,
                                    string_attributes: List[str]):
        return [stix_id.get_value() for stix_id in string_attributes]

    def __query_stix_ids(self):
        get_ids_tql = 'match $ids isa stix-id; get $ids;'
        data_query = query_ids
        query_data = match_query(self.uri,
                                 self.port,
                                 self.database,
                                 get_ids_tql,
                                 data_query)

        return query_data


    def get_stix_ids(self):
        """ Get all the stix-ids in a database, should be moved to DataSource object

        Returns:
            id_list : list of the stix-ids in the database
        """
        stix_ids_query = self.__query_stix_ids()

        result = self.__filter_markings(stix_ids_query)
        return result


    def __retrieve_stix_id(self,
                           stix_id: str):
        type_db_source = self.__get_source_client()
        return type_db_source.get(stix_id)


    def __delete_instruction(self,
                             stixid: str):

        stix_obj = self.__retrieve_stix_id(stixid)

        dep_match, dep_insert, indep_ql, core_ql, dep_obj = raw_stix2_to_typeql(stix_obj, self.import_type)
        del_match, del_tql = delete_stix_object(stix_obj, dep_match, dep_insert, indep_ql, core_ql, self.import_type)
        dep_obj["delete"] = del_match + '\n' + del_tql

        log_delete_instruction(del_match, dep_insert, indep_ql, dep_obj, del_match, del_tql)
        if del_match == '' and del_tql == '':
            return None
        else:
            return dep_obj


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


    def __retrieve_delete_instructions(self,
                                       stixids: List[str]) -> Instructions:

        layers = []
        indexes = []
        missing = []

        instructions = Instructions()

        for stixid in stixids:
            del_result = self.__delete_instruction(stixid)
            layers, indexes, missing = self.__update_delete_layers(layers, indexes, missing, del_result)

        for layer in layers:
            instructions.insert_delete_instruction(layer['id'], layer)
        return instructions


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
        order_instruction_result = self.__order_delete_instructions(delete_instruction_result)
        delete_from_database_result = delete_layers(self.uri,
                                                    self.port,
                                                    self.database,
                                                    order_instruction_result)

        instructions = delete_from_database_result

        return instructions.convert_to_result()



    def __get_core_client(self) -> TypeDBDriver:
        typedb_url = self.uri + ":" + self.port
        return TypeDB.core_driver(typedb_url)


    def __get_source_client(self):
        connection = {'uri': self.uri,
                      'port': self.port,
                      'database': self.database,
                      'user': self.user,
                      'password': self.password}

        return TypeDBSource(connection, self.import_type)




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
            dep_list=dep_obj.get('dep_list', [])
        )

        return typeql_obj


    def __generate_instructions(self,
                                obj_list) -> Instructions:
        instructions = Instructions()
        for stix_dict in obj_list:
            try:
                typeql_object_result = self.__generate_typeql_object(stix_dict)

                typeql_object: TypeQLObject = typeql_object_result
                instructions.insert_add_instruction(stix_dict['id'], typeql_object)
            except Exception as e:
                logging.exception(e)
                logging.info("Error generating instructions for " + stix_dict['id'])
                instructions.insert_add_instruction(stix_dict['id'], None)
                traceback_str = traceback.format_exc()
                instructions.update_instruction_as_error(stix_dict['id'], traceback_str)


        return instructions


    def __create_instruction_dependency_graph(self,
                                              instructions: Instructions):
        directed_graph = nx.DiGraph()
        instruction: AddInstruction
        for instruction in instructions.instructions.values():
            try:
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
            except Exception as e:
                logging.error("Error creating dependency graph for " + instruction.id)
                logging.error(e)
                traceback_str = traceback.format_exc()
                instructions.update_instruction_as_error(instruction.id, traceback_str)

        return instructions



    def __generate_queries(self,
                           instructions: Instructions):
        result = instructions.create_insert_queries(build_insert_query)
        return result

    def batch_generator(self, data):
        batch_size = 500
        for i in range(0, len(data), batch_size):
            yield data[i:i + batch_size]

    def __check_missing_dependencies(self,
                                     instructions: Instructions):
        missing_ids_from_tree = instructions.missing_dependency_ids()

        result = []
        for missing_ids in self.batch_generator(missing_ids_from_tree):
            query_result = build_match_id_query(missing_ids)

            data_result = match_query(uri=self.uri,
                                      port=self.port,
                                      database=self.database,
                                      query=query_result,
                                      data_query=query_id,
                                      import_type=None)
            result = result + data_result


        missing_ids_found_in_db = result
        # ids with no record in db and in dependency tree
        ids_missing = list(set(missing_ids_from_tree) - set(missing_ids_found_in_db))
        instructions.register_missing_dependencies(ids_missing)

        return instructions



    def __reorder_instructions(self,
                               instructions: Instructions):
        try:
            order = list(nx.topological_sort(instructions.dependencies))
            instructions.add_insertion_order(order)
        except Exception as e:
            logging.exception(e)
        return instructions




    def add(self, stix_data: Optional[List[dict]] = None) -> List[Result]:
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

        generate_instructions_result = self.__generate_instructions(obj_result)
        logger.info("\n##########################################################################################################################################################\n")
        #logger.info(f"generate instructions is {generate_instructions_result}")
        instruction_dependency_graph_result =  self.__create_instruction_dependency_graph(generate_instructions_result)
        check_missing_dependency_result = self.__check_missing_dependencies(instruction_dependency_graph_result)

        instructions: Instructions = check_missing_dependency_result
        if instructions.exist_missing_dependencies():
            return instructions.convert_to_result()
        if instructions.exist_cyclical_ids():
            instructions.register_cyclical_dependencies()
            return instructions.convert_to_result()

        reorder_result = self.__reorder_instructions(instructions)

        queries_result = self.__generate_queries(reorder_result)

        add_to_database_result = add_instructions_to_typedb(self.uri,
                                                            self.port,
                                                            self.database,
                                                            reorder_result)

        instructions = add_to_database_result

        return instructions.convert_to_result()



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

    def __init__(self, connection: Dict[str, str], import_type: Optional[ImportType]=None, **kwargs):
        super(TypeDBSource, self).__init__()
        logger.debug(f'TypeDBSource: {connection}')

        assert connection["uri"] is not None
        assert connection["port"] is not None
        assert connection["database"] is not None
        assert import_type is None or isinstance(import_type, ImportType)

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


    def __retrieve_stix_object(self,
                               stix_id: str):
        logger.debug(f'__retrieve_stix_object: {stix_id}')
        obj_var, type_ql = get_embedded_match(stix_id, self.import_type)
        query = 'match ' + type_ql + "get;"
        logger.debug(f'query is {query}')

        data = match_query(uri=self.uri,
                           port=self.port,
                           database=self.database,
                           query=query,
                           data_query=convert_ans_to_stix,
                           import_type=self.import_type)

        logger.debug(f'data is -> {data}')
        stix_obj = parse(data=data, allow_custom=False, import_type=self.import_type)

        # result = write_to_file("stixorm/module/how_it_works/export_final.json", stix_obj)
        # if not is_successful(result):
        #     logging.exception("\n".join(traceback.format_exception(result.failure())))
        #     logger.error(str(result.failure()))

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
        return result

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


