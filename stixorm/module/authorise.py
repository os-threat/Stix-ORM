
import logging
from typing import List

from stixorm.module.definitions.property_definitions import get_libraries
from stixorm.module.typedb_lib.factories.definition_factory import get_definition_factory_instance, DomainDefinition
from stixorm.module.typedb_lib.factories.import_type_factory import ImportTypeFactory, ImportType
from stixorm.module.typedb_lib.factories.process_map_factory import ProcessMapFactory

logger = logging.getLogger(__name__)




##############################################################
#  1.) Default Import Type at only Stix Objects, all else False
############################################################


import_type_factory = ImportTypeFactory.get_import_type_factory()
default_import_type = import_type_factory.get_default_import()


def authorised_mappings(import_type: ImportType=default_import_type):
    auth = {}
    auth["reln_name"] = {}
    auth["reln"] = {}
    auth["tql_types"] = {}
    auth["types"] = {}
    auth["is_lists"] = {}
    definition_factory = get_definition_factory_instance()
    auth_domains: List[DomainDefinition] = definition_factory.get_definitions_for_import(import_type)


    dom= get_libraries()
    # initialise authorisation object, for documentation purposes
    auth["reln_name"]["embedded_relations"] = []
    auth["reln_name"]["standard_relations"] = []
    auth["reln_name"]["list_of_objects"] = []
    auth["reln_name"]["key_value_relations"] = []
    auth["reln_name"]["extension_relations"] = []
    auth["reln_name"]["relations_sro_roles"] = []
    auth["reln"]["embedded_relations"] = []
    auth["reln"]["standard_relations"] = []
    auth["reln"]["list_of_objects"] = []
    auth["reln"]["key_value_relations"] = []
    auth["reln"]["extension_relations"] = []
    auth["reln"]["relations_sro_roles"] = []
    auth["tql_types"]["embedded_relations"] = []
    auth["tql_types"]["standard_relations"] = []
    auth["tql_types"]["list_of_objects"] = []
    auth["tql_types"]["key_value_relations"] = []
    auth["tql_types"]["extension_relations"] = []
    auth["tql_types"]["relations_sro_roles"] = []
    auth["tql_types"]["sdo"] = []
    auth["tql_types"]["sro"] = []
    auth["tql_types"]["sco"] = []
    auth["tql_types"]["sub"] = []
    auth["tql_types"]["meta"] = []
    auth["types"]["sdo"] = []
    auth["types"]["sro"] = []
    auth["types"]["sco"] = []
    auth["types"]["sub"] = []
    auth["types"]["meta"] = []
    auth["is_lists"]["sdo"] = {}
    auth["is_lists"]["sro"] = {}
    auth["is_lists"]["sco"] = {}
    auth["is_lists"]["sub"] = {}
    auth["is_lists"]["meta"] = {}
    auth["sub_objects"] = {}
    auth["objects"] = {}
    auth["conv"] = {}
    auth["conv"]["sdo"] = []
    auth["conv"]["sro"] = []
    auth["conv"]["sco"] = []
    auth["conv"]["sub"] = []
    auth["conv"]["meta"] = []
    auth["classes"] = {}
    auth["classes"]["sdo"] = {}
    auth["classes"]["sro"] = {}
    auth["classes"]["sco"] = {}
    auth["classes"]["sub"] = {}
    auth["classes"]["meta"] = {}

    process_map_factory = ProcessMapFactory.process_map_factory()
    process_maps = process_map_factory.all_process_maps()

    for j, domain in enumerate(auth_domains):
        for process in process_maps:
            name = process.name
            keys = process.keys
            matches = process.match
            conds = process.cond
            if name == "reln_name":
                #logger.debug("----------- reln_name ------------")
                for i, key in enumerate(keys):
                    if domain.contains_mapping(matches[i]):
                        #logger.debug(f'Auth Loading: domain->{dom[j]}, name->{name}, key->{keys[i]}, match->{matches[i]}, cond->{conds[i]}')
                        value_list = [x[conds[i]] for x in domain.get_mapping(matches[i])]
                        auth[name][key].extend(value_list)
            elif name == "reln":
                #logger.debug("--------- reln--------------")
                for i, key in enumerate(keys):
                    if domain.contains_mapping(matches[i]):
                        #logger.debug(f'Auth Loading: domain->{dom[j]}, name->{name}, key->{key}, match->{matches[i]}')
                        value_list =  domain.get_mapping(matches[i])
                        auth[name][key].extend(value_list)
            elif name == "tql_types1":
                #logger.debug("--------- reln--------------")
                for i, key in enumerate(keys):
                    if domain.contains_mapping(matches[i]):
                        logger.debug(f'\nAuth Loading: domain->{dom[j]}, name->{name}, key->{key}, match->{matches[i]}')
                        value_list = [x[conds[i]] for x in domain.get_mapping(matches[i])]
                        logger.debug(f'value list -> {value_list}')
                        auth["tql_types"][key].extend(value_list)
            elif name == "tql_types":
                #logger.debug("---------- tql_types -------------")
                for i, key in enumerate(keys):
                    if domain.contains_mapping("object_conversion"):
                        #logger.debug(f'Auth Loading: domain->{dom[j]}, name->{name}, key->{keys[i]}, match->{matches[i]}, cond->{conds[i]}')
                        value_list_type = [x["type"] for x in domain.get_mapping(matches[i]) if x["object"] == conds[i]]
                        value_list_typeql = [x["typeql"] for x in domain.get_mapping(matches[i]) if x["object"] == conds[i]]
                        logger.debug(f' value_list_type -> {value_list_type}\n\n value_list_typeql -> {value_list_typeql}')
                        auth["tql_types"][key].extend(value_list_typeql)
                        auth["types"][key].extend(value_list_type)

                #auth["tql_types"]["meta"] = stix_models["mappings"]["types_meta"]
            elif name == "is_lists":
                #logger.debug("--------- is_lists --------------")
                for i, key in enumerate(keys):
                    if domain.contains_mapping(matches[i]):
                        #logger.debug(f'Auth Loading: domain->{dom[j]}, name->{name}, key->{keys[i]}, match->{matches[i]}, cond->{conds[i]}')
                        value_dict = domain.get_mapping(matches[i])
                        auth[name][key].update(value_dict)
            elif name == "direct":
                #logger.debug("-------- direct ---------------")
                for i, key in enumerate(keys):
                    if domain.does_property_contain_values(matches[i]):
                        #logger.debug(f'Auth Loading: domain->{dom[j]}, name->{name}, key->{keys[i]}, match->{matches[i]}')
                        value_dict = domain.get_property_values(matches[i])
                        auth[key].update(value_dict)
            elif name == "conv":
                #logger.debug("-------- conv ---------------")
                for i, key in enumerate(keys):
                    if domain.contains_mapping("object_conversion"):
                        #logger.debug(f'Auth Loading: domain->{dom[j]}, name->{name}, key->{keys[i]}, match->{matches[i]}, cond->{conds[i]}')
                        value_list = [x for x in domain.get_mapping("object_conversion") if x["object"] == conds[i]]
                        auth[name][key].extend(value_list)
            elif name == "classes":
                #logger.debug("-------- conv ---------------")
                for i, key in enumerate(keys):
                    if domain.does_classes_contain_values(key):
                        #logger.debug(f'Auth Loading: domain->{dom[j]}, name->{name}, key->{keys[i]}, match->{matches[i]}, cond->{conds[i]}')
                        value_dict = domain.get_classes_property_values(key)
                        auth[name][key].update(value_dict)

            else:
                pass


    # finally add the import type to the auth object
    auth.update(ImportTypeFactory.convert_to_dict(import_type))

    return auth

