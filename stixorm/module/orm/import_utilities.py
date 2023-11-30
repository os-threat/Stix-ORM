import datetime
from typing import List, Dict
import copy

import logging

from stixorm.module.parsing.conversion_decisions import get_source_from_id
from stixorm.module.typedb_lib.factories.auth_factory import get_auth_factory_instance
from stixorm.module.typedb_lib.factories.definition_factory import get_definition_factory_instance
from stixorm.module.typedb_lib.factories.import_type_factory import ImportType
from stixorm.module.typedb_lib.model.definitions import DefinitionName

stix_models = get_definition_factory_instance().lookup_definition(DefinitionName.STIX_21)
logger = logging.getLogger(__name__)


# ---------------------------------------------------
# 1.5) Sub Object Methods for adding common standard properties
#                -  e.g. stix-type, stix-id, name, description etc.
# --------------------------------------------------


def clean_props(total_props):
    """
        Future function to clean the list of properties
    Args:
        total_props []:

    Returns:
        total_props []:
    """
    # remove the properties that are mistakes

    return total_props


def add_property_to_typeql(prop, obj_tql, obj, prop_var_list):
    """
        Add a property by typeql
    Args:
        prop (): property
        obj_tql (): the tql that applies to this
        obj (): the stix object this is part of
        prop_var_list ():

    Returns:
        type_ql, the basic typeql statement for the property
        type_ql_props, the typeql statement that defines the property
        prop_var_list, a list of dicts describing the property
    """
    type_ql = type_ql_props = ''
    tql_prop_name = obj_tql[prop]
    # if property is defanged, summary or revoked, and the value is false, then don't add it to typedb_lib description
    if prop == "defanged" and obj.defanged == False:
        return type_ql, type_ql_props, prop_var_list
    elif prop == "revoked" and obj.revoked == False:
        return type_ql, type_ql_props, prop_var_list
    elif prop == "summary" and obj.summary == False:
        return type_ql, type_ql_props, prop_var_list

    # or else add the property to the typeql statement
    if isinstance(obj[prop], list):
        # if the property is a list, add each item to the typeql statement
        for i, instance in enumerate(obj[prop]):
            prop_var_dict = {}
            # import statements for each of the list items
            prop_var = '$' + prop + str(i)
            type_ql += ',\n has ' + tql_prop_name + ' ' + prop_var
            type_ql_props += '\n ' + prop_var + ' ' + val_tql(instance) + ';'
            prop_var_dict["prop_var"] = prop_var
            prop_var_dict["prop"] = prop
            prop_var_dict["index"] = i
            prop_var_list.append(prop_var_dict)
    else:
        prop_var_dict = {}
        # import statements for a single value
        prop_var = '$' + tql_prop_name
        type_ql += ',\n has ' + tql_prop_name + ' ' + prop_var
        type_ql_props += '\n ' + prop_var + ' ' + val_tql(obj[prop]) + ';'
        prop_var_dict["prop_var"] = prop_var
        prop_var_dict["prop"] = prop
        prop_var_dict["index"] = -1
        prop_var_list.append(prop_var_dict)

    return type_ql, type_ql_props, prop_var_list


# ---------------------------------------------------
# 1.6) Sub Object Methods for adding embedded structures
#                -  e.g. hasehs, kill-chain-phases, created_by, external_references, object_marking_refs etc.
# --------------------------------------------------
# Giant Switch statement to add the embedded relations to the typeql statement

def add_relation_to_typeql(rel,
                           obj,
                           obj_var,
                           prop_var_list,
                           import_type: ImportType,
                           inc,
                           protocol: str):
    """
        Top level function to add one of the sub objects to the stix object
    Args:
        rel (): the relation object to add
        obj (): the stix object to add it too
        obj_var (): the typeql variable string
        prop_var_list (): the property variable list
        import_type: the dict describing import preferences
        inc (): an incrementing variable that is used to add to the var string

    Returns:
        match: the typeql match strings
        insert: the typeql insert string
    """
    logger.debug(f'===============\n=====================\n===================\n')
    logger.debug(f'rel {rel}')
    logger.debug(f'obj[rel] {obj[rel]}')
    logger.debug(f'obj {obj}')
    logger.debug(f'obj_Var {obj_var}')
    logger.debug(f'\nprop var list {prop_var_list}')
    auth_factory = get_auth_factory_instance()
    auth = auth_factory.get_auth_for_import(import_type)
    dep_list = []
    logger.debug("\nstarting into choices")
    if rel == "granular_markings":
        logger.debug("in granular")
        match, insert = granular_markings(rel, obj[rel], obj_var, prop_var_list)

    # hashes type
    elif (rel == "hashes"
          or rel == "file_header_hashes"):
        logger.debug("in hashes")
        match, insert = hashes(rel, obj[rel], obj_var)

    # insert key value store
    elif rel in auth["reln_name"]["key_value_relations"]:
        logger.debug("in key value")
        match, insert = key_value_store(rel, obj[rel], obj_var, import_type)

    # insert list of object relation
    elif rel in auth["reln_name"]["list_of_objects"]:
        logger.debug("list of objects")
        match, insert, dep_list = list_of_object(rel, obj[rel], obj_var, inc, import_type, protocol)

    # insert embedded relations based on stix-id
    elif rel in auth["reln_name"]["embedded_relations"]:
        logger.debug("embedded")
        match, insert, dep_list = embedded_relation(rel, obj[rel], obj_var, inc, import_type, protocol)

    # insert plain sub-object with relation
    elif (rel == "x509_v3_extensions"
          or rel == "optional_header"):
        logger.debug("X509")
        match, insert, dep_list = load_object(rel, obj[rel], obj_var, inc, import_type, protocol)

    # insert  SCO Extensions here, a possible dict of sub-objects
    elif rel in auth["reln_name"]["extension_relations"] or rel == "extensions":
        logger.debug("extension")
        match, insert, dep_list = extensions(rel, obj[rel], obj_var, inc, import_type, protocol)

    # ignore the following relations as they are already processed, for Relationships, Sightings and Extensions
    elif rel in auth["reln_name"]["standard_relations"] or rel == "definition" or "definition_type":
        logger.debug("standard")
        match = insert = ''

    else:
        logger.debug(f'relation type not known, ignore if "source_ref" or "target_ref" -> {rel}')
        logger.debug("in else")
        match = insert = ""

    return match, insert, dep_list


# ---------------------------------------------------
# Methods for adding the embedded structures to the typeql statement
# --------------------------------------------------
# generic methods


def extensions(prop_name: str,
               prop_dict,
               parent_var,
               inc,
               import_type: ImportType,
               protocol: str):
    """
        Create the Typeql for the extensions sub object
    Args:
        prop_name (): the name of the extension
        prop_dict (): the dict for the extension
        parent_var (): the var of the Stix object that is the owner
        import_type: the dict describing import preferences

    Returns:
        match: the typeql match string
        insert: the typeql insert string
    """
    auth_factory = get_auth_factory_instance()
    auth = auth_factory.get_auth_for_import(import_type)
    match = insert = ''
    dep_list = []
    # for each key in the dict (extension type)
    # logger.debug('--------------------- extensions ----------------------------')
    for num, ext_type in enumerate(prop_dict):
        for ext_type_ql in auth["reln"]["extension_relations"]:
            if ext_type == ext_type_ql["stix"]:
                match2, insert2, dep_list2 = load_object(ext_type, prop_dict[ext_type], parent_var, num, import_type, protocol)
                match = match + match2
                insert = insert + insert2
                dep_list = dep_list + dep_list2
                break

    return match, insert, dep_list


def load_object(prop_name: str,
                prop_dict,
                parent_var: str,
                inc,
                import_type: ImportType,
                protocol: str):
    """
        Create the Typeql for a sub object
    Args:
        prop_name (): the name of the extension
        prop_dict (): the dict for the extension
        parent_var (): the var of the Stix object that is the owner
        import_type: the dict describing import preferences

    Returns:
        match: the typeql match string
        insert: the typeql insert string
    """
    auth_factory = get_auth_factory_instance()
    auth = auth_factory.get_auth_for_import(import_type)
    match = insert = type_ql = type_ql_props = ''
    # as long as it is predefined, history the object
    # logger.debug('------------------- history object ------------------------------')
    for prop_type in auth["reln"]["extension_relations"]:
        if prop_name == prop_type["stix"]:
            #tot_prop_list = [tot for tot in prop_dict.keys()]
            obj_type = prop_type["object"]
            obj_tql = copy.deepcopy(auth["sub_objects"][obj_type])
            obj_var = '$' + obj_type
            reln = prop_type["relation"]
            rel_var = '$' + reln + str(inc)
            rel_owner = prop_type["owner"]
            rel_pointed_to = prop_type["pointed-to"]
            type_ql += ' ' + obj_var + ' isa ' + obj_type
            # Split them into properties and relations
            total_props = prop_dict._inner
            logger.debug(f'load object properties: {total_props}')
            properties, relations = split_on_activity_type(total_props, obj_tql)
            prop_var_list = []
            dep_list = []
            logger.debug(f'load object relations: {relations}')
            for prop in properties:
                # split off for properties processing
                type_ql2, type_ql_props2, prop_var_list = add_property_to_typeql(prop, obj_tql, prop_dict,
                                                                                 prop_var_list)
                # then add them all together
                type_ql += type_ql2
                type_ql_props += type_ql_props2
                # add a terminator on the end of the insert statement
            type_ql += ";\n" + type_ql_props + "\n\n"

            # add each of the relations to the match and insert statements
            logger.debug(f'load object relations: {relations}')
            for rel in relations:
                # split off for relation processing
                logger.debug(f'load object relation: {rel}, protocol: {protocol}')
                match2, insert2, dep_list2 = add_relation_to_typeql(rel, prop_dict, obj_var, prop_var_list, import_type, inc, protocol)
                # then add it back together    
                match = match + match2
                insert = insert + "\n" + insert2
                dep_list = dep_list + dep_list2

            # finally, connect the local object to the parent object
            type_ql += ' ' + rel_var + ' (' + rel_owner + ':' + parent_var
            type_ql += ', ' + rel_pointed_to + ':' + obj_var + ')'
            type_ql += ' isa ' + reln + ';\n'
            break

    insert = type_ql + "\n" + insert
    return match, insert, dep_list


def list_of_object(prop_name: str,
                   prop_value_list: List[str],
                   parent_var,
                   inc,
                   import_type: ImportType,
                   protocol: str):
    """
        Create the Typeql for the list of object sub object
    Args:
        prop_name (): the name of the object
        prop_value_list (): the list of object
        parent_var (): the var of the Stix object that is the owner
        import_type: the dict describing import preferences

    Returns:
        match: the typeql match string
        insert: the typeql insert string
    """
    auth_factory = get_auth_factory_instance()
    auth = auth_factory.get_auth_for_import(import_type)
    for config in auth["reln"]["list_of_objects"]:
        if config["name"] == prop_name:
            rel_typeql = config["typeql"]
            role_owner = config["owner"]
            role_pointed = config["pointed_to"]
            typeql_obj = config["object"]
            break

    if typeql_obj in auth["sub_objects"]:
        obj_props_tql = copy.deepcopy(auth["sub_objects"][typeql_obj])
    else:
        raise ValueError("no sub-object available")

    lod_list = []
    dep_list = []
    match = rel_insert = rel_match = insert = ''
    for i, dict_instance in enumerate(prop_value_list):
        lod_var = '$' + typeql_obj + str(i)
        lod_list.append(lod_var)
        insert += lod_var + ' isa ' + typeql_obj
        for key in dict_instance:
            typeql_prop = obj_props_tql[key]
            if typeql_prop == '':
                rel_match2, rel_insert2, dep_list2 = add_relation_to_typeql(key, dict_instance, lod_var, [], import_type, i, protocol)
                rel_insert += rel_insert2
                rel_match += rel_match2
                dep_list = dep_list + dep_list2
            else:
                insert += ',\n has ' + typeql_prop + ' ' + val_tql(dict_instance[key])
        insert += ';\n'

    insert += '\n $' + rel_typeql + ' (' + role_owner + ':' + parent_var
    for lod_var in lod_list:
        insert += ', ' + role_pointed + ':' + lod_var

    insert += ') isa ' + rel_typeql + ';\n' + rel_insert
    match += rel_match
    return match, insert, dep_list


def key_value_store(prop,
                    prop_value_dict,
                    obj_var,
                    import_type: ImportType):
    """
        Create the Typeql for the key-value store sub object
    Args:
        prop (): the name of the object
        prop_value_dict (): the dict of object
        obj_var (): the var of the Stix object that is the owner
        import_type: the dict describing import preferences

    Returns:
        match: the typeql match string
        insert: the typeql insert string
    """
    auth_factory = get_auth_factory_instance()
    auth = auth_factory.get_auth_for_import(import_type)
    for config in auth["reln"]["key_value_relations"]:
        if config["name"] == prop:
            rel_typeql = config["typeql"]
            role_owner = config["owner"]
            role_pointed = config["pointed_to"]
            d_key = config["key"]
            d_value = config["value"]
            break

    match = ''
    insert = '\n'
    field_var_list = []
    for i, key in enumerate(prop_value_dict):
        a_value = prop_value_dict[key]
        key_var = ' $' + d_key + str(i)
        field_var_list.append(key_var)
        insert += key_var + ' isa ' + d_key + '; ' + key_var + ' "' + key + '";\n'
        if isinstance(a_value, list):
            for j, n in enumerate(a_value):
                value_var = ' $' + d_value + str(j)
                insert += key_var + ' ' + 'has ' + d_value + ' "' + str(n) + '";\n'
        else:
            value_var = ' $' + d_value + str(i)
            insert += key_var + ' ' + 'has ' + d_value + ' "' + str(a_value) + '";\n'

    insert += ' $' + rel_typeql + ' (' + role_owner + ':' + obj_var
    for var in field_var_list:
        insert += ', ' + role_pointed + ':' + var
    insert += ') isa ' + rel_typeql + ';\n\n'
    return match, insert


# specific methods
def hashes(prop_name, prop_dict, parent_var):
    """
        Create the Typeql for the hashes sub object
    Args:
        prop_name (): the name of the object
        prop_dict (): the dict of object
        parent_var (): the var of the Stix object that is the owner

    Returns:
        match: the typeql match string
        insert: the typeql insert string
    """
    match = insert = ''
    hash_var_list = []
    for i, key in enumerate(prop_dict):
        hash_var = '$hash' + str(i)
        hash_var_list.append(hash_var)
        if key in stix_models.get_sub_objects("hash_typeql_dict"):
            insert += ' ' + hash_var + ' isa ' + stix_models.get_sub_objects("hash_typeql_dict")[
                key] + ', has hash-value ' + val_tql(prop_dict[key]) + ';\n'
        else:
            logger.error(f'Unknown hash type {key}')

    # insert the hash objects into the hashes relation with the parent object
    insert += '\n $hash_rel (hash-owner:' + parent_var
    for hash_var in hash_var_list:
        insert += ', hash-actual:' + hash_var

    insert += ') isa hashes;\n'
    return match, insert


def granular_markings(prop_name, prop_value_List, parent_var, prop_var_list):
    """
        Create the Typeql for the granular markings sub object
    Args:
        prop_name (): the name of the object
        prop_value_List (): the list of object values
        parent_var (): the var of the Stix object that is the owner
        prop_var_list: the list of property variables

    Returns:
        match: the typeql match string
        insert: the typeql insert string
    """
    match = insert = ''
    for i, prop_dict in enumerate(prop_value_List):
        # setup and match in the marking, based on its id
        m_id = prop_dict['marking_ref']
        m_var = '$marking' + str(i)
        g_var = '$granular' + str(i)
        match += ' ' + m_var + ' isa marking-definition, has stix-id ' + '"' + m_id + '";\n'
        insert += ' ' + g_var + ' (marking:' + m_var + ', object:' + parent_var
        prop_list = prop_dict['selectors']
        for selector in prop_list:
            selector_var = get_selector_var(selector, prop_var_list)
            insert += ', marked:' + selector_var

        insert += ') isa granular-marking;\n'

    return match, insert


def get_selector_var(selector, prop_var_list):
    """
        Get the typeql variable for the property
    Args:
        selector (): the property to select
        prop_var_list (): the variable list to select from

    Returns:
        selector_var: the typeql variable for the property
    """
    if selector[-1] == ']':
        text = selector.split(".")
        selector = text[0]
        index = int(text[1][1])
    else:
        selector = selector
        index = -1

    # logger.debug(f'selector after processing -> {selector}, index after procesing -> {index}')
    for prop_var_dict in prop_var_list:
        if selector == prop_var_dict['prop'] and index == prop_var_dict['index']:
            selector_var = prop_var_dict['prop_var']
            break

    return selector_var


# ---------------------------------------------------
#        EMBEDDED RELATION METHODS
# ---------------------------------------------------
# object_refs
# sample_refs
# sample_ref
# host_vm_ref
# operating_system_ref
# installed_software_refs
# analysis_sco_refs
# etc.

def embedded_relation(prop,
                      prop_value,
                      obj_var,
                      inc: int,
                      import_type: ImportType,
                      protocol: str):
    """
        Create the Typeql for the embedded relation sub object
    Args:
        prop (): the name of the object
        prop_value (): the value of object
        obj_var (): the var of the Stix object that is the owner

    Returns:
        match: the typeql match string
        insert: the typeql insert string
    """
    logger.debug("I'm in embedded")
    auth_factory = get_auth_factory_instance()
    auth = auth_factory.get_auth_for_import(import_type)
    for ex in auth["reln"]["embedded_relations"]:
        if ex["rel"] == prop:
            owner = ex["owner"]
            pointed_to = ex["pointed-to"]
            relation = ex["typeql"]
            break

    prop_var_list = []
    dep_list = []
    match = ''
    if inc == -1:
        inc_add = ''
    else:
        inc_add = str(inc)
    # if the prop_value is a list, then match in each item
    logger.debug(f'\n1\n')
    if isinstance(prop_value, list):
        dep_list = prop_value
        logger.debug(f'deplist {dep_list}')
        for i, prop_v in enumerate(prop_value):
            prop_type = get_source_from_id(prop_v, import_type, protocol)
            if prop_type == 'relationship':
                prop_type = 'stix-core-relationship'
            prop_var = '$' + prop_type + str(i) + inc_add
            prop_var_list.append(prop_var)
            match += ' ' + prop_var + ' isa ' + prop_type + ', has stix-id ' + '"' + prop_v + '";\n'
    # else, match in the single prop_value
    else:
        dep_list.append(prop_value)
        prop_type = get_source_from_id(prop_value, import_type, protocol)
        logger.debug(f'deplist {dep_list}')
        if prop_type == 'relationship':
            prop_type = 'stix-core-relationship'
        if prop_type == 'attack-identity':
            prop_type = 'identity'
        prop_var = '$' + prop_type + inc_add
        prop_var_list.append(prop_var)
        match += ' ' + prop_var + ' isa ' + prop_type + ', has stix-id ' + '"' + prop_value + '";\n'

    # Then setup and insert the relation
    logger.debug(f'\n2\n')
    insert = '\n $' + relation + inc_add + ' (' + owner + ':' + obj_var
    for prop_var in prop_var_list:
        insert += ', ' + pointed_to + ':' + prop_var
    insert += ') isa ' + relation + ';\n'
    return match, insert, dep_list


# ---------------------------------------------------
# 1.7) Helper Methods for 
#           - converting a Python value --> typeql string
#           - splitting a list of total properties into properties and relations
# ---------------------------------------------------


def val_tql(val):
    """
        Modify the value used in a typeql statement, depending on its type
    Args:
        val (): the value being used

    Returns:
        val: the value formatted for typeql
    """
    if isinstance(val, str):
        replaced_val = val.replace('"', "'")
        replaced_val2 = replaced_val.replace('\\', '\\\\')
        return '"' + replaced_val2 + '"'
    elif isinstance(val, bool):
        return str(val).lower()
    elif isinstance(val, int):
        return str(val)
    elif isinstance(val, float):
        return str(val)
    elif isinstance(val, datetime.datetime):
        return str(val.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3])
    else:
        return logger.error(f'value  not supported: {val}')


def split_on_activity_type(total_props: dict, obj_tql: Dict[str, str]) -> [List[str], List[str]]:
    """
        Split the Stix object properties into flat properties and sub objects
    Args:
        total_props (): the total properties for this object
        obj_tql (): the mapping dict for this object

    Returns:
        prop_list, a list of the flat properties
        rel_list, a list of the sub objects
    """
    prop_list = []
    rel_list = []
    logger.debug("@@@@@@@@@@@@@@@@@@@@@@ splitting @@@@@@@@@@@@@@@")
    logger.debug("========================================")
    logger.debug(f'total props: {total_props}')
    # for k, v in total_props.items():
    #     logger.debug(k, v)
    # logger.debug("=========================================")
    logger.debug("========================================")
    logger.debug(f'obj tql: {obj_tql}')
    # for k, v in obj_tql.items():
    #     logger.debug(k, v)
    # logger.debug("=========================================")
    logger.debug("@@@@@@@@@@@@@@@@@@@@@@ end splitting @@@@@@@@@@@@@@@")
    for prop in total_props:
        tql_prop_name = obj_tql[prop]
        logger.debug(f'prop {prop}, object tql -> {tql_prop_name}')

        if tql_prop_name == "":
            rel_list.append(prop)
            # logger.debug(f'Im a rel --> {prop},        tql --> {tql_prop_name}')
        else:
            prop_list.append(prop)
            # logger.debug(f'Im a prop --> {prop},        tql --> {tql_prop_name}')

    return prop_list, rel_list

###################################################################################################
