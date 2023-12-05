import copy
from typing import Dict

from stixorm.module.authorise import authorised_mappings, default_import_type
from stixorm.module.parsing.conversion_decisions import sdo_type_to_tql, sro_type_to_tql, sco__type_to_tql, \
    meta_type_to_tql, get_embedded_match

from stixorm.module.orm.import_utilities import clean_props, split_on_activity_type, \
    add_property_to_typeql, add_relation_to_typeql, val_tql

import logging

from stixorm.module.typedb_lib.factories.auth_factory import get_auth_factory_instance
logger = logging.getLogger(__name__)



marking =["marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",
          "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da",
          "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82",
          "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed"]

# ---------------------------------------------------
# 1.0) Helper method to direct the right typeql method to an incoming Stix object
# ---------------------------------------------------


def stix2_to_typeql(stix_object, import_type=default_import_type):
    """
    Initial function to convert Stix into typeql, it adds together the match and insert statements

    Args:
        stix_object (): valid Stix2 object
        import_type (): string, either Stix2 or ATT&CK

    Returns:
        typeql: a string of typeql to match and insert the object int typedb_lib

    """
    match, insert, dep_obj = stix2_to_match_insert(stix_object, import_type)
    typeql = match + insert

    return typeql, dep_obj


def stix2_to_match_insert(stix_object, import_type=default_import_type):
    """
    Initial function to convert Stix into match/insert statments

    Args:
        stix_object (): valid Stix2 object
        import_type (): string, either Stix2 or ATT&CK

    Returns:
        match: a typeql match statement for this object
        insert: a typeql insert statement for this object

    """
    dep_match, dep_insert, indep_ql, core_ql, dep_obj = raw_stix2_to_typeql(stix_object, import_type)
    if dep_match == '':
        match = ''
    else:
        match = 'match ' + dep_match
    if indep_ql == '' and dep_insert == '':
        insert = ''
    else:
        insert = 'insert ' + indep_ql + dep_insert

    return match, insert, dep_obj


def raw_stix2_to_typeql(stix_object,
                        import_type=None) -> [str, str, str, str, {}]:
    """
    Initial function to convert Stix into typeql, it splits the incoming object into different
    channels based on its object type: sdo, sro, sco or meta

    Args:
        stix_object (): valid Stix2 object
        import_type (): string, either Stix2 or ATT&CK

    Returns:
        dep_match: a typeql match statement that depends on other objects
        dep_insert: a typeql insert statement that depends on other objects
        indep_ql: a typeql insert statement with no extenral dependencies
        core_ql: a typeql insert statement that describes the object head, so the independent and dependent parts can be injected seaparately

    """
    if import_type is None:
        import_type = default_import_type

    auth_factory = get_auth_factory_instance()
    auth = auth_factory.get_auth_for_import(import_type)
    logger.debug(f'stix object type {stix_object["type"]}\n')

    auth_types = copy.deepcopy(auth["types"])
    if stix_object.type in auth_types["sdo"]:
        logger.debug(f' going into sdo ---? {stix_object}')
        dep_match, dep_insert, indep_ql, core_ql, dep_obj = sdo_to_typeql(stix_object, import_type)
    elif stix_object.type in auth_types["sro"]:
        logger.debug(f' going into sro ---> {stix_object}')
        dep_match, dep_insert, indep_ql, core_ql, dep_obj = sro_to_typeql(stix_object, import_type)
    elif stix_object.type in auth_types["sco"]:
        logger.debug(f' going into sco ---> {stix_object}')
        dep_match, dep_insert, indep_ql, core_ql, dep_obj = sco_to_typeql(stix_object, import_type)
    elif stix_object.type == 'marking-definition':
        dep_match, dep_insert, indep_ql, core_ql, dep_obj = marking_definition_to_typeql(stix_object, import_type)
    else:
        logger.error(f'object type not supported: {stix_object.type}, import type {import_type}')
        dep_match, dep_insert, indep_ql, core_ql, dep_obj = '', '', '', '', ''
        dep_list = []

    return dep_match, dep_insert, indep_ql, core_ql, dep_obj


# -------------------------------------------------------------
# 1.1) SDO Object Method to convert a Python object --> typeql string
#                 -   
# -------------------------------------------------------------
def sdo_to_data(sdo, import_type=default_import_type) -> [dict, Dict[str, str], str]:
    """ convert Stix object into a data model for processing

    Args:
        sdo (): the Stix2 SDO object
        import_type (): the type of import to use

    Returns:
        total_props, : a list of all properties
        obj_tql : the dict of the tql properties

    """
    sdo_tql_name = sdo.type
    # - list of property names that have values
    total_props = sdo._inner
    total_props = clean_props(total_props)
    # 1.B) get the specific typeql names for an object into a dictionary
    # b. Instance details
    attack_object = False if not sdo.get("x_mitre_version", False) else True
    step_type = ""
    if sdo.type == "sequence":
        step_type = sdo.get("step_type", "sequence")
    sub_technique = False
    if attack_object:
        sub_technique = False if not sdo.get("x_mitre_is_subtechnique", False) else True

    obj_tql, sdo_tql_name, is_list, protocol = sdo_type_to_tql(sdo_tql_name, import_type, attack_object, sub_technique, step_type)
    logger.debug(f'\nobject tql {obj_tql}, \nsdo tql name {sdo_tql_name},\n is_list {is_list}')

    return total_props, obj_tql, sdo_tql_name, protocol


def sdo_to_typeql(sdo, import_type=default_import_type) -> [str, str, str, str, dict]:
    """
    Initial function to convert Stix2 SDO object into typeql

    Args:
        sdo (): valid Stix2 object
        import_type (): string, either Stix2 or ATT&CK

    Returns:
        dep_match: a typeql match statement that depends on other objects
        dep_insert: a typeql insert statement that depends on other objects
        indep_ql: a typeql insert statement with no extenral dependencies
        core_ql: a typeql insert statement that describes the object head, so the independent and dependent parts can be injected seaparately

    """
    # 1.A) get configuration parameters
    # - variable for use in typeql statements
    dep_list = []
    # 1.B) get the data model
    total_props, obj_tql, sdo_tql_name, protocol = sdo_to_data(sdo, import_type)
    logger.debug("\n Step 0 I've just gotten through getting data")
    logger.debug(f'\n\n total_props {total_props}\n\nobj_tql {obj_tql}\n\nsdo_tql_name {sdo_tql_name}')
    sdo_var = '$' + sdo_tql_name
    if obj_tql == '':
        return '', '', '', '', {}
    properties, relations = split_on_activity_type(total_props, obj_tql)
    logger.debug("\n----> Step 1 sdo to typeql")

    # 2.) setup the typeql statement for the sdo entity
    sdo_var = '$' + sdo_tql_name
    indep_ql = sdo_var + ' isa ' + sdo_tql_name
    core_ql = sdo_var + ' isa ' + sdo_tql_name + ', has stix-id $stix-id;\n$stix-id ' + val_tql(sdo.id) + ';\n'
    indep_ql_props = dep_match = dep_insert = ''
    logger.debug("----> Step 2 sdo to typeql")
    # 3.) add each of the properties and values of the properties to the typeql statement
    prop_var_list = []
    for prop in properties:
        # split off for properties processing
        indep_ql2, indep_ql_props2, prop_var_list = add_property_to_typeql(prop, obj_tql, sdo, prop_var_list)
        # then add them all together
        indep_ql += indep_ql2
        indep_ql_props += indep_ql_props2
        # add a terminator on the end of the query statement
    indep_ql += ";\n" + indep_ql_props + "\n\n"
    logger.debug("----> Step 3 sdo to typeql")

    # 4.) add each of the relations to the match and insert statements
    for j, rel in enumerate(relations):
        # split off for relation processing
        dep_match2, dep_insert2, dep_list2 = add_relation_to_typeql(rel, sdo, sdo_var, prop_var_list, import_type, j, protocol)
        # then add it back together
        dep_match = dep_match + dep_match2
        dep_insert = dep_insert + dep_insert2
        dep_list = dep_list + dep_list2

    logger.debug("----> Step 4 sdo to typeql")
    dep_obj = {"id": sdo.id, "dep_list": dep_list, "type": sdo.type}
    return dep_match, dep_insert, indep_ql, core_ql, dep_obj


# -------------------------------------------------------
# 1.2) SRO Object Method to convert a Python object --> typeql string
#                 -   
# -----------------------------------------------------
def sro_to_data(sro, import_type=default_import_type) -> [dict, Dict[str, str], str]:
    """ convert Stix object into a data model for processing

        Args:
            sro (): the Stix2 sco object
            import_type (): the type of import to use

        Returns:
            total_props, : a list of all properties
            obj_tql : the dict of the twl proeprties

    """
    # - list of property names that have values, and do not include False values
    total_props = sro._inner
    total_props = clean_props(total_props)

    logger.debug(f'into sro -> {sro}')
    # - work out the type of object
    uses_relation = False
    is_procedure = False
    attack_object = False if not sro.get("x_mitre_version", False) else True
    if attack_object:
        uses_relation = False if not sro.get("relationship_type", False) == "uses" else True
        if sro.get("target_ref", False):
            target = sro.get("target_ref", False)
            is_procedure = False if not target.split('--')[0] == "attack-pattern" else True
    obj_tql = {}
    sro_tql_name = sro.type
    sro_sub_rel = "" if not sro.get("relationship_type", False) else sro["relationship_type"]

    obj_tql, sro_tql_name, is_list, protocol = sro_type_to_tql(sro_tql_name, sro_sub_rel, import_type, attack_object, uses_relation, is_procedure)
    logger.debug(f'object tql {obj_tql}, sro tql name {sro_tql_name}')

    return total_props, obj_tql, sro_tql_name, protocol


def sro_to_typeql(sro, import_type=default_import_type) -> [str, str, str, str, dict]:
    """
    Initial function to convert Stix2 SRO object into typeql

    Args:
        sro (): valid Stix2 object
        import_type (): string, either Stix2 or ATT&CK

    Returns:
        dep_match: a typeql match statement that depends on other objects
        dep_insert: a typeql insert statement that depends on other objects
        indep_ql: a typeql insert statement with no extenral dependencies
        core_ql: a typeql insert statement that describes the object head, so the independent and dependent parts can be injected seaparately

    """
    auth_factory = get_auth_factory_instance()
    auth = auth_factory.get_auth_for_import(import_type)
    # 1.) get configuration parameters
    # - variable for use in typeql statements
    dep_list = []
    # - work out the type of object
    obj_type = sro.type
    total_props, obj_tql, sro_tql_name, protocol = sro_to_data(sro, import_type)
    sro_var = '$' + sro_tql_name
    if obj_tql == '':
        return '', '', '', '', {}
    # initialise the typeql insert statement
    dep_match = dep_insert = indep_ql = core_ql = dep_insert_props = ''

    # 2.) setup the match statements first, depending on whether the object is a sighting or a relationship
    # A. If it is a Relationship then find the source and target roles for the relation, and match them in
    if obj_type == 'relationship':
        source_id = sro.source_ref
        dep_list.append(source_id)
        source_var, source_match = get_embedded_match(source_id, import_type, 0, protocol)
        target_id = sro.target_ref
        dep_list.append(target_id)
        target_var, target_match = get_embedded_match(target_id, import_type, 1, protocol)
        dep_match += source_match + target_match
        # 3.)  then setup the typeql statement to insert the specific sro relation, from the dict, with the matches
        for record in auth["reln"]["standard_relations"]:
            if record['stix'] == sro_tql_name:
                dep_insert += '\n' + sro_var
                dep_insert += ' (' + record['source'] + ':' + source_var
                dep_insert += ', ' + record['target'] + ':' + target_var + ')'
                dep_insert += ' isa ' + record['typeql']
                core_ql = sro_var + ' isa ' + sro_tql_name
                core_ql += ', has stix-id $stix-id;\n$stix-id ' + val_tql(sro.id) + ';\n'
                break
                # B. If it is a Sighting then match the object to the sighting
        logger.debug(f'dep_insert -> {dep_insert}')
    elif obj_type == 'sighting':
        sighting_of_id = sro.sighting_of_ref
        dep_list.append(sighting_of_id)
        sighting_of_var, sighting_of_match = get_embedded_match(sighting_of_id, import_type, 0, protocol)
        dep_match += ' \n' + sighting_of_match
        dep_insert += '\n' + sro_var + ' (sighting-of:' + sighting_of_var
        # if there is observed data list, then add it to the match statement
        observed_data_list = sro.get("observed_data_refs")
        if (observed_data_list is not None) and (len(observed_data_list) > 0):
            for i, observed_data_id in enumerate(observed_data_list):
                dep_list.append(observed_data_id)
                observed_data_var, observed_data_match = get_embedded_match(observed_data_id, import_type, i, protocol)
                dep_match += observed_data_match
                dep_insert += ', observed:' + observed_data_var
        # if there is a list of who and where the sighting's occured, then match it in
        where_sighted_list = sro.get("where_sighted_refs")
        if (where_sighted_list is not None) and (len(where_sighted_list) > 0):
            for where_sighted_id in where_sighted_list:
                dep_list.append(where_sighted_id)
                where_sighted_var, where_sighted_match = get_embedded_match(where_sighted_id, import_type, 1, protocol)
                dep_match += where_sighted_match
                dep_insert += ', where-sighted:' + where_sighted_var

        # then finalise the typeql statement for the sro sighting
        dep_insert += ') isa sighting'
        core_ql = sro_var + ' ($role:$any) isa sighting'
        core_ql += ', has stix-id $stix-id;\n$stix-id ' + val_tql(sro.id) + ';\n'
    else:
        logger.error(f'relationship type {obj_type} not supported')
        return ''

    # 4.) next, split total properties into actual properties and nested structures (Relations)
    properties, relations = split_on_activity_type(total_props, obj_tql)

    # 5.) add each of the properties and values of the properties to the typeql statement
    prop_var_list = []
    for prop in properties:
        # split off for properties processing
        dep_insert2, dep_insert_props2, prop_var_list = add_property_to_typeql(prop, obj_tql, sro, prop_var_list)
        # then add them all together
        dep_insert += dep_insert2
        dep_insert_props += dep_insert_props2
        # add a terminator on the end of the query statement
    dep_insert += ";\n" + dep_insert_props + "\n\n"

    # 6.) add each of the relations to the match and insert statements
    for j, rel in enumerate(relations):
        # split off for relation processing
        dep_match2, dep_insert2, dep_list2 = add_relation_to_typeql(rel,
                                                                    sro,
                                                                    sro_var,
                                                                    prop_var_list,
                                                                    import_type,
                                                                    j,
                                                                    protocol)
        # then add it back together
        dep_match = dep_match + dep_match2
        dep_insert = dep_insert + dep_insert2
        dep_list = dep_list + dep_list2

    dep_obj = {"id": sro.id, "dep_list": dep_list, "type": "relation"}
    return dep_match, dep_insert, indep_ql, core_ql, dep_obj


# ---------------------------------------------------
# 1.3) SCO Object Method to convert a Python object --> typeql string
#                 -
# --------------------------------------------------
def sco_to_data(sco, import_type=default_import_type) -> [dict, dict, str]:
    """ convert Stix object into a data model for processing

        Args:
            sco (): the Stix2 sco object
            import_type (): the type of import to use

        Returns:
            total_props, : a list of all properties
            obj_tql : the dict of the twl proeprties

    """
    # - list of property names that have values
    total_props = sco._inner
    total_props = clean_props(total_props)
    # logger.debug(properties)
    # - work out the type of object
    sco_tql_name = sco.type
    # - get the object-specific typeql names, sighting or relationship
    obj_tql, sco_tql_name, is_list, protocol = sco__type_to_tql(sco_tql_name, import_type)

    return total_props, obj_tql, sco_tql_name, protocol


def sco_to_typeql(sco, import_type=default_import_type):
    """
    Initial function to convert Stix2 SCO object into typeql

    Args:
        sco (): valid Stix2 object
        import_type (): string, either Stix2 or ATT&CK

    Returns:
        dep_match: a typeql match statement that depends on other objects
        dep_insert: a typeql insert statement that depends on other objects
        indep_ql: a typeql insert statement with no extenral dependencies
        core_ql: a typeql insert statement that describes the object head, so the independent and dependent parts can be injected seaparately

    """
    # 1.) get configuration parameters
    # - variable for use in typeql statements
    sco_var = '$' + sco.type
    dep_list = []
    # initialise the typeql insert statement
    dep_match = dep_insert = indep_ql = core_ql = dep_insert_props = ''

    # 1.C) Split them into properties and relations
    total_props, obj_tql, sco_tql_name, protocol = sco_to_data(sco, import_type)
    properties, relations = split_on_activity_type(total_props, obj_tql)

    # 2.) setup the typeql statement for the sco entity
    dep_insert = sco_var + ' isa ' + sco.type
    core_ql = sco_var + ' isa ' + sco.type + ', has stix-id $stix-id;\n$stix-id ' + val_tql(sco.id) + ';\n'

    # 3.) add each of the properties and values of the properties to the typeql statement
    # 5.) add each of the properties and values of the properties to the typeql statement
    prop_var_list = []
    for prop in properties:
        # split off for properties processing
        dep_insert2, dep_insert_props2, prop_var_list = add_property_to_typeql(prop, obj_tql, sco, prop_var_list)
        # then add them all together
        dep_insert += dep_insert2
        dep_insert_props += dep_insert_props2
        # add a terminator on the end of the insert statement
    dep_insert += ";\n" + dep_insert_props + "\n\n"

    # 6.) add each of the relations to the match and insert statements
    for j, rel in enumerate(relations):
        # split off for relation processing
        dep_match2, dep_insert2, dep_list2 = add_relation_to_typeql(rel, sco, sco_var, prop_var_list, import_type, j, protocol)
        # then add it back together
        dep_match = dep_match + dep_match2
        dep_insert = dep_insert + dep_insert2
        dep_list = dep_list + dep_list2

    dep_obj = {"id": sco.id, "dep_list": dep_list, "type": sco.type}
    return dep_match, dep_insert, indep_ql, core_ql, dep_obj


# ---------------------------------------------------
# 1.4) Meta Object Method to convert a Python object --> typeql string
#                 -  marking definitions, statement, colour and Mitre copyright
# --------------------------------------------------


def marking_definition_to_typeql(meta, import_type=default_import_type):
    """
    Initial function to convert Stix2 marking object into typeql

    Args:
        meta (): valid Stix2 object
        import_type (): string, either Stix2 or ATT&CK

    Returns:
        dep_match: a typeql match statement that depends on other objects
        dep_insert: a typeql insert statement that depends on other objects
        indep_ql: a typeql insert statement with no extenral dependencies
        core_ql: a typeql insert statement that describes the object head, so the independent and dependent parts can be injected seaparately

    """
    total_props = meta._inner
    total_props = clean_props(total_props)
    dep_list = []
    statement = {}
    dep_match = dep_insert = indep_ql = core_ql = ''
    # 1.A) if one of the existing colours, return an empty string
    if meta.id in marking:
        return dep_match, dep_insert, indep_ql, core_ql, {}
    # 1.B) Test for attack object and handle statement if a statement marking
    attack_object = False if not meta.get("x_mitre_attack_spec_version", False) else True
    if total_props.get("definition", False):
        statement = total_props["definition"]
        total_props.update(statement)

    obj_tql, meta_tql_name, is_list, protocol = meta_type_to_tql(meta.type, import_type, attack_object)

    properties, relations = split_on_activity_type(total_props, obj_tql)

    # 2.) setup the typeql statement for the sdo entity
    meta_var = '$' + meta_tql_name
    indep_ql = meta_var + ' isa ' + meta_tql_name
    core_ql = meta_var + ' isa ' + meta_tql_name + ', has stix-id $stix-id;\n$stix-id ' + val_tql(meta.id) + ';\n'
    indep_ql_props = dep_match = dep_insert = ''
    logger.debug("----> Step 2 meta to typeql")
    # 3.) add each of the properties and values of the properties to the typeql statement
    prop_var_list = []
    for prop in properties:
        # split off for properties processing
        indep_ql2, indep_ql_props2, prop_var_list = add_property_to_typeql(prop, obj_tql, meta, prop_var_list)
        # then add them all together
        indep_ql += indep_ql2
        indep_ql_props += indep_ql_props2
        # add a terminator on the end of the query statement
    indep_ql += ";\n" + indep_ql_props + "\n\n"
    logger.debug("----> Step 3 sdo to typeql")

    # 4.) add each of the relations to the match and insert statements
    for j, rel in enumerate(relations):
        # split off for relation processing
        dep_match2, dep_insert2, dep_list2 = add_relation_to_typeql(rel, meta, meta_var, prop_var_list, import_type, j,
                                                                    protocol)
        # then add it back together
        dep_match = dep_match + dep_match2
        dep_insert = dep_insert + dep_insert2
        dep_list = dep_list + dep_list2

    logger.debug("----> Step 4 sdo to typeql")
    dep_obj = {"id": meta.id, "dep_list": dep_list, "type": meta.type}
    return dep_match, dep_insert, indep_ql, core_ql, dep_obj

    # # if the marking is a colour, match it in, else it is a statement type
    # if stix_object.definition_type == "statement":
    #     if attack_object:
    #         indep_ql = '\n $marking isa attack-marking'
    #         indep_ql += ',\n has x-mitre-attack-spec-version ' + val_tql(stix_object.x_mitre_attack_spec_version)
    #         loc_list = stix_object.x_mitre_domains
    #         for dom in loc_list:
    #             indep_ql += ',\n has x-mitre-domains ' + val_tql(dom)
    #         core_ql = '$marking isa attack-marking'
    #     else:
    #         indep_ql = '\n $marking isa statement-marking'
    #         core_ql = '$marking isa statement-marking'
    #     indep_ql += ',\n has statement ' + val_tql(stix_object.definition.statement)
    #     indep_ql += ',\n has stix-type "marking-definition"'
    #     indep_ql += ',\n has stix-id ' + val_tql(stix_object.id)
    #     indep_ql += ',\n has created ' + val_tql(stix_object.created)
    #     indep_ql += ',\n has spec-version ' + val_tql(stix_object.spec_version)
    #     indep_ql += ';\n'
    #     core_ql += ', has stix-id $stix-id;\n$stix-id ' + val_tql(stix_object.id)
    #     core_ql += ';'
    #
    # dep_obj = {"id": stix_object.id, "dep_list": dep_list, "type": "marking"}
    # return dep_match, dep_insert, indep_ql, core_ql, dep_obj
