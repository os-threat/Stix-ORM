import json
import pathlib
import traceback
from typing import List

from stix.module.authorise import authorised_mappings
from stix.module.parsing.conversion_decisions import sdo_type_to_tql, sro_type_to_tql, sco__type_to_tql
from stix.module.orm.export_utilities import convert_ans_to_res
import logging
logger = logging.getLogger(__name__)

###################################################################################################
#
#    TypeQL to Stix Mapping
#
###################################################################################################


# --------------------------------------------------------------------------------------------------------
#  Overview:
#     1. Convert TypeQL Ans to Res, using the transaction
#     2. Convert Res to Stix, creating first the dict, then parsing the dict to Stix object
# --------------------------------------------------------------------------------------------------------


def convert_ans_to_stix(answer_iterator, r_tx, import_type):
    """
        High level function to convert the typedb_lib return into a Stix object.
        Firstly, drive the grpc to make an intermediate format, then convert that to a Stix dict
    Args:
        answer_iterator (): the returned iterator from the typedb_lib query
        r_tx (): the transaction
        import_type (): the type of import STIX21 or ATT&CK

    Returns:
        stix_dict {}: a dict containing the stix object
    """
    res = convert_ans_to_res(answer_iterator, r_tx, import_type)
    path = pathlib.Path(__file__).parent.joinpath("export_test.json")
    with open(str(path), 'w') as outfile:
        json.dump(res, outfile)
    logger.debug(f'got res, now for stix')
    stix_dict = convert_res_to_stix(res, import_type)
    return stix_dict


# --------------------------------------------------------------------------------------------------------
#  2. Convert Res to Stix
# --------------------------------------------------------------------------------------------------------

def convert_res_to_stix(res: List[dict], import_type: dict):
    """
        High level function to conver the intermediate form into a stix dict
    Args:
        res (): the intermediate form
        import_type (): the type of import "STIX21" or "ATT&CK"

    Returns:
        stix_dict {}: a dict containing the stix object
    """

    auth = authorised_mappings(import_type)
    stix_dict = {}
    for obj in res:
        obj_type = obj["T_name"]
        tql_type = obj["type"]
        if obj_type in auth["tql_types"]["sdo"]:
            stix_dict = make_sdo(obj, import_type)
        elif obj_type in auth["tql_types"]["sco"]:
            stix_dict = make_sco(obj, import_type)
        elif tql_type in auth["tql_types"]["sro"]:
            stix_dict = make_sro(obj, import_type)
        elif obj_type in auth["tql_types"]["meta"]:
            stix_dict = make_meta(obj, import_type)
        else:
            logger.error(f'Unknown object type: {obj}')

    return stix_dict


def make_sdo(res, import_type):
    """
        High-level function to convert intermediate format into a Stix domain object
    Args:
        res (): intermediate format
        import_type (): the type of import "STIX21" or "ATT&CK"

    Returns:
        stix_dict {}: a dict containing the stix object
    """
    try:
        auth = authorised_mappings(import_type)
        stix_dict = {}
        # 2.A) get the typeql properties and relations
        sdo_tql_name = res["T_name"]
        props = res["has"]
        relns = res["relns"]
        attack_object = False
        sub_technique = False
        for prop in props:
            if prop["typeql"] == "x_mitre_version":
                attack_object = True
            if prop["typeql"] == "x_mitre_is_subtechnique":
                sub_technique = True

        obj_tql, sdo_tql_name, is_list = sdo_type_to_tql(sdo_tql_name, import_type, attack_object, sub_technique)

        # 2.B) get the is_list list, the list of properties that are lists for that object
        is_list = auth["is_lists"]["sdo"]["sdo"] + auth["is_lists"]["sdo"][sdo_tql_name]
        # 3.A) add the properties onto the the object
        stix_dict = make_properties(props, obj_tql, stix_dict, is_list)
        logger.debug('sdo, add properties')
        # 3.B) add the relations onto the object
        stix_dict = make_relations(relns, obj_tql, stix_dict, is_list, sdo_tql_name, import_type)
        logger.debug('sdo, add relations')
        # 4.0 Check for the edge case where an identity creates an identity, but they are the same id
        if "created_by_ref" in stix_dict and stix_dict["type"] == "identity":
            if stix_dict["created_by_ref"] == stix_dict["id"]:
                del stix_dict["created_by_ref"]
    except Exception as e:
        traceback.print_exc()
        print(e)

    return stix_dict


def make_sro(res, import_type):
    """
        High-level function to convert intermediate format into a Stix relationship object
    Args:
        res (): intermediate format
        import_type (): the type of import "STIX21" or "ATT&CK"

    Returns:
        stix_dict {}: a dict containing the stix object
    """
    auth = authorised_mappings(import_type)
    stix_dict = {}
    # 2.A) get the typeql properties and relations
    sro_tql_name = res["type"]

    props = res["has"]
    sro_sub_rel = ""
    if sro_tql_name == "relationship":
        for has in props:
            if has["typeql"] == "relationship-type":
                sro_sub_rel = has["value"]
                break

    relns = res["relns"]
    #
    # Note, Issue, cannot yet tell what to do with a procedure
    #
    attack_object = False
    uses_relation = False
    is_procedure = False
    for prop in props:
        if prop["typeql"] == "x_mitre_version":
            attack_object = True

    obj_tql, sro_tql_name, is_list = sro_type_to_tql(sro_tql_name, sro_sub_rel, import_type, attack_object, uses_relation, is_procedure)

    # 2.A) get the typeql properties and relations
    props = res["has"]
    relns = res["relns"]
    edges = res["edges"]
    # 2.) setup the match statements first, depending on whether the object is a sighting or a relationship
    # A. If it is a Relationship then find the source and target roles for the relation, and match them in
    if sro_tql_name in auth["reln_name"]["standard_relations"]:
        for stix_rel in auth["reln"]["standard_relations"]:
            if stix_rel["typeql"] == sro_tql_name:
                source_role = stix_rel["source"]
                target_role = stix_rel["target"]
                break

        for edge in edges:
            players = edge["player"]
            if edge["role"] == source_role:
                for p in players:
                    stix_dict["source_ref"] = p["stix_id"]
                    break

            elif edge["role"] == target_role:
                for p in players:
                    stix_dict["target_ref"] = p["stix_id"]
                    break
            else:
                logger.error(f'edge role {edge["role"]} not supported')
                return ''

    # B. If it is a Sighting then match the object to the sighting
    elif sro_tql_name == 'sighting':
        is_list = auth["is_lists"]["sro"]["sro"] + auth["is_lists"]["sro"]["sighting"]
        for edge in edges:
            players = edge["player"]
            if edge["role"] == "sighting-of":
                for p in players:
                    stix_dict["sighting_of_ref"] = p["stix_id"]

            elif edge["role"] == "where-sighted":
                for p in players:
                    if "where_sighted_refs" in stix_dict:
                        stix_dict["where_sighted_refs"].append(p["stix_id"])
                    else:
                        stix_dict["where_sighted_refs"] = []
                        stix_dict["where_sighted_refs"].append(p["stix_id"])
            elif edge["role"] == "observed":
                for p in players:
                    if "observed_data_refs" in stix_dict:
                        stix_dict["observed_data_refs"].append(p["stix_id"])
                    else:
                        stix_dict["observed_data_refs"] = []
                        stix_dict["observed_data_refs"].append(p["stix_id"])
            else:
                logger.error(f'edge role {edge["role"]} not supported')
                return ''

    else:
        logger.error(f'relationship type {sro_tql_name} not supported')
        return ''

    # 3.A) add the properties onto the the object
    stix_dict = make_properties(props, obj_tql, stix_dict, is_list)
    # 3.B) add the relations onto the object
    stix_dict = make_relations(relns, obj_tql, stix_dict, is_list, sro_tql_name, import_type)
    return stix_dict


def make_sco(res: dict, import_type):
    """
        High-level function to convert intermediate format into a Stix cyber observable object
    Args:
        res (): intermediate format
        import_type (): the type of import "STIX21" or "ATT&CK"

    Returns:
        stix_dict {}: a dict containing the stix object
    """
    auth = authorised_mappings(import_type)
    # - work out the type of object
    stix_dict = {}
    obj_type = res["T_name"]
    # - get the object-specific typeql names, sighting or relationship
    # - work out the type of object
    sco_tql_name = obj_type
    # - get the object-specific typeql names, sighting or relationship
    obj_tql, sco_tql_name, is_list = sco__type_to_tql(sco_tql_name, import_type)

    # 2.A) get the typeql properties and relations
    props = res["has"]
    relns = res["relns"]

    is_list = auth["is_lists"]["sco"]["sco"] + auth["is_lists"]["sco"][obj_type]
    # 3.A) add the properties onto the the object
    stix_dict = make_properties(props, obj_tql, stix_dict, is_list)
    # 3.B) add the relations onto the object
    stix_dict = make_relations(relns, obj_tql, stix_dict, is_list, obj_type, import_type)
    return stix_dict


colours_dict = {
    "tlp-amber": {"type": "marking-definition", "spec_version": "2.1",
                  "id": "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82",
                  "created": "2017-01-20T00:00:00.000Z", "definition_type": "tlp",
                  "name": "TLP:AMBER", "definition": {"tlp": "amber"}},
    "tlp-green": {"type": "marking-definition", "spec_version": "2.1",
                  "id": "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da",
                  "created": "2017-01-20T00:00:00.000Z", "definition_type": "tlp",
                  "name": "TLP:GREEN", "definition": {"tlp": "green"}},
    "tlp-white": {"type": "marking-definition", "spec_version": "2.1",
                  "id": "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",
                  "created": "2017-01-20T00:00:00.000Z", "definition_type": "tlp",
                  "name": "TLP:WHITE", "definition": {"tlp": "white"}},
    "tlp-red": {"type": "marking-definition", "spec_version": "2.1",
                "id": "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed",
                "created": "2017-01-20T00:00:00.000Z", "definition_type": "tlp",
                "name": "TLP:RED", "definition": {"tlp": "red"}}
}


def make_meta(res, import_type):
    """
        High-level function to convert intermediate format into a Stix meta object
    Args:
        res (): intermediate format
        import_type (): the type of import "STIX21" or "ATT&CK"

    Returns:
        stix_dict {}: a dict containing the stix object
    """
    stix_dict = {}
    obj_type = res["T_name"]
    props = res["has"]
    if obj_type == "tlp-white" or obj_type == "tlp-green" or obj_type == "tlp-amber" or obj_type == "tlp-red":
        return colours_dict[obj_type]
    elif obj_type == "statement-marking":
        stix_dict["definition_type"] = "statement"
        stix_dict["type"] = "marking-definition"
        for prop in props:
            if prop["typeql"] == "stix-id":
                stix_dict["id"] = prop["value"]
            elif prop["typeql"] == "spec-version":
                stix_dict["spec_version"] = prop["value"]
            elif prop["typeql"] == "created":
                stix_dict["created"] = prop["value"]
            elif prop["typeql"] == "statement":
                temp_dict = {}
                temp_dict["statement"] = prop["value"]
                stix_dict["definition"] = temp_dict

    else:
        logger.error(f' make meta type not implemented {obj_type}')

    return stix_dict


def make_properties(props, obj_tql, stix_dict, is_list):
    """
        Unpack properties for a stix object (i.e. values at the 'has' level)
    Args:
        props (): a list of proeprties
        obj_tql (): the tql that describes the object
        stix_dict (): the stix dict that we are building
        is_list (): a list of the properties that are lists

    Returns:
        stix_dict {}: a dict containing the stix object
    """
    for prop in props:
        prop_tql_name = prop["typeql"]
        prop_value = prop["value"]
        for stix_name, stix_value in obj_tql.items():
            if prop_tql_name == stix_value:
                # if property is a list, then
                if stix_name in is_list:
                    if stix_name not in stix_dict:
                        stix_dict[stix_name] = []
                        stix_dict[stix_name].append(prop_value)
                        break
                    else:
                        stix_dict[stix_name].append(prop_value)
                        break
                # else property is a value, not a list
                else:
                    stix_dict[stix_name] = prop_value

    return stix_dict


def make_relations(relns, obj_tql, stix_dict, is_list, obj_name=None, import_type=None):
    """
        Overall branching function for processing all the sub objects
    Args:
        relns (): the list of relations to process
        obj_tql (): the object tql for this stix object
        stix_dict (): the stix dict we are building
        is_list (): the list of properties that are a list
        obj_name (): the stix object these sub objects belong to

    Returns:
        stix_dict {}: a dict containing the stix object
    """
    auth = authorised_mappings(import_type)
    for reln in relns:
        reln_name = reln["T_name"]
        if reln_name in auth["reln_name"]["embedded_relations"]:
            stix_dict = make_embedded_relations(reln, reln_name, stix_dict, is_list, obj_name, import_type)

        elif reln_name in auth["reln_name"]["standard_relations"] or reln_name == "sighting":
            stix_dict = make_standard_relations(reln, reln_name, stix_dict, is_list, obj_name, import_type)

        elif reln_name in auth["reln_name"]["key_value_relations"]:
            stix_dict = make_key_value_relations(reln, reln_name, stix_dict, is_list, obj_name, import_type)

        elif reln_name in auth["reln_name"]["extension_relations"]:
            stix_dict = make_extension_relations(reln, reln_name, stix_dict, is_list, obj_name, import_type)

        elif reln_name in auth["reln_name"]["list_of_objects"]:
            stix_dict = make_list_of_objects(reln, reln_name, stix_dict, is_list, obj_name, import_type)

        elif reln_name == "x509_v3_extensions" or reln_name == "optional_header":
            stix_dict = make_object(reln, reln_name, stix_dict, is_list, obj_name, import_type)

        elif reln_name == "granular-marking":
            stix_dict = make_granular_marking(reln, reln_name, stix_dict, is_list, obj_tql, obj_name)

        elif reln_name == "hashes" or reln_name == "file_header_hashes":
            stix_dict = make_hashes(reln, reln_name, stix_dict)

        else:
            logger.error(f'Error, relation name is {reln_name}')
            break

    return stix_dict


def make_embedded_relations(reln, reln_name, stix_dict, is_list, obj_name, import_type):
    """
        Setup embedded relations based on stix-id's
    Args:
        reln (): relation object
        reln_name (): relation name
        stix_dict (): stix dict being built
        is_list (): list of parameters that are lists
        obj_name (): stix object that owns the embedded relation

    Returns:
        stix_dict {}: a dict containing the stix object
    """
    auth = authorised_mappings(import_type)
    stix_object_type = obj_name
    for embedded_r in auth["reln"]["embedded_relations"]:
        if reln_name == embedded_r["typeql"]:
            role_pointed = embedded_r["pointed-to"]
            stix_name = embedded_r["rel"]
            role_owner = embedded_r["owner"]

    roles = reln["roles"]
    for role in roles:
        if role["role"] == role_pointed:
            pointed = role
        elif role["role"] == role_owner:
            owner = role
        else:
            logger.error(f'unsupported role in embedded relation {role["role"]}')

    # 1. Is Owner correct, basically my super object?
    # - should be only one object in the owner role list, and its type is the same as my super object type
    own_players = owner["player"]
    own_player = own_players[0]
    if own_player['tql'] == stix_object_type:
        # 2. If 1 is yes, then we want to find the emebedded relation, else not
        pointed_players = pointed["player"]
        for p in pointed_players:
            prop_value = p['stix_id']
            # if property is a list, then
            if stix_name in is_list:
                if stix_name not in stix_dict:
                    stix_dict[stix_name] = []
                    stix_dict[stix_name].append(prop_value)

                else:
                    stix_dict[stix_name].append(prop_value)

            # else property is a value, not a list
            else:
                stix_dict[stix_name] = prop_value
    else:
        return stix_dict

    return stix_dict


def make_standard_relations(reln, reln_name, stix_dict, is_list, obj_name=None, import_type=None):
    logger.warning(" make standard relations visited, but not implemented")
    auth = authorised_mappings(import_type)
    return stix_dict


def make_key_value_relations(reln, reln_name, stix_dict, is_list, obj_type=None, import_type=None):
    """
        Setup embedded relations based on stix-id's
    Args:
        reln (): relation object
        reln_name (): relation name
        stix_dict (): stix dict being built
        is_list (): list of parameters that are lists
        obj_type (): stix object that owns the embedded relation

    Returns:
        stix_dict {}: a dict containing the stix object
    """
    auth = authorised_mappings(import_type)
    for kv_obj in auth["reln"]["key_value_relations"]:
        if reln_name == kv_obj["typeql"]:
            role_pointed = kv_obj["pointed_to"]
            reln_owner = kv_obj["owner"]
            key_name = kv_obj["key"]
            val_name = kv_obj["value"]
            stix_field_name = kv_obj["name"]
            break

    roles = reln["roles"]
    dict_of_kv = {}
    for role in roles:
        if role["role"] == role_pointed:
            players = role["player"]
            for p in players:
                key_value = p["value"]
                props = p['props']
                prop_list = []
                if len(props) > 1:
                    for prop in props:
                        val_value = prop["value"]
                        prop_list.append(val_value)

                    dict_of_kv[key_value] = prop_list

                else:
                    val_value = props[0]["value"]
                    dict_of_kv[key_value] = val_value

    stix_dict[stix_field_name] = dict_of_kv
    return stix_dict


def make_extension_relations(reln, reln_name, stix_dict, is_list, obj_type, import_type=None):
    """
        Setup extension relations based on stix-id's
    Args:
        reln (): relation object
        reln_name (): relation name
        stix_dict (): stix dict being built
        is_list (): list of parameters that are lists
        obj_type (): stix object that owns the embedded relation

    Returns:
        stix_dict {}: a dict containing the stix object
    """
    auth = authorised_mappings(import_type)
    local_dict = {}
    local_dict = make_object(reln, reln_name, local_dict, is_list, obj_type)
    stix_dict["extensions"] = local_dict
    return stix_dict


def make_object(reln, reln_name, stix_dict, is_list, obj_type=None, import_type=None):
    """
        Setup a sub object
    Args:
        reln (): relation object
        reln_name (): relation name
        stix_dict (): stix dict being built
        is_list (): list of parameters that are lists
        obj_type (): stix object that owns the embedded relation

    Returns:
        stix_dict {}: a dict containing the stix object
    """
    auth = authorised_mappings(import_type)
    for ext_obj in auth["reln"]["extension_relations"]:
        if reln_name == ext_obj["relation"]:
            role_pointed = ext_obj["pointed-to"]
            role_owner = ext_obj["owner"]
            ext_object = ext_obj["object"]
            stix_ext_name = ext_obj["stix"]
            obj_is_list =auth["is_lists"]["sub"][ext_object]
            break

    if ext_object in auth["sub_objects"]:
        obj_props_tql = auth["sub_objects"][ext_object]
    else:
        raise ValueError("no sub-object available")
    roles = reln["roles"]
    ext_data_object = {}
    for role in roles:
        if role["role"] == role_pointed:
            players = role["player"]
            for p in players:
                player = {}
                # get properties for the sub object
                props = p['has']
                for prop in props:
                    prop_name = prop["typeql"]
                    prop_stix_name = prop_value = None
                    for stix, tql in obj_props_tql.items():
                        if prop_name == tql:
                            prop_stix_name = stix
                            prop_value = prop["value"]
                            break
                    # if property is a list, then
                    if prop_stix_name in obj_is_list:
                        if prop_stix_name not in player:
                            player[prop_stix_name] = []
                            player[prop_stix_name].append(prop_value)

                        else:
                            player[prop_stix_name].append(prop_value)

                    # else property is a value, not a list
                    else:
                        player[prop_stix_name] = prop_value
                # now look to see if there are relations
                obj_relns = [k for k, v in obj_props_tql.items() if v == ""]
                sub_relns = p['relns']
                obj_tql = auth["sub_objects"][ext_object]
                new_dict = {}
                new_dict = make_relations(sub_relns, obj_tql, new_dict, is_list, ext_object)
                for k, v in new_dict.items():
                    player[k] = v

    stix_dict[stix_ext_name] = player
    return stix_dict


def make_list_of_objects(reln, reln_name, stix_dict, is_list, obj_type=None, import_type=None):
    """
        Setup a list of sub objects
    Args:
        reln (): relation object
        reln_name (): relation name
        stix_dict (): stix dict being built
        is_list (): list of parameters that are lists
        obj_type (): stix object that owns the embedded relation

    Returns:
        stix_dict {}: a dict containing the stix object
    """
    auth = authorised_mappings(import_type)
    for l_obj in auth["reln"]["list_of_objects"]:
        if reln_name == l_obj["typeql"]:
            role_pointed = l_obj["pointed_to"]
            reln_object = l_obj["object"]
            stix_field_name = l_obj["name"]
            obj_is_list = auth["is_lists"]["sub"][reln_object]
            break

    if reln_object in auth["sub_objects"]:
        obj_props_tql = auth["sub_objects"][reln_object]
    else:
        raise ValueError("no sub-object available")
    roles = reln["roles"]
    list_of_objects = []
    for role in roles:
        if role["role"] == role_pointed:
            players = role["player"]
            for p in players:
                player = {}
                # get properties for the sub object
                props = p['has']
                for prop in props:
                    prop_name = prop["typeql"]
                    prop_stix_name = prop_value = None
                    for stix, tql in obj_props_tql.items():
                        if prop_name == tql:
                            prop_stix_name = stix
                            prop_value = prop["value"]
                            break
                    # if property is a list, then
                    if prop_stix_name in obj_is_list:
                        if prop_stix_name not in player:
                            player[prop_stix_name] = []
                            player[prop_stix_name].append(prop_value)

                        else:
                            player[prop_stix_name].append(prop_value)

                    # else property is a value, not a list
                    else:
                        player[prop_stix_name] = prop_value
                # now look to see if there are relations
                obj_relns = [k for k, v in obj_props_tql.items() if v == ""]
                sub_relns = p['relns']
                for sub_reln in sub_relns:
                    # if the relation is embedded
                    if sub_reln["T_name"] in auth["reln_name"]["embedded_relations"]:
                        for inst in auth["reln"]["embedded_relations"]:
                            if inst["typeql"] == sub_reln["T_name"]:
                                obj_reln_name = inst["typeql"]
                                obj_owner = inst["owner"]
                                obj_pointed = inst["pointed-to"]
                                obj_stix_name = inst["rel"]
                                break

                        local_roles = sub_reln["roles"]
                        for l_r in local_roles:
                            # if the owner role  is considered
                            if l_r["role"] == obj_owner:
                                local_players = l_r["player"]
                                # and the existing object used in the list of objects
                                if local_players[0]["tql"] == reln_object:
                                    for l_r2 in local_roles:
                                        if l_r2["role"] == obj_pointed:
                                            players2 = l_r2["player"]
                                            for p2 in players2:
                                                # then we write the result as an embedded relation
                                                answer = p2['stix_id']
                                                if obj_stix_name in obj_is_list:
                                                    if obj_stix_name not in player:
                                                        player[obj_stix_name] = []
                                                        player[obj_stix_name].append(answer)

                                                    else:
                                                        player[obj_stix_name].append(answer)

                                                else:
                                                    player[obj_stix_name] = answer

                    # else:
                    # logger.debug(f'unsupported relation for list of objects {sub_reln}')
                    # print(f'embedded --> {stix_models["embedded_relations_typeql"]}')

                list_of_objects.append(player)

    stix_dict[stix_field_name] = list_of_objects
    return stix_dict


def make_granular_marking(reln, reln_name, stix_dict, is_list, obj_tql, obj_type=None):
    """
        Setup granular marking sub object
    Args:
        reln (): relation object
        reln_name (): relation name
        stix_dict (): stix dict being built
        is_list (): list of parameters that are lists
        obj_type (): stix object that owns the embedded relation

    Returns:
        stix_dict {}: a dict containing the stix object
    """
    stix_label = "granular_markings"
    local_marking = {}
    roles = reln["roles"]
    lang_marking = stix_marking = None
    for role in roles:
        if role["role"] == "marking":
            local_p = role["player"][0]
            local_id = local_p["stix_id"]
            local_type = local_id.split('--')[0]
            if local_type == "marking-definition":
                stix_marking = local_id
            else:
                lang_marking = local_id

        elif role["role"] == "marked":
            local_p = role["player"]
            selectors = []
            for p in local_p:
                tql_name = p["tql"]
                stix_name = ''
                for key, value in obj_tql.items():
                    if value == tql_name:
                        stix_name = key
                        break

                # if property being marked is a list, then
                if stix_name in is_list:
                    # find the item in the property list with the same value, as my typeql value
                    tql_value = p["value"]
                    list_to_check = stix_dict[stix_name]
                    for i, item in enumerate(list_to_check):
                        if item == tql_value:
                            stix_name = stix_name + '.[' + str(i) + ']'
                            selectors.append(stix_name)

                            # else property is a value, not a list
                else:
                    selectors.append(stix_name)

    if stix_marking is not None:
        local_marking["marking_ref"] = stix_marking
        local_marking["selectors"] = selectors
    else:
        local_marking["lang"] = lang_marking
        local_marking["selectors"] = selectors

    if "granular_markings" in stix_dict:
        stix_dict["granular_markings"].append(local_marking)
    else:
        stix_dict["granular_markings"] = []
        stix_dict["granular_markings"].append(local_marking)

    return stix_dict


def make_hashes(reln, reln_name, stix_dict):
    """
        Setup hashes sub object
    Args:
        reln (): relation object
        reln_name (): relation name
        stix_dict (): stix dict being built

    Returns:
        stix_dict {}: a dict containing the stix object
    """
    stix_label = "hashes"
    hashes = {}
    roles = reln["roles"]
    for r in roles:
        if r["role"] == "owner":
            own_players = r["player"]
        elif r['role'] == "pointed-to":
            own_players = r["player"]
            for p in own_players:
                hash_type = p["tql"]
                hash_value = p["hash_value"]
                hashes[hash_type] = hash_value

        else:
            logger.error(f" make hashes relation not implemented {r['role']}")

    stix_dict[stix_label] = hashes
    return stix_dict



