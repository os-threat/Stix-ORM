import copy
from datetime import timezone

from typedb.api.concept.type.attribute_type import AttributeType

from stixorm.module.authorise import authorised_mappings

import logging

from stixorm.module.typedb_lib.factories.auth_factory import get_auth_factory_instance
from stixorm.module.typedb_lib.factories.import_type_factory import ImportType

logger = logging.getLogger(__name__)



# --------------------------------------------------------------------------------------------------------
#  1. Convert TypeQl Ans to Res
# --------------------------------------------------------------------------------------------------------


def convert_ans_to_res(answer_iterator, r_tx, import_type: ImportType):
    """
    Take the response from TypeDB to a query, and start the process to use GRPC (typedb_lib-client) commands
    to expand on the returned data to some potential object shape (i.e. mandatory and optional),
    and report it back in some intermediate form that can then be reprocessed into Stix 2.1 format.
    This depends on the shape of the Stix object involved.

    The first step is to branch depending on whether we are decoding an entity or relation.

    Args:
        answer_iterator (): current answers
        r_tx (): transaction thread to query
        import_type (): stix2.1 or att&ck, used in the second half

    Returns:
        res: A list of data objects, in the intermediate form for processing into Stix objects
    """
    res = []

    for answer in answer_iterator:
        #concepts = answer.concepts()
        variables = answer.variables()
        for variable in variables:
            concept = answer.get(variable)
            key = variable
            # pull entity data
            if concept.is_entity():
                # 1. describe entity
                thing = concept.as_entity()
                ent = {'type': 'entity',
                       'symbol': key,
                       'T_id': thing.get_iid(),
                       'T_name': thing.get_type().get_label().name}
                # 2 get and dsecribe properties
                props_obj = thing.get_has(r_tx)
                ent['has'] = process_props(props_obj)
                # 3. get and describe relations
                reln_types = thing.get_relations(r_tx)
                ent['relns'] = process_relns(reln_types, r_tx, import_type)
                res.append(ent)
                # logger.debug(f'ent -> {ent}')

            # pull relation data
            elif concept.is_relation():
                # 1. setup basis
                thing = concept.as_relation()
                rel = {'type': 'relationship',
                       'symbol': key,
                       'T_id': thing.get_iid(),
                       'T_name': thing.get_type().get_label().name}
                att_obj = thing.get_has(r_tx)
                rel['has'] = process_props(att_obj)
                # 3. get and describe relations
                reln_types = thing.get_relations(r_tx)
                rel['relns'] = process_relns(reln_types, r_tx, import_type)
                # 4. get and describe the edges
                edges = []
                edge_types = thing.get_players(r_tx)
                stix_id = r_tx.concepts.get_attribute_type("stix-id").resolve()
                for role, things in edge_types.items():
                    edge = {"role": role.get_label().name, 'player': []}
                    for thing in things:
                        if thing.is_entity():
                            edge['player'].append(process_entity(thing, r_tx, stix_id))

                    edges.append(edge)

                rel['edges'] = edges
                res.append(rel)

            # else log out error condition
            elif concept.is_type():
                logger.debug(f'Error key is {key}, thing is type')
            elif concept.is_thing_type():
                logger.debug(f'Error key is {key}, thing is thing type')
            elif concept.is_attribute_type():
                logger.debug(f'Error key is {key}, thing is attribute type')
            elif concept.is_relation_type():
                logger.debug(f'Error key is {key}, thing is relation type')
            elif concept.is_attribute():
                logger.debug(f'Error key is {key}, thing is attributee')
            elif concept.is_value():
                logger.debug(f'Error key is {key}, thing is value')
            elif concept.is_role_type():
                logger.debug(f'Error key is {key}, thing is role type')

    return res


def process_entity(thing, r_tx, stix_id: str):
    """
        If the current returned object from typedb_lib contains an entity then unpack it install grpc commands
        into an interim list
    Args:
        thing (): the grpc entity reference
        r_tx (): the typedb_lib transaction
        stix_id (): the stix object id

    Returns:
        play {}: a return dict
    """
    play = {"type": "entity", "tql": thing.get_type().get_label().name}
    attr_stix_id = thing.get_has(r_tx, attribute_type=stix_id)
    for attr in attr_stix_id:
        play["stix_id"] = attr.get_value()

    return play


def process_relns(reln_types, r_tx, import_type: ImportType):
    """
        If the current returned object is a list of relations (i.e. a list of embedded objects), then unpack them
    Args:
        reln_types (): iterable of relation types
        r_tx (): returned transaction

    Returns:
        relns []: a list of reln's
    """
    relns = []
    for r in reln_types:
        logger.debug(f'r  - >{r}, rtx -> {r_tx}')
        reln = get_relation_details(r, r_tx, import_type)
        relns.append(reln)

    return relns


def process_relation(p, r_tx, stix_id):
    """
        If the current returned object is a relation (i.e. embedded object) then unpack it
    Args:
        p ():  returned object
        r_tx (): returned transaction
        stix_id (): the id of the stix object

    Returns:
        plays {}: a dict containing the unpacked relation
    """
    plays = {"type": "attribute", "tql": p.get_type().get_label().name}
    attr_stix_id = p.get_has(r_tx, attribute_type=stix_id)
    for attr in attr_stix_id:
        plays["stix_id"] = attr.get_value()

    return plays


def process_props(props_obj):
    """
        Unpack  a list of properties/values
    Args:
        props_obj (): iterable object of properties

    Returns:
        props []: a list of properties
    """
    props = []
    for a in props_obj:
        prop = {"typeql": a.get_type().get_label().name}
        if a.is_datetime():
            nt_obj = a.get_value()
            dt_obj = nt_obj.astimezone(timezone.utc)
            prop["value"] = dt_obj.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
            prop['datetime'] = True
        elif a.is_string():
            temp_string = a.get_value()
            prop["value"] = temp_string.replace("\\\\", "\\")
            prop['datetime'] = False
        else:
            prop["value"] = a.get_value()
            prop['datetime'] = False

        props.append(prop)

    return props


def process_value(p):
    """
        If object is a value, then unpack it
    Args:
        p (): an object that is a value

    Returns:
        ret_value : a returned value
    """
    if p.is_datetime():
        nt_obj = p.get_value()
        dt_obj = nt_obj.astimezone(timezone.utc)
        ret_value = dt_obj.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    else:
        ret_value = p.get_value()

    return ret_value


def get_relation_details(r, r_tx, import_type: ImportType):
    """
        For a given sub-object type, unpack it
    Args:
        r (): the embedded relation object
        r_tx (): the retrned transaction

    Returns:
        reln {}: a dict containing the reln details
    """
    auth_factory = get_auth_factory_instance()
    auth = auth_factory.get_auth_for_import(import_type)
    reln = {}
    reln_name = r.get_type().get_label().name
    reln['T_name'] = reln_name
    reln['T_id'] = r.get_iid()
    if reln_name in auth["tql_types"]["embedded_relations"]:
        reln['roles'] = get_embedded_relations(r, r_tx)

    elif reln_name in auth["tql_types"]["standard_relations"] or reln_name == "sighting":
        reln['roles'] = get_standard_relations(r, r_tx)

    elif reln_name in auth["tql_types"]["key_value_relations"]:
        reln['roles'] = get_key_value_relations(r, r_tx)

    elif reln_name in auth["tql_types"]["extension_relations"]:
        reln['roles'] = get_extension_relations(r, r_tx, import_type)

    elif reln_name in auth["tql_types"]["list_of_objects"]:
        reln['roles'] = get_list_of_objects(r, r_tx, import_type)

    elif reln_name == "granular-marking":
        reln['roles'] = get_granular_marking(r, r_tx)

    elif reln_name == "hashes" or reln_name == "file-header-hashes":
        reln['roles'] = get_hashes(r, r_tx)

    else:
        logger.error(f'Error, relation name is {reln_name}')

    return reln


def reln_map_entity_attribute(reln_map, r_tx, stix_id: str, is_kv):
    """
        Process a map of Player by Role types, and unpack entity and attribute
    Args:
        reln_map (): relation map of player by role types
        r_tx (): transaction
        stix_id (): stix id
        is_kv (): do extra stuff if coming froma key-value relationship

    Returns:
        roles []: list of dict objects
    """
    roles = []
    for role, player in reln_map.items():
        role_i = {'role': role.get_label().name, 'player': []}
        for p in player:
            play = {}
            if p.is_entity():
                role_i['player'].append(process_entity(p, r_tx, stix_id))
            elif p.is_attribute():
                play["type"] = "attribute"
                play["tql"] = p.get_type().get_label().name
                play["value"] = process_value(p)
                if is_kv:
                    att_obj = p.get_has(r_tx)
                    play['props'] = process_props(att_obj)
                role_i['player'].append(play)

            else:
                logger.debug(f'player is not entity type {p}')

        roles.append(role_i)

    return roles


def get_granular_marking(r, r_tx):
    """
        Process a granular marking sub object through grpc
    Args:
        r (): the typedb_lib object
        r_tx (): the transaction

    Returns:
        roles []: list of dict objects
    """
    stix_id = r_tx.concepts.get_attribute_type("stix-id").resolve()
    reln_map = r.get_players(r_tx)
    is_kv: object = False
    roles = reln_map_entity_attribute(reln_map, r_tx, stix_id, is_kv)
    return roles


def get_hashes(r, r_tx):
    """
        Process a get hashes sub object through grpc
    Args:
        r (): the typedb_lib object
        r_tx (): the transaction

    Returns:
        roles []: list of dict objects
    """
    roles = []
    stix_id = r_tx.concepts.get_attribute_type("stix-id").resolve()
    hash_value = r_tx.concepts.get_attribute_type("hash-value").resolve()
    reln_map = r.get_players(r_tx)

    for role, player in reln_map.items():
        role_name = role.get_label().name
        role_i = {'role': role_name, 'player': []}
        for p in player:
            play = {}
            if p.is_entity():
                play["type"] = "entity"
                play["tql"] = p.get_type().get_label().name
                if role_name == "owner":
                    attr_stix_id = p.get_has(r_tx, attribute_type=stix_id)
                    for attr in attr_stix_id:
                        play["stix_id"] = attr.get_value()
                else:
                    attr_hash_value = p.get_has(r_tx, attribute_type=hash_value)
                    for attr in attr_hash_value:
                        play["hash_value"] = attr.get_value()

                role_i['player'].append(play)

            else:
                logger.debug(f'player is not entity type {p}')

        roles.append(role_i)
    return roles


def get_key_value_relations(r, r_tx):
    """
        Process a key-value sub object through grpc
    Args:
        r (): the typedb_lib object
        r_tx (): the transaction

    Returns:
        roles []: list of dict objects
    """
    stix_id = r_tx.concepts.get_attribute_type("stix-id").resolve()
    reln_map = r.get_players(r_tx)
    is_kv: object = True
    roles = reln_map_entity_attribute(reln_map, r_tx, stix_id, is_kv)
    return roles


def get_list_of_objects(r,
                        r_tx,
                        import_type: ImportType):
    """
        Process a list of objects sub object through grpc
    Args:
        r (): the typedb_lib object
        r_tx (): the transaction

    Returns:
        roles []: list of dict objects
    """
    auth_factory = get_auth_factory_instance()
    auth = auth_factory.get_auth_for_import(import_type)
    reln_name = r.get_type().get_label().name
    for lot in auth["reln"]["list_of_objects"]:
        if reln_name == lot["typeql"]:
            reln_pointed_to = lot["pointed_to"]
            reln_object = lot["object"]
            reln_object_props = copy.deepcopy(auth["sub_objects"][reln_object])
            reln_stix = lot["name"]

    stix_id = r_tx.concepts.get_attribute_type("stix-id").resolve()
    reln_map = r.get_players(r_tx)
    roles = []
    for role, player in reln_map.items():
        role_i = {'role': role.get_label().name, 'player': []}
        for p in player:
            play = {}
            if p.is_entity():
                play["type"] = "entity"
                play["tql"] = p.get_type().get_label().name
                props_obj = p.get_has(r_tx)
                play['has'] = process_props(props_obj)
                # 3. get and describe relations
                reln_types = p.get_relations(r_tx)
                relns = []
                for rel in reln_types:
                    reln = {}
                    reln_name = rel.get_type().get_label().name

                    reln['T_name'] = reln_name
                    reln['T_id'] = rel.get_iid()
                    reln_map = rel.get_players(r_tx)
                    reln['roles'] = reln_map_entity_relation(reln_map, r_tx, stix_id)
                    relns.append(reln)

                play['relns'] = relns
                role_i['player'].append(play)


            else:
                logger.debug(f'player is not entity type {p}')

        roles.append(role_i)
    return roles


def reln_map_entity_relation(reln_map,
                             r_tx,
                             stix_id: str):
    """

    Args:
        reln_map ():
        r_tx ():
        stix_id ():

    Returns:

    """
    roles = []
    for role_type, relns in reln_map.items():
        for reln in relns:
            role_i = {'role': role_type.get_label().name, 'player': []}
            play = {}
            if reln.is_entity():
                role_i['player'].append(process_entity(reln, r_tx, stix_id))
            elif reln.is_relation():
                role_i['player'].append(process_relation(reln, r_tx, stix_id))

            else:
                logger.debug(f'player is not entity type {reln.get_type().get_label().name}')


            roles.append(role_i)

    return roles


def get_embedded_relations(r, r_tx):
    """
        Process embedded relationships (i.e. based on Stix-id)
    Args:
        r (): relation
        r_tx (): transaction

    Returns:
        roles []: list of dict objects
    """
    stix_id_attribute_type: AttributeType = r_tx.concepts.get_attribute_type("stix-id").resolve()

    #stix_id = stix_id_attribute_type.get(r_tx, str)
    reln_map = r.get_players(r_tx)
    roles = reln_map_entity_relation(reln_map, r_tx, stix_id_attribute_type)
    return roles


def get_extension_relations(r,
                            r_tx,
                            import_type: ImportType):
    """
        Process a Stix extension sub object through grpc
    Args:
        r (): the typedb_lib object
        r_tx (): the transaction

    Returns:
        roles []: list of dict objects
    """
    auth_factory = get_auth_factory_instance()
    auth = auth_factory.get_auth_for_import(import_type)
    reln_name = r.get_type().get_label().name
    for ext in auth["reln"]["extension_relations"]:
        if ext['relation'] == reln_name:
            reln_object = ext['object']

    stix_id = r_tx.concepts.get_attribute_type("stix-id").resolve()
    reln_map = r.get_players(r_tx)
    roles = []
    for role, player in reln_map.items():
        role_i = {'role': role.get_label().name, 'player': []}
        for p in player:
            play = {}
            if p.is_entity():
                play["type"] = "entity"
                p_name = p.get_type().get_label().name
                play["tql"] = p_name
                if p_name == reln_object:
                    props_obj = p.get_has(r_tx)
                    play['has'] = process_props(props_obj)
                    # 3. get and describe relations
                    reln_types = p.get_relations(r_tx)
                    relns = []
                    for rel in reln_types:
                        reln = {}
                        reln = validate_get_relns(rel, r_tx, reln_object, import_type)
                        if reln == {} or reln is None:
                            pass
                        else:
                            relns.append(reln)

                    play['relns'] = relns

                else:
                    attr_stix_id = p.get_has(r_tx, attribute_type=stix_id)
                    for attr in attr_stix_id:
                        play["stix_id"] = attr.get_value()

                role_i['player'].append(play)
            elif p.is_attribute():
                play["type"] = "attribute"
                play["tql"] = p.get_type().get_label().name
                play["value"] = process_value(p)
                role_i['player'].append(play)

            else:
                logger.debug(f'player is not entity type {p}')

        roles.append(role_i)
    return roles


def validate_get_relns(rel,
                       r_tx,
                       obj_name,
                       import_type: ImportType):
    """
        When processing relations for an object, ensure we only access relations for sub objects,
        and not Stix relations or sightings
    Args:
        rel (): the relation
        r_tx (): the transaction
        obj_name (): the object involved in the relation

    Returns:
        reln {}: a dict containing the reln details
    """
    auth_factory = get_auth_factory_instance()
    auth = auth_factory.get_auth_for_import(import_type)
    reln={}
    reln_name = rel.get_type().get_label().name
    if reln_name in auth["tql_types"]["embedded_relations"]:
        for emb in auth["reln"]["embedded_relations"]:
            if emb['typeql'] == reln_name:
                role_owner = emb['owner']
        return return_valid_relations(rel, r_tx, obj_name, role_owner, import_type)

    elif reln_name in auth["tql_types"]["key_value_relations"]:
        for kvt in auth["reln"]["key_value_relations"]:
            if kvt['typeql'] == reln_name:
                role_owner = kvt['owner']
        return return_valid_relations(rel, r_tx, obj_name, role_owner, import_type)

    elif reln_name in auth["tql_types"]["extension_relations"]:
        logger.debug(f'reln name {reln_name}')
        for kvt in auth["reln"]["extension_relations"]:
            if kvt['relation'] == reln_name:
                role_owner = kvt['owner']
        return return_valid_relations(rel, r_tx, obj_name, role_owner, import_type)

    elif reln_name in auth["tql_types"]["list_of_objects"]:
        for kvt in auth["reln"]["list_of_objects"]:
            if kvt['typeql'] == reln_name:
                role_owner = kvt['owner']
        return return_valid_relations(rel, r_tx, obj_name, role_owner, import_type)

    elif reln_name == "granular-marking":
        return get_relation_details(rel, r_tx, import_type)

    elif reln_name == "hashes":
        return get_relation_details(rel, r_tx, import_type)

    else:
        logger.error(f'Error, relation name is {reln_name}')


def return_valid_relations(rel,
                           r_tx,
                           obj_name,
                           role_owner,
                           import_type: ImportType):
    """
        return only the valid relations to the relation check
    Args:
        rel (): the actual relation
        r_tx (): the transaction
        obj_name (): the object involved
        role_owner (): the owner of the role

    Returns:
        reln {}: a dict containing the reln details
    """
    reln_map = rel.get_players(r_tx)
    for role, player in reln_map.items():
        role_name = role.get_label().name
        if role_name == role_owner:
            for p in player:
                if p.is_entity():
                    play_name = p.get_type().get_label().name
                    if play_name == obj_name:
                        return get_relation_details(rel, r_tx, import_type)


def get_standard_relations(r, r_tx):
    """
        Ignore standard relations, as they are not sub objects
    Returns:
        Emptyy List:
    """
    return []
