import logging
import traceback
from typing import List, Iterator
from typedb.api.answer.concept_map import ConceptMap
from typedb.api.connection.driver import TypeDBDriver
from typedb.api.connection.session import SessionType, TypeDBSession
from typedb.api.connection.transaction import TransactionType, TypeDBTransaction
from typedb.common.promise import Promise
from typedb.api.query.query_manager import QueryManager
from typedb.driver import TypeDB
#from typedb.stream.bidirectional_stream import BidirectionalStream
from typedb.common.promise import Promise
from typedb.driver import TypeDB
from stixorm.module.typedb_lib.logging import log_delete_layer, log_add_layer
from stixorm.module.typedb_lib.instructions import Instructions

logger = logging.getLogger(__name__)



def build_insert_query(layer):
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
    logger.debug(f'\n match_tql string?-> {match_tql}')
    logger.debug(f'\n insert_tql string?-> {insert_tql}')
    typeql_string = match_tql + insert_tql

    insertion_is_empty = len(insert_tql) == 0
    if insertion_is_empty:
        return None
    return typeql_string


def build_match_id_query(stix_ids: List[str]):
    get_ids_tql = 'match $id isa stix-id; '
    len_id = len(stix_ids)
    if len_id == 1:
        get_ids_tql += '$id "' + stix_ids[0] + '";'
    else:
        for index, id_l in enumerate(stix_ids):
            get_ids_tql += ' {$id "' + id_l + '";}'
            if index == len_id - 1:
                get_ids_tql += " ;"
            else:
                get_ids_tql += ' or '
    return get_ids_tql + " get $id;"


def get_core_client(uri: str,
                    port: str):
    typedb_url = uri + ":" + port
    return TypeDB.core_driver(typedb_url)

def get_data_session(core_client: TypeDBDriver,
                     database: str):
    return core_client.session(database, SessionType.DATA)

def get_read_transaction(session: TypeDBSession):
    return session.transaction(TransactionType.READ)

def get_write_transaction(session: TypeDBSession):
    return session.transaction(TransactionType.WRITE)




def match_query(uri: str, port: str, database: str, query: str, data_query, **data_query_args):
    data = []
    try:
        with get_core_client(uri, port) as client:
            client_session = get_data_session(client, database)
            with client_session as session:
                read_transaction = get_read_transaction(session)
                with read_transaction as transaction:
                    answer_iterator = transaction.query.get(query)
                    data = data_query(query, answer_iterator, transaction, **data_query_args)
                    return data
    except Exception as e:
        logger.exception(e)
        raise Exception("Problem matching")

def get_all_databases(uri: str, port: str):
    client = get_core_client(uri, port)
    return client.databases.all()

def delete_database(uri: str, port: str, database: str):
    client = get_core_client(uri, port)
    if client.databases.contains(database):
       logger.info('Database ' + database + ' exists... deleting')
       client.databases.get(database).delete()
    else:
       logger.info('Database ' + database + ' does not exists... skipping')


def query_ids(query, generator, transaction, **data_query_args):
    logger.info(
        '\n\n-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------\n' + \
        '---------------------------------------------------------------------------------------- Query ids ------------------------------------------------------------------------------\n' + \
        '-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------\n')

    logger.info(query)

    number = 0
    ids = []
    for result in generator:
        ids.append(result.get("ids"))
        logger.info(
            '\nxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\n' + \
            'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx    Query IDs Concept Map ' + str(
                number) + 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\n' + \
            'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\n')
        for concept in enumerate(result.concepts()):
            if concept[1].is_type():
                logger.info('   Type:' + concept[1].as_type().get_label())
            if concept[1].is_relation():
                logger.info('   Relation: iid ' + concept[1].as_relation().get_iid())
            if concept[1].is_attribute():
                logger.info('   Attribute iid: ' + concept[1].as_attribute().get_iid())
                logger.info('           value: ' + str(concept[1].as_attribute().get_value()))
        number = number + 1

    logger.info('\n')

    return ids

def query_id(query, generator, transaction, **data_query_args):
    logger.info(
        '\n\n-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------\n' + \
        '---------------------------------------------------------------------------------------- Query ids ------------------------------------------------------------------------------\n' + \
        '-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------\n')

    logger.info(query)

    number = 0
    ids = []
    for result in generator:
        ids.append(result.get("id").get_value())
        logger.info(
            '\nxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\n' + \
            'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx    Query ID Concept Map ' + str(
                number) + 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\n' + \
            'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\n')
        for concept in enumerate(result.concepts()):
            if concept[1].is_type():
                logger.info('   Type:' + concept[1].as_type().get_label())
            if concept[1].is_relation():
                logger.info('   Relation: iid ' + concept[1].as_relation().get_iid())
            if concept[1].is_attribute():
                logger.info('   Attribute iid: ' + concept[1].as_attribute().get_iid())
                logger.info('           value: ' + str(concept[1].as_attribute().get_value()))
        number = number + 1

    logger.info('\n')

    return ids


def delete_layers(uri: str, port: str, database: str, instructions: Instructions):
    with get_core_client(uri, port) as client:
        client_session = get_data_session(client, database)
        with client_session as session:
            for instruction_id in instructions.get_ordered_ids():
                write_transaction = get_write_transaction(session)
                with write_transaction as transaction:
                    query = instructions.get_query_for_id(instruction_id)
                    result = delete_layer(transaction, query)
                    log_delete_layer(result, query)
                    instructions.update_delete_instruction_as_success(instruction_id)
    return instructions



def delete_layer(transaction: TypeDBTransaction, query: str):
    transaction_query: QueryManager = transaction.query
    query_future: Promise = transaction_query.delete(query)
    bi_d = query_future.resolve()
    logger.info(
        '\n\n-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------\n' + \
        '---------------------------------------------------------------------------------------- Delete Layer Query ------------------------------------------------------------------------------\n' + \
        '-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------\n')

    logger.info(query)

    logger.info(
        '\nxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\n' + \
        'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx    Delete Result ' + 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\n' + \
        'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\n')

    logger.info(str(bi_d))

    transaction.commit()


def add_layer(transaction: TypeDBTransaction, layer: str):
    transaction_query: QueryManager = transaction.query
    query_future: Iterator[ConceptMap] = transaction_query.insert(layer)

    logger.debug('\n\n-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------\n')
    logger.info('\n------------------------------------------------ Add Layer Query ----------------------------------------------\n')
    logger.debug('-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------\n')

    logger.info(layer)

    number = 0
    logger.info('\nxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx    Add Layer Response     xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\n')
    logger.info(f'insert_iterator response ->\n{query_future}')
    for result in query_future:
        logger.debug('\nxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\n' )
        logger.debug('\nxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx    Add Layer Concept Map ' + str(number) +      'xxxxxxxxxxxxxxxxxxxxxx\n')
        logger.debug('\nxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\n')

        logger.debug(f'typedb response ->\n{result}')

        for concept in enumerate(result.concepts()):
            if concept[1].is_type():
                logger.debug('   Type:' + concept[1].as_type().get_label())
            if concept[1].is_relation():
                logger.debug('   Relation: iid ' + concept[1].as_relation().get_iid() )
            if concept[1].is_attribute():
                logger.debug('   Attribute iid: ' + concept[1].as_attribute().get_iid())
                logger.debug('           value: ' + str(concept[1].as_attribute().get_value()))
        number = number + 1

    logger.info('\n\n')

    transaction.commit()


def add_instructions_to_typedb(uri: str, port: str, database: str, instructions: Instructions):
    try:
        with get_core_client(uri, port) as client:
            client_session = get_data_session(client, database)
            with client_session as session:
                for instruction_id in instructions.get_ordered_ids():
                    if instructions.not_allow_insertion(instruction_id):
                        continue
                    write_transaction = get_write_transaction(session)
                    with write_transaction as transaction:
                        query = instructions.get_query_for_id(instruction_id)
                        add_layer(transaction, query)
                        instructions.update_instruction_as_success(instruction_id)
    except Exception as e:
        traceback_str = traceback.format_exc()
        instructions.update_instruction_as_error(instruction_id, traceback_str)
    return instructions


