import logging
import traceback
from typing import List, Iterator

from returns.io import impure_safe, IOResult
from returns.methods import unwrap_or_failure
from returns.pipeline import is_successful
from returns.result import safe
from returns.unsafe import unsafe_perform_io
from typedb.api.answer.concept_map import ConceptMap
from typedb.api.connection.client import TypeDBClient
from typedb.api.connection.session import SessionType, TypeDBSession
from typedb.api.connection.transaction import TransactionType, TypeDBTransaction
from typedb.api.query.future import QueryFuture
from typedb.api.query.query_manager import QueryManager
from typedb.client import TypeDB
from typedb.stream.bidirectional_stream import BidirectionalStream

from stixorm.module.typedb_lib.logging import log_delete_layer, log_add_layer
from stixorm.module.typedb_lib.instructions import Instructions

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


@safe
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
    #logger.info(f'\n match_tql string?-> {match_tql}')
    #logger.info(f'\n insert_tql string?-> {insert_tql}')
    typeql_string = match_tql + insert_tql

    insertion_is_empty = len(insert_tql) == 0
    if insertion_is_empty:
        return None
    return typeql_string

@safe
def build_match_id_query(stix_ids: List[str]):
    get_ids_tql = 'match $id isa stix-id;'
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
    return get_ids_tql

@safe
def get_core_client(uri: str,
                    port: str):
    typedb_url = uri + ":" + port
    return TypeDB.core_client(typedb_url)

@impure_safe
def get_data_session(core_client: TypeDBClient,
                     database: str):
    return core_client.session(database, SessionType.DATA)

@impure_safe
def get_read_transaction(session: TypeDBSession):
    return session.transaction(TransactionType.READ)

@impure_safe
def get_write_transaction(session: TypeDBSession):
    return session.transaction(TransactionType.WRITE)




@impure_safe
def match_query(uri: str, port: str, database: str, query: str, data_query, **data_query_args):
    data = []
    with get_core_client(uri, port).unwrap() as client:
        client_session = unsafe_perform_io(get_data_session(client, database))
        if not is_successful(client_session):
            logging.exception("\n".join(traceback.format_exception(client_session.failure())))
            return IOResult.failure(client_session.failure())
        with client_session.unwrap() as session:
            read_transaction = unsafe_perform_io(get_read_transaction(session))
            if not is_successful(read_transaction):
                logging.exception("\n".join(traceback.format_exception(read_transaction.failure())))
                return IOResult.failure(read_transaction.failure())
            with read_transaction.unwrap() as transaction:
                answer_iterator = transaction.query().match(query)
                data = data_query(query, answer_iterator, transaction, **data_query_args)
                return data

@impure_safe
def delete_database(uri: str, port: str, database: str):
    with get_core_client(uri, port).unwrap() as client:
        client_session = unsafe_perform_io(get_data_session(client, database))
        if not is_successful(client_session):
            return IOResult.failure(client_session.failure())
        with client_session.unwrap() as session:
            read_transaction = unsafe_perform_io(get_read_transaction(session))
            if not is_successful(read_transaction):
                return IOResult.failure(read_transaction.failure())
            session.database().delete()

def query_ids(query, generator, transaction, **data_query_args):
    logger.info(
        '\n\n-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------\n' + \
        '---------------------------------------------------------------------------------------- Query ids ------------------------------------------------------------------------------\n' + \
        '-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------\n')

    logger.info(query)

    number = 0
    for result in generator:
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

    return [ans.get("ids") for ans in generator]

def query_id(query, generator, transaction, **data_query_args):
    logger.info(
        '\n\n-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------\n' + \
        '---------------------------------------------------------------------------------------- Query ids ------------------------------------------------------------------------------\n' + \
        '-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------\n')

    logger.info(query)

    number = 0
    for result in generator:
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

    return [ans.get("id").get_value() for ans in generator]

@impure_safe
def delete_layers(uri: str, port: str, database: str, instructions: Instructions):
    with get_core_client(uri, port).unwrap() as client:
        client_session = unsafe_perform_io(get_data_session(client, database))
        if not is_successful(client_session):
            return IOResult.failure(client_session.failure())
        with client_session.unwrap() as session:
            for instruction_id in instructions.get_ordered_ids():
                write_transaction = unsafe_perform_io(get_write_transaction(session))
                if not is_successful(write_transaction):
                    return IOResult.failure(write_transaction.failure())
                with write_transaction.unwrap() as transaction:
                    query = instructions.get_query_for_id(instruction_id)
                    result = delete_layer(transaction, query)
                    log_delete_layer(result, query)
                    if is_successful(result):
                        instructions.update_delete_instruction_as_success(instruction_id)
                    else:
                        instructions.update_delete_instruction_as_error(instruction_id, str(result.failure()))
    return instructions


@impure_safe
def delete_layer(transaction: TypeDBTransaction, query: str):
    transaction_query: QueryManager = transaction.query()
    query_future: QueryFuture = transaction_query.delete(query)
    bi_d: BidirectionalStream = query_future.get()
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

@impure_safe
def add_layer(transaction: TypeDBTransaction, layer: str):
    transaction_query: QueryManager = transaction.query()
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

@impure_safe
def add_instructions_to_typedb(uri: str, port: str, database: str, instructions: Instructions):
    with get_core_client(uri, port).unwrap() as client:
        client_session = unsafe_perform_io(get_data_session(client, database))
        if not is_successful(client_session):
            return IOResult.failure(client_session.failure())
        with client_session.unwrap() as session:
            for instruction_id in instructions.get_ordered_ids():
                if instructions.not_allow_insertion(instruction_id):
                    continue
                write_transaction = unsafe_perform_io(get_write_transaction(session))
                if not is_successful(write_transaction):
                    return IOResult.failure(write_transaction.failure())
                with write_transaction.unwrap() as transaction:
                    query = instructions.get_query_for_id(instruction_id)
                    result = add_layer(transaction, query)
                    log_add_layer(result, query)
                    if is_successful(result):
                        instructions.update_instruction_as_success(instruction_id)
                    else:
                        instructions.update_instruction_as_error(instruction_id, str(result.failure()))
    return instructions

