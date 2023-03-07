import logging
from typing import List

from returns.io import impure_safe, IOResult
from returns.methods import unwrap_or_failure
from returns.pipeline import is_successful
from returns.result import safe
from returns.unsafe import unsafe_perform_io
from typedb.api.connection.client import TypeDBClient
from typedb.api.connection.session import SessionType, TypeDBSession
from typedb.api.connection.transaction import TransactionType
from typedb.client import TypeDB

from stix.module.typedb_lib.logging import log_delete_layer, log_add_layer
from stix.module.typedb_lib.instructions import Instructions

logger = logging.getLogger(__name__)


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
    logger.info(f'\n match_tql string?-> {match_tql}')
    logger.info(f'\n insert_tql string?-> {insert_tql}')
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
            return IOResult.failure(client_session.failure())
        with client_session.unwrap() as session:
            read_transaction = unsafe_perform_io(get_read_transaction(session))
            if not is_successful(read_transaction):
                return IOResult.failure(read_transaction.failure())
            with read_transaction.unwrap() as transaction:
                answer_iterator = transaction.query().match(query)
                data = data_query(answer_iterator, transaction, **data_query_args)
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

def query_ids(generator, transaction, **data_query_args):
    return [ans.get("ids") for ans in generator]

def query_id(generator, transaction, **data_query_args):
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
def delete_layer(transaction, query):
    query_future = transaction.query().delete(query)
    logger.info(f'delete_iterator response ->\n{query_future}')
    for result in query_future:
        logger.info(f'typedb response ->\n{result}')
    transaction.commit()

@impure_safe
def add_layer(transaction, layer):
    query_future = transaction.query().insert(layer)
    logger.info(f'insert_iterator response ->\n{query_future}')
    for result in query_future:
        logger.info(f'typedb response ->\n{result}')
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


