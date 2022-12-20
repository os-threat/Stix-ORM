import logging

from returns.io import impure_safe, IOResult
from returns.pipeline import is_successful
from returns.result import safe
from returns.unsafe import unsafe_perform_io
from typedb.api.connection.client import TypeDBClient
from typedb.api.connection.session import SessionType, TypeDBSession
from typedb.api.connection.transaction import TransactionType
from typedb.client import TypeDB

from stix.module.type_db_logging import log_delete_layer

logger = logging.getLogger(__name__)

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
    logger.debug(f' Matching query on db {database}')
    logger.debug(f' typeql -->: {query}')

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

@impure_safe
def delete_layers(uri: str, port: str, database: str, layers: list):
    with get_core_client(uri, port).unwrap() as client:
        client_session = unsafe_perform_io(get_data_session(client, database))
        if not is_successful(client_session):
            return IOResult.failure(client_session.failure())
        with client_session.unwrap() as session:
            for layer in layers:
                write_transaction = unsafe_perform_io(get_write_transaction(session))
                if not is_successful(write_transaction):
                    return IOResult.failure(write_transaction.failure())
                with write_transaction.unwrap() as transaction:

                    result = delete_layer(transaction, layer)
                    log_delete_layer(result)


@impure_safe
def delete_layer(transaction, layer):
    query_future = transaction.query().delete(layer["delete"])
    transaction.commit()
