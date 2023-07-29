import logging
import os
import re
from functools import lru_cache

import psycopg2
import psycopg2.extras
import ujson

from exceptions import DuplicateTable
from exceptions import InvalidAttr
from exceptions import UnexpectedError
from exceptions import UnknownViewname
from pgcommon import (CHECK_FOR_COMMON_SCHEMA, CHECK_FOR_CACHE_TABLE,INTERNAL_TABLES,_rewrite_view_def, _infer_type, pg_shorten)

from sqlstorage import SqlStorage, DB_VERSION

logger = logging.getLogger()


def get_storage(url, session_id):
    dbname = url.path.lstrip('/')
    return PgStorage(dbname, url.geturl(), session_id)

# PostgreSQL defaults for COPY text format
SEP = '\t'
TEXT_ESCAPE_TABLE = str.maketrans({
    '\\': '\\\\',
    '\n': '\\n',
    '\r': '\\r',
    SEP: f'\\{SEP}'
})


@lru_cache(maxsize=256, typed=True)
def _text_encode(value):
    if value is None:
        return r'\N'
    elif not isinstance(value, str):
        return str(value)
    # MUST "escape" special chars
    return value.translate(TEXT_ESCAPE_TABLE)


class ListToTextIO:
    """
    Convert an iterable of lists into a file-like object with
    PostgreSQL TEXT formatting
    """

    def __init__(self, objs, cols, sep=SEP):
        self.it = iter(objs)
        self.cols = cols
        self.sep = sep
        self.buf = ''

    def read(self, n):
        result = ''
        try:
            while n > len(self.buf):
                obj = next(self.it)
                vals = [ujson.dumps(val, ensure_ascii=False) if isinstance(val, (list, dict))
                        else _text_encode(val) for val in obj]
                self.buf += self.sep.join(vals) + '\n'
            result = self.buf[:n]
            self.buf = self.buf[n:]
        except StopIteration:
            result = self.buf
            self.buf = ''
        return result


class TuplesToTextIO:
    """
    Convert an iterable of tuples into a file-like object
    """

    def __init__(self, objs, cols, sep=SEP):
        self.it = iter(objs)
        self.cols = cols
        self.sep = sep
        self.buf = ''

    def read(self, n):
        result = ''
        try:
            while n > len(self.buf):
                obj = next(self.it)
                self.buf += self.sep.join(obj)
                self.buf += '\n'
            result = self.buf[:n]
            self.buf = self.buf[n:]
        except StopIteration:
            result = self.buf
            self.buf = ''
        return result


class PgStorage(SqlStorage):
    def __init__(self, dbname, url, session_id=None):
        super().__init__()
        self.placeholder = '%s'
        self.dialect = 'postgresql'
        self.text_min = 'LEAST'
        self.text_max = 'GREATEST'
        self.ifnull = 'COALESCE'
        self.dbname = dbname
        self.infer_type = _infer_type
        self.defer_index = False
        if not session_id:
            session_id = 'stixorm'
        self.session_id = session_id
        options = f'options=--search-path%3D{session_id}'
        sep = '&' if '?' in url else '?'
        connstring = f'{url}{sep}{options}'
        self.connection = psycopg2.connect(
            connstring,
            cursor_factory=psycopg2.extras.RealDictCursor)

        self._create_stixorm_common_schema()
        if session_id:
            try:
                self._execute(f'CREATE SCHEMA IF NOT EXISTS "{session_id}";')
                # how to check if schema exists
            except psycopg2.errors.UniqueViolation:
                self.connection.rollback()

        self._execute(f'SET search_path TO "{session_id}", stixorm_common;')

        res = self._query(CHECK_FOR_CACHE_TABLE, (session_id,)).fetchone()
        done = list(res.values())[0] if res else False
        if not done:
            self._setup()
        else:
            self._checkdb()

        logger.debug("Connection to PostgreSQL DB %s successful", dbname)

    def _create_stixorm_common_schema(self):
        try:
            res = self._query(CHECK_FOR_COMMON_SCHEMA).fetchall()
            #TODO: put future schema
        except psycopg2.errors.DuplicateFunction:
            self.connection.rollback()

    def _setup(self):
        cursor = self._execute('BEGIN;')
        try:
            # Do DB initization from base class
            for stmt in INTERNAL_TABLES:
                self._execute(stmt, cursor)

            # Record db version
            self._set_meta(cursor, 'dbversion', DB_VERSION)

            self.connection.commit()
            cursor.close()
        except (psycopg2.errors.DuplicateFunction, psycopg2.errors.UniqueViolation):
            # We probably already created all these, so ignore this
            self.connection.rollback()

    def _query(self, query, values=None, cursor=None):
        """Private wrapper for logging SQL query"""
        logger.debug('Executing query: %s', query)
        if not cursor:
            cursor = self.connection.cursor()
        if not values:
            values = ()
        try:
            cursor.execute(query, values)
        except psycopg2.errors.UndefinedColumn as e:
            self.connection.rollback()
            raise InvalidAttr(str(e)) from e
        except psycopg2.errors.UndefinedTable as e:
            self.connection.rollback()
            raise UnknownViewname(str(e)) from e
        except Exception as e:
            self.connection.rollback()
            logger.error('%s: %s', query, e, exc_info=e)
            raise UnexpectedError(str(e)) from e
        self.connection.commit()
        return cursor

    def _create_table(self, tablename, columns):
        # Same as base class, but disable WAL
        stmt = f'CREATE UNLOGGED TABLE "{tablename}" ('
        stmt += ','.join([f'"{colname}" {coltype}' for colname, coltype in columns.items()])
        stmt += ');'
        logger.debug('_create_table: "%s"', stmt)
        try:
            cursor = self._execute(stmt)
            if not self.defer_index:
                self._create_index(tablename, cursor)
            self.connection.commit()
            cursor.close()
        except (psycopg2.errors.DuplicateTable,
                psycopg2.errors.DuplicateObject,
                psycopg2.errors.UniqueViolation) as e:
            self.connection.rollback()
            raise DuplicateTable(tablename) from e

    def _add_column(self, tablename, prop_name, prop_type):
        stmt = f'ALTER TABLE "{tablename}" ADD COLUMN "{prop_name}" {prop_type};'
        logger.debug('new_property: "%s"', stmt)
        try:
            cursor = self._execute(stmt)
            self.connection.commit()
            cursor.close()
        except psycopg2.errors.DuplicateColumn:
            self.connection.rollback()

        # update all relevant viewdefs
        stmt = 'SELECT name, type FROM __symtable'
        cursor = self._query(stmt, (tablename,))
        rows = cursor.fetchall()
        for row in rows:
            logger.debug('%s', row)
        stmt = 'SELECT name FROM __symtable WHERE type = %s'
        cursor = self._query(stmt, (tablename,))
        rows = cursor.fetchall()
        for row in rows:
            viewname = row['name']
            viewdef = self._get_view_def(viewname)
            self._execute(f'CREATE OR REPLACE VIEW "{viewname}" AS {viewdef}', cursor)


    def _is_sql_view(self, name, cursor=None):
        cursor = self._query("SELECT definition"
                             " FROM pg_views"
                             " WHERE schemaname = %s"
                             " AND viewname = %s", (self.session_id, name))
        viewdef = cursor.fetchone()
        return viewdef is not None

    def tables(self):
        cursor = self._query("SELECT table_name"
                             " FROM information_schema.tables"
                             " WHERE table_schema = %s"
                             "   AND table_type != 'VIEW'", (self.session_id, ))
        rows = cursor.fetchall()
        return [i['table_name'] for i in rows
                if not i['table_name'].startswith('__')]

    def types(self, private=False):
        stmt = ("SELECT table_name FROM information_schema.tables"
                " WHERE table_schema = %s AND table_type != 'VIEW'"
                "  EXCEPT SELECT name as table_name FROM __symtable")
        cursor = self._query(stmt, (self.session_id, ))
        rows = cursor.fetchall()
        if private:
            return [i['table_name'] for i in rows]
        # Ignore names that start with 1 or 2 underscores
        return [i['table_name'] for i in rows
                if not i['table_name'].startswith('_')]

    def delete(self):
        """Delete ALL data in this store"""
        cursor = self._execute('BEGIN;')
        self._execute(f'DROP SCHEMA "{self.session_id}" CASCADE;', cursor)
        self.connection.commit()
        cursor.close()

    def write_objects(self, objects):
        try:
            cursor = self.connection.cursor()
            cursor.execute('BEGIN')
            for object in objects:
                tablename = f'{object.type}'

                if object.type in self.tables():

                    stmt = f'INSERT INTO "{tablename}" (id,created,modified) VALUES ({self.placeholder}, {self.placeholder}, {self.placeholder})'
                    cursor.execute(stmt,(object['id'],str(object['created']),str(object['modified'])))
                    logger.debug(stmt)
            cursor.execute('COMMIT')
        finally:
            cursor.close()

    def read_records(self,obj_type):
        if obj_type in self.tables():
            stmt = f'SELECT * FROM "{obj_type}";'
            values = None
            cursor = self._query(stmt, values)
            res = cursor.fetchall()
            cursor.close()
            return res

    def upsert_many(self, cursor, tablename, objs, query_id, schema, **kwargs):
        use_copy = kwargs.get('use_copy')
        if use_copy:
            self.upsert_copy(cursor, tablename, objs, query_id, schema)
        else:
            self.upsert_multirow(cursor, tablename, objs, query_id, schema)

    def upsert_multirow(self, cursor, tablename, objs, query_id, schema):
        colnames = list(schema.keys())
        quoted_colnames = [f'"{x}"' for x in colnames]
        valnames = ', '.join(quoted_colnames)

        placeholders = ', '.join([f"({', '.join([self.placeholder] * len(colnames))})"] * len(objs))
        stmt = f'INSERT INTO "{tablename}" ({valnames}) VALUES {placeholders}'
        idx = None
        if 'id' in colnames:
            idx = colnames.index('id')
            action = 'NOTHING'
            if tablename != 'identity':
                excluded = self._get_excluded(colnames, tablename)
                if excluded:
                    action = f'UPDATE SET {excluded}'
            stmt += f' ON CONFLICT (id) DO {action}'
        else:
            stmt += ' ON CONFLICT DO NOTHING'
        values = []
        query_values = []
        for obj in objs:
            if query_id and idx is not None:
                query_values.append(obj[idx])
                query_values.append(query_id)
            values.extend([ujson.dumps(value, ensure_ascii=False)
                           if isinstance(value, (list, dict)) else value for value in obj])
        cursor.execute(stmt, values)

        if query_id and 'id' in colnames:
            # Now add to query table as well
            placeholders = ', '.join([f'({self.placeholder}, {self.placeholder})'] * len(objs))
            stmt = (f'INSERT INTO "__queries" (sco_id, query_id)'
                    f' VALUES {placeholders}')
            cursor.execute(stmt, query_values)


    def finish(self, index=True):
        if index:
            cursor = self._query("SELECT table_name"
                                 " FROM information_schema.tables"
                                 " WHERE table_schema = %s"
                                 "   AND table_name IN (%s, %s)", (self.session_id, '__contains', '__reflist'))
            rows = cursor.fetchall()
            tables = [i['table_name'] for i in rows]
            cursor = self._execute('BEGIN;')
            if 'relationship' in self.tables():
                tables.append('relationship')
            for tablename in tables:
                self._create_index(tablename, cursor)
            self.connection.commit()
            cursor.close()
