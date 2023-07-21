import logging
import re
import uuid

from collections import defaultdict

import ujson

from exceptions import DatabaseMismatch,UnknownViewname

from identifiers import makeid

DB_VERSION = "1.0"

logger = logging.getLogger(__name__)

def infer_type(key, value):
    if key == 'id':
        rtype = 'TEXT UNIQUE'
    elif key in ['number_observed', 'src_port', 'dst_port', 'x_firepit_rank']:
        rtype = 'INTEGER'
    elif key == 'ipfix.flowId':
        rtype = 'TEXT'  # Should be uint64, but that's not supported anywhere!
    elif isinstance(value, int):
        rtype = 'BIGINT'
    elif isinstance(value, float):
        rtype = 'REAL'
    elif isinstance(value, list):
        rtype = 'TEXT'
    else:
        rtype = 'TEXT'
    return rtype


def _format_query(query, dialect):
    query_text, query_values = query.render('{}', dialect)
    formatted_values = [f"'{v}'" if isinstance(v, str) else v for v in query_values]
    return query_text.format(*formatted_values)


class SqlStorage:
    def __init__(self):
        self.connection = None  # Python DB API connection object
        self.placeholder = '%s'  # Derived class can override this
        self.dialect = None      # Derived class can override this

        # Functions to use for min/max text.  It can vary - sqlite3
        # uses MIN/MAX, postgresql uses LEAST/GREATEST
        self.text_min = 'MIN'
        self.text_max = 'MAX'

        # Function that returns first non-null arg_type
        self.ifnull = 'IFNULL'

        # Python-to-SQL type mapper
        self.infer_type = infer_type

    def close(self):
        if self.connection:
            #logger.debug("Closing %s connection",
            #             self.connection.__class__.__module__.split('.', 1)[0])
            self.connection.close()

    def _get_writer(self, **kwargs):
        """Get a DB inserter object"""
        # This is DB-specific
        raise NotImplementedError('SqlStorage._get_writer')

    def _initdb(self, cursor):
        """Do some initial DB setup"""
        stmt = ('CREATE TABLE IF NOT EXISTS "__metadata" '
                '(name TEXT, value TEXT);')
        self._execute(stmt, cursor)

        '''
        stmt = ('CREATE TABLE IF NOT EXISTS "__symtable" '
                '(name TEXT, type TEXT, appdata TEXT,'
                ' UNIQUE(name));')
        self._execute(stmt, cursor)
        stmt = ('CREATE TABLE IF NOT EXISTS "__queries" '
                '(sco_id TEXT, query_id TEXT);')
        self._execute(stmt, cursor)
        stmt = ('CREATE TABLE IF NOT EXISTS "__contains" '
                '(source_ref TEXT, target_ref TEXT, x_firepit_rank,'
                ' UNIQUE(source_ref, target_ref) ON CONFLICT IGNORE);')
        self._execute(stmt, cursor)
        stmt = ('CREATE TABLE IF NOT EXISTS "__columns" '
                '(otype TEXT, path TEXT, shortname TEXT, dtype TEXT,'
                ' UNIQUE(otype, path));')
        
        self._execute(stmt, cursor)
        '''

        self._set_meta(cursor, 'dbversion', DB_VERSION)
        self.connection.commit()
        cursor.close()

    def _checkdb(self):
        dbversion = 0
        stmt = 'SELECT value FROM "__metadata" WHERE name = \'dbversion\''
        try:
            cursor = self._query(stmt)
        except UnknownViewname:
            raise DatabaseMismatch(dbversion, DB_VERSION)
        res = cursor.fetchone()
        dbversion = res['value'] if res else ""
        if dbversion != DB_VERSION:
            if self._migrate(dbversion, cursor):
                self._set_meta(cursor, 'dbversion', DB_VERSION)
            else:
                raise DatabaseMismatch(dbversion, DB_VERSION)

    def _migrate(self, _version, _cursor):
        return False

    def _set_meta(self, cursor, name, value):
        stmt = ('INSERT INTO "__metadata" (name, value)'
                f' VALUES ({self.placeholder}, {self.placeholder});')
        cursor.execute(stmt, (name, value))

    def _new_name(self, cursor, name, sco_type):
        stmt = ('INSERT INTO "__symtable" (name, type)'
                f' VALUES ({self.placeholder}, {self.placeholder})'
                ' ON CONFLICT (name) DO UPDATE SET type = EXCLUDED.type')
        cursor.execute(stmt, (name, sco_type))

    def _drop_name(self, cursor, name):
        stmt = f'DELETE FROM "__symtable" WHERE name = {self.placeholder};'
        cursor.execute(stmt, (name,))

    def _execute(self, statement, cursor=None):
        """Private wrapper for logging SQL statements"""
        logger.debug('Executing statement: %s', statement)
        if not cursor:
            cursor = self.connection.cursor()
        cursor.execute(statement)
        return cursor

    def _command(self, cmd, cursor=None):
        """Private wrapper for logging SQL commands"""
        logger.debug('Executing command: %s', cmd)
        if not cursor:
            cursor = self.connection.cursor()
        cursor.execute(cmd)
        self.connection.commit()

    def _query(self, query, values=None, cursor=None):
        """Private wrapper for logging SQL query"""
        logger.debug('Executing query: %s', query)
        if not cursor:
            cursor = self.connection.cursor()
        if not values:
            values = ()
        cursor.execute(query, values)
        self.connection.commit()
        return cursor

    def _select(self, tvname, cols="*", sortby=None, groupby=None,
                ascending=True, limit=None, offset=None, where=None):
        """Generate a SELECT query on table or view `tvname`"""

        if cols != "*":
            cols = ", ".join([f'"{col}"' if not col.startswith("'") else col for col in cols])

        stmt = f'SELECT {cols} FROM "{tvname}"'
        if where:
            stmt += f' WHERE {where}'

        if sortby:
            #validate_path(sortby)
            stmt += f' ORDER BY "{sortby}" ' + ('ASC' if ascending else 'DESC')
        if limit:
            if not isinstance(limit, int):
                raise TypeError('LIMIT must be an integer')
            stmt += f' LIMIT {limit}'
        if offset:
            if not isinstance(offset, int):
                raise TypeError('LIMIT must be an integer')
            stmt += f' OFFSET {offset}'
        return stmt

    def _create_index(self, tablename, cursor):
        if tablename in ['__contains', '__reflist', 'relationship']:
            for col in ['source_ref', 'target_ref']:
                self._execute(f'CREATE INDEX IF NOT EXISTS "{tablename}_{col}_idx" ON "{tablename}" ("{col}");', cursor)

    def _create_table(self, tablename, columns):
        stmt = f'CREATE TABLE "{tablename}" ('
        stmt += ','.join([f'"{colname}" {coltype}' for colname, coltype in columns.items()])
        stmt += ');'
        logger.debug('_create_table: "%s"', stmt)
        cursor = self._execute(stmt)
        self._create_index(tablename, cursor)
        self.connection.commit()
        cursor.close()

    def _add_column(self, tablename, prop_name, prop_type):
        stmt = f'ALTER TABLE "{tablename}" ADD COLUMN "{prop_name}" {prop_type};'
        logger.debug('new_property: "%s"', stmt)
        self._execute(stmt)

    def _create_view(self, viewname, select, sco_type, deps=None, cursor=None):
        # This is DB-specific
        raise NotImplementedError('Storage._create_view')

    def _recreate_view(self, viewname, viewdef, cursor):
        self._execute(f'DROP VIEW IF EXISTS "{viewname}"', cursor)
        self._execute(f'CREATE VIEW "{viewname}" AS {viewdef}', cursor)

    def _get_view_def(self, viewname):
        # This is DB-specific
        raise NotImplementedError('Storage._get_view_def')

    def _is_sql_view(self, name, cursor=None):
        ## This is DB-specific
        raise NotImplementedError('Storage._is_sql_view')


    def upsert(self, cursor, tablename, obj, query_id, schema):
        colnames = [k for k in list(schema.keys()) if k != 'type']
        excluded = self._get_excluded(colnames, tablename)
        valnames = ', '.join([f'"{x}"' for x in colnames])
        placeholders = ', '.join([self.placeholder] * len(colnames))
        stmt = f'INSERT INTO "{tablename}" ({valnames}) VALUES ({placeholders})'
        if 'id' in colnames:
            if excluded and tablename != 'observed-data':
                action = f'UPDATE SET {excluded}'
            else:
                action = 'NOTHING'
            stmt += f' ON CONFLICT (id) DO {action}'
        values = tuple([ujson.dumps(value, ensure_ascii=False)
                        if isinstance(value, (list, dict)) else value for value in obj])
        #logger.debug('_upsert: "%s", %s', stmt, values)
        cursor.execute(stmt, values)

        if query_id and 'id' in colnames:
            # Now add to query table as well
            idx = colnames.index('id')
            stmt = (f'INSERT INTO "__queries" (sco_id, query_id)'
                    f' VALUES ({self.placeholder}, {self.placeholder})')
            cursor.execute(stmt, (obj[idx], query_id))

    def upsert_many(self, cursor, tablename, objs, query_id, schema):
        for obj in objs:
            self.upsert(cursor, tablename, obj, query_id, schema)

    def cache(self, query_id, bundles, batchsize=2000, **kwargs):
        """Cache the result of a query/dataset

        Takes the `observed-data` SDOs from `bundles` and "flattens"
        them, splits out SCOs by type, and inserts into a database
        with 1 table per type.

        Accepts some keyword args for runtime options, some of which
        may depend on what database type is in use (e.g. sqlite3,
        postgresql, ...)

        Args:

          query_id (str): a unique identifier for this set of bundles

          bundles (list): STIX bundles (either in-memory Python objects or filename paths)

          batchsize (int): number of objects to insert in 1 batch (defaults to 2000)

        """
        logger.debug('Caching %s', query_id)

        if not isinstance(bundles, list):
            bundles = [bundles]

        writer = self._get_writer(**kwargs)
        splitter = SplitWriter(writer, batchsize=batchsize, query_id=str(query_id))

        # walk the bundles and figure out all the columns
        for bundle in bundles:
            if isinstance(bundle, str):
                logger.debug('- Caching %s', bundle)
            for obj in _transform(bundle):
                splitter.write(obj)
        splitter.close()


    def load(self, viewname, objects, sco_type=None, query_id=None, preserve_ids=True):
        """Import `objects` as type `sco_type` and store as `viewname`"""
        validate_name(viewname)
        if not query_id:
            # Look inside data
            if 'query_id' in objects[0]:
                query_id = objects[0]['query_id']
            else:
                query_id = str(uuid.uuid4())
        writer = self._get_writer(query_id=query_id)
        splitter = SplitWriter(writer, batchsize=1000, query_id=str(query_id))

        for obj in objects:
            if not sco_type:
                # objects MUST be dicts with a type
                if 'type' not in obj:
                    raise InvalidObject('missing `type`')
                sco_type = obj['type']
            if isinstance(obj, str):
                obj = {'type': sco_type, primary_prop(sco_type): obj}
            elif not isinstance(obj, dict):
                raise InvalidObject('Unknown data format')
            if 'type' not in obj:
                obj['type'] = sco_type
            if 'id' not in obj or not preserve_ids:
                obj['id'] = makeid(obj)
            splitter.write(obj)
        splitter.close()

        self.extract(viewname, sco_type, query_id, '')

        return sco_type



    def tables(self):
        """Get all table names"""
        # This is DB-specific
        raise NotImplementedError('Storage.tables')

    def types(self, private=False):
        """Get all table names that correspond to SCO types"""
        # This is DB-specific
        raise NotImplementedError('Storage.types')

    def views(self):
        """Get all view names"""
        stmt = 'SELECT name FROM __symtable'
        cursor = self._query(stmt)
        result = cursor.fetchall()
        return [row['name'] for row in result]


    def columns(self, viewname):
        """Get the column names (properties) of `viewname`"""
        # This is DB-specific
        raise NotImplementedError('Storage.columns')

    def schema(self, viewname=None):
        """
        Get the schema (names and types) of table/view `viewname` or all
        tables if not specified
        """
        # This is DB-specific
        raise NotImplementedError('Storage.schema')

    def delete(self):
        """Delete ALL data in this store"""
        # This is DB-specific
        raise NotImplementedError('Storage.delete')




    def finish(self, index=True):
        """Do any DB-specific post-caching/insertion activity, such as indexing"""
        # This is a DB-specific hook, but by default we'll do nothing
        pass




