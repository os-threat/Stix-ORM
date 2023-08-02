"""
Some common PostgreSQL stuff used by both pgstorage.py (the normal
interface) and aio.asyncpgstorage.py (the async interface).
"""

import logging
import re
import uuid
from collections import defaultdict

from sqlstorage import infer_type

logger = logging.getLogger()

CHECK_FOR_COMMON_SCHEMA = (
    "SELECT routines.routine_name"
    " FROM information_schema.routines"
    " WHERE routines.specific_schema = 'stixorm_common'"
)


CHECK_FOR_CACHE_TABLE = (
    "SELECT (EXISTS (SELECT *"
    " FROM INFORMATION_SCHEMA.TABLES"
    " WHERE TABLE_SCHEMA = %s"
    " AND  TABLE_NAME = 'feeds'))"
)

METADATA_TABLE = ('CREATE UNLOGGED TABLE IF NOT EXISTS "__metadata" '
                  '(name TEXT, value TEXT)')

# Our cache of objects
FEEDS_TABLE = ('CREATE UNLOGGED TABLE "feeds" ('
            ' "id" TEXT UNIQUE,'
            ' "created" TEXT,'
            ' "modified" TEXT'
            ')')

FEED_TABLE = ('CREATE UNLOGGED TABLE "feed" ('
            ' "id" TEXT UNIQUE,'
            ' "created" TEXT,'
            ' "modified" TEXT'
            ')')

INTERNAL_TABLES = [
    METADATA_TABLE,
    FEEDS_TABLE,
    FEED_TABLE
]

def _infer_type(key, value):
    # PostgreSQL type specializations
    rtype = None
    if isinstance(value, bool):
        rtype = 'BOOLEAN'
    elif key in ('src_byte_count', 'dst_byte_count'):
        rtype = 'NUMERIC'  # Support data sources using uint64
    else:
        # Fall back to defaults
        rtype = infer_type(key, value)
    return rtype


def _rewrite_select(stmt):
    p = r"SELECT (DISTINCT )?(\"observed-data\".[\w_]+\W+)?(\"?[\w\d_-]+\"?\.\"?['\w\d\._-]+\"?,?\W+)+FROM"
    m = re.search(p, stmt)
    if m:
        matched = m.group(0).split()[1:-1]  # Drop SELECT and FROM
        if matched[0].strip() == 'DISTINCT':
            distinct = 'DISTINCT '
        else:
            distinct = ''
        data = defaultdict(list)
        order = []
        for i in matched:
            table, _, column = i.partition('.')
            column = column.rstrip(',')
            data[table].append(column)
            if table not in order and not table.startswith('DISTINCT'):
                order.append(table)
        new_cols = []
        for table in order:
            num = len(data[table])
            if num > 1:
                new_cols.append(f'{table}.*')
            elif num == 1:
                col = data[table][0]
                new_cols.append(f'{table}.{col}')
        repl = f'SELECT {distinct}' + ', '.join(new_cols) + ' FROM'
        stmt = re.sub(p, repl, stmt, count=1)
    return stmt


def _rewrite_query(qry):
    parts = qry.split('UNION')
    new_parts = []
    for part in parts:
        new_parts.append(_rewrite_select(part).strip())
    return ' UNION '.join(new_parts)


def _rewrite_view_def(viewname, viewdef):
    if viewdef:
        stmt = viewdef['definition'].rstrip(';').replace('\n', ' ')

        # PostgreSQL will "expand" the original "*" to the columns
        # that existed at that time.  We need to get the star back, to
        # match SQLite3's behavior.
        logger.debug('%s original:  %s', viewname, stmt)
        stmt = _rewrite_query(stmt)
        logger.debug('%s rewritten: %s', viewname, stmt)
        return stmt

    # Must be a table
    return f'SELECT * FROM "{viewname}"'


FIREPIT_NS = uuid.UUID('{c55c83a6-06d3-4680-b1e0-1cfd1deb332d}')

def pg_shorten(key):
    key = re.sub(r"^extensions\.'(x-)?([\w\d_-]+)'\.", "x_", key)
    if len(key) > 48:
        # Still too long
        key = uuid.uuid5(FIREPIT_NS, key).hex
    return key
