import os
from exceptions import SessionExists, SessionNotFound
import re
from importlib import import_module
from urllib.parse import urlparse

def get_storage(url, session_id=None):
    """
    Get a storage object for firepit.  `url` will determine the type; a file path means sqlite3.
    `session_id` is used in the case of postgresql to partition your data.
    """
    url = re.sub(r'^.*postgresql://', 'postgresql://', url)  # Ugly hack for kestrel
    url = urlparse(url)
    if url.scheme == 'postgresql':
        module = import_module('pgstorage')
        return module.get_storage(url, session_id)
    if url.scheme in ['sqlite3', '']:
        module = import_module('sqlitestorage')
        return module.get_storage(url.path)
    raise NotImplementedError(url.scheme)


def tmp_storage(tmpdir, clear=True):
    dbname = os.getenv('STIXORM_DB', str(tmpdir.join('test.db')))
    session = os.getenv('STIXORM_ID', 'test-session')

    if clear:
        # Clear out previous test session
        store = get_storage(dbname, session)
        store.delete()

    return get_storage(dbname, session)