import json
from stixorm.module.typedb import TypeDBSink, TypeDBSource
from stixorm.module.authorise import import_type_factory
from stixorm.module.parsing.parse_objects import parse
import logging
logger = logging.getLogger(__name__)

import_type = import_type_factory.get_attack_import()
logging.basicConfig(level=logging.DEBUG, format='[%(asctime)s] %(levelname)s [%(name)s:%(lineno)s] %(message)s')
logger = logging.getLogger(__name__)


connection = {
    "uri": "localhost",
    "port": "1729",
    "database": "stix",
    "user": None,
    "password": None
}


def test_initialise():
    """
        Initialise the Database
    """
    typedb = TypeDBSink(connection, True, import_type)


def load_file(fullname):
    """
        Load a single file, containing either a list or bundle
    Args:
        fullname ():
    """
    with open(fullname, mode="r", encoding="utf-8") as f:
        json_text = json.load(f)
        typedb = TypeDBSink(connection, True, import_type)
        typedb.add(json_text)


# if this file is run directly, then start here
if __name__ == '__main__':

    std_path = "test/data/standard/"
    file1 = 'file_basic.json'  # hashes example
    file2 = 'x509_cert_v3_ext.json' # extension
    file2b = 'email_mime.json' # extensions, sub-object

    ex_path = "test/data/examples/"
    file4 = "attack_pattern_malware.json"  # list of objects

    report_data = "data/threat_reports/"
    file5 = "apt1.json"

    #test_initialise()
    load_file(report_data + file5)
