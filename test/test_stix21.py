import unittest
import json
import os
from stix.module.typedb import TypeDBSink, TypeDBSource
from stix.module.stix2typeql import stix2_to_typeql
from typedb.client import *

import glob

import logging
logging.basicConfig(level = logging.INFO,format = '[%(asctime)s] %(levelname)s [%(name)s:%(lineno)s] %(message)s')
logger = logging.getLogger(__name__)

from stix2 import (v21, parse)

# define the database data and import details
connection = {
    "uri": "localhost",
    "port": "1729",
    "database": "stix2",
    "user": None,
    "password": None
}

os.environ['LOGURU_LEVEL'] = 'info'

class TestDatabase(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        '''
        Create a connection to the database and reset it
        '''
        cls._typedb =  TypeDBSink(connection = connection, clear=True, import_type="Stix21")
        cls._example = "./data/examples/"

    @classmethod
    def tearDownClass(cls):
       pass

    def test_insert_errors(self):

        self.assertTrue(os.path.exists(self._example))

        for filename in glob.glob(self._example+'*.json'):
            with open(filename,'r') as file:
                logger.info(f'Loading file {filename}')
                stix_dict = json.load(file)
                try:
                    self._typedb.add(stix_dict)
                except Exception as e:
                    self.fail(e)

if __name__ == '__main__':
    unittest.main()