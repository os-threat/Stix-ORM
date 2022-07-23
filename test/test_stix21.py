import unittest
import json
import os
from stix.module.typedb import TypeDBSink, TypeDBSource
from stix.module.stix2typeql import stix2_to_typeql
from typedb.client import *

import glob

import logging

logging.basicConfig(level=logging.INFO, format='[%(asctime)s] %(levelname)s [%(name)s:%(lineno)s] %(message)s')
logger = logging.getLogger(__name__)

from stix2 import (v21, parse)
from .dbconfig import *

os.environ['LOGURU_LEVEL'] = 'info'


class TestDatabase(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        '''
        Create a connection to the database and reset it
        '''
        cls._typedb = TypeDBSink(connection=connection, clear=True, import_type="Stix21")
        cls._example = "./data/examples/"

    @classmethod
    def tearDownClass(cls):
        pass

    def test_markings(self):

        self.assertTrue(os.path.exists(self._example))

        filename = './data/examples/marking_definitions.json'

        with self.assertRaises(TypeError):
            logger.info(f'Loading file {filename}')
            stix_dict = json.load(filename)
            self._typedb.add(stix_dict)

    def test_others(self):

        self.assertTrue(os.path.exists(self._example))

        for filename in glob.glob(self._example + '*.json'):
            with open(filename, 'r') as file:
                if filename.endswith('marking_definitions.json'):
                    continue
                else:
                    stix_dict = json.load(file)
                    logger.info(f'Loading file {filename}')
                    try:
                        self._typedb.add(stix_dict)
                    except Exception as e:
                        self.fail(e)


if __name__ == '__main__':
    unittest.main()
