import unittest
import json
import os
from stix.module.typedb import TypeDBSink, TypeDBSource
from stix.module.stix2typeql import stix2_to_typeql
from typedb.client import *

import glob
from hamcrest import *
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
        cls._typedbSink = TypeDBSink(connection=connection, clear=True, import_type="Stix21")
        cls._typedbSource = TypeDBSource(connection=connection, import_type="Stix21")

        cls._example = "./data/examples/"

    @classmethod
    def tearDownClass(cls):
        pass

    def test_markings(self):

        self.assertTrue(os.path.exists(self._example))

        filename = './data/examples/marking_definitions.json'

        with self.assertRaises(Exception):
            logger.info(f'Loading file {filename}')
            with open(filename,mode="r", encoding="utf-8") as file:
                stix_dict = json.load(file)
                stix_obj = parse(stix_dict)
                self._typedbSink.add(stix_obj)

    def test_others(self):

        self.assertTrue(os.path.exists(self._example))

        for filename in glob.glob(self._example + '*.json'):
            logger.info(f'Testing file {filename}')
            with open(filename, mode="r", encoding="utf-8") as file:
                if filename.endswith('marking_definitions.json'):
                    continue
                else:
                    json_blob = json.load(file)

                    if isinstance(json_blob, list):
                        for item in json_blob:
                            stix_obj = parse(item)
                            self._typedbSink.add(stix_obj)
                            return_dict = self._typedbSource.get(stix_obj.id)
                            return_obj = parse(return_dict)
                            assert_that(stix_obj, equal_to(return_obj))
                    else:
                        bundle = parse(json_blob)
                        for stix_obj in bundle.objects:
                            self._typedbSink.add(stix_obj)
                            return_dict = self._typedbSource.get(stix_obj.id)
                            return_obj = parse(return_dict)
                            assert_that(stix_obj, equal_to(return_obj))

if __name__ == '__main__':
    unittest.main()
