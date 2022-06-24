import unittest
import json
import os
from stix.module.typedb import TypeDBSink, TypeDBSource
from stix.module.stix2typeql import stix2_to_typeql
from typedb.client import *


from loguru import logger

from stix2 import (v21, parse)

# define the database data and import details
connection = {
    "uri": "localhost",
    "port": "1729",
    "database": "stix2",
    "user": None,
    "password": None
}


class TestDatabase(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls._typedb =  TypeDBSink(connection = connection, clear=True, import_type="Stix21")
        cls._example = "./data/examples/"

    @classmethod
    def tearDownClass(cls):
       pass

    def test_folder(self):
        self.assertTrue(os.path.exists(self._example))
        #self.assertEqual('foo'.upper(), 'FOO')

if __name__ == '__main__':
    unittest.main()