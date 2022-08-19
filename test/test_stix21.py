import unittest
import json
import os
from stix.module.typedb import TypeDBSink, TypeDBSource
from stix.module.import_stix_to_typeql import stix2_to_typeql
from typedb.client import *

import glob
from hamcrest import *
import logging

logging.basicConfig(level=logging.INFO, format='[%(asctime)s] %(levelname)s [%(name)s:%(lineno)s] %(message)s')
logger = logging.getLogger(__name__)

from stix2 import (v21, parse)
from .dbconfig import *

class StixComparator(object):

    def property_check(self,a,b,key,property_type):
        if property_type == 'ListProperty':
            if sorted(a._inner[key]) == sorted(b._inner[key]):
                return True
            else:
                return False
        elif property_type == 'StringProperty':
            return a._inner[key] == b._inner[key]
        elif property_type == 'StringProperty':
            return a._inner[key] == b._inner[key]
        elif property_type == 'BooleanProperty':
            return a._inner[key] == b._inner[key]
        elif property_type == 'TimestampProperty':
            return a._inner[key] == b._inner[key]
        elif property_type == 'ReferenceProperty':
            return a._inner[key] == b._inner[key]
        elif property_type == 'IDProperty':
            return a._inner[key] == b._inner[key]
        elif property_type == 'TypeProperty':
            return a._inner[key] == b._inner[key]
        elif property_type == 'OpenVocabProperty':
            return a._inner[key] == b._inner[key]
        elif property_type == 'PatternProperty':
            return a._inner[key] == b._inner[key]
        else: raise NotImplementedError(f'Property type {property_type} not considered')

    def compare(self,a,b):
        if a._type != b._type:
            return False,[]
        else:
            common_properties = a._properties.keys() & b._properties.keys()

            equals = []
            not_equals = []
            for property_name in common_properties:
                a_type = a._properties[property_name]
                b_type = b._properties[property_name]
                a_class = a_type.__class__.__name__
                b_class = b_type.__class__.__name__

                if a_class != b_class:
                    logger.debug(f'Property {property_name} has different class')
                    return False
                if property_name in a._inner and property_name in b._inner:
                    a_obj = a._inner[property_name]
                    b_obj = b._inner[property_name]
                    is_equal = self.property_check(a,b,property_name,a_class)
                    if is_equal: equals.append(property_name)
                    else: not_equals.append(property_name)
                elif property_name in a._inner and property_name not in b._inner:
                    logger.debug(f'Property {property_name} not available in a')
                    not_equals.append(property_name)
                elif property_name in b._inner and property_name not in a._inner:
                    logger.debug(f'Property {property_name} not available in a')
                    not_equals.append(property_name)
                else:
                    logger.debug(f'Property {property_name} not available in both objects')
                    continue

            return len(not_equals)==0,equals,not_equals

class TestDatabase(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        '''
        Create a connection to the database and reset it
        '''
        cls._typedbSink = TypeDBSink(connection=connection, clear=True, import_type="STIX21")
        cls._typedbSource = TypeDBSource(connection=connection, import_type="STIX21")

        cls._example = "./data/examples/"

    @classmethod
    def tearDownClass(cls):
        pass

    def test_markings(self):

        self.assertTrue(os.path.exists(self._example))

        filename = './data/examples/marking_definitions.json'

        logger.info(f'Loading file {filename}')
        with open(filename,mode="r", encoding="utf-8") as file:
            stix_dict = json.load(file)
            stix_obj = parse(stix_dict)
            self._typedbSink.add(stix_obj)

    def test_others(self):

        self.assertTrue(os.path.exists(self._example))

        for filename in sorted(glob.glob(self._example + '*.json')):
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
                            cmp = StixComparator()
                            check, p_ok, p_not = cmp.compare(stix_obj, return_obj)
                            self.assertTrue(check)
                    else:
                        bundle = parse(json_blob)
                        for stix_obj in bundle.objects:
                            self._typedbSink.add(stix_obj)
                            return_dict = self._typedbSource.get(stix_obj.id)
                            return_obj = parse(return_dict)
                            cmp = StixComparator()
                            check, p_ok, p_not = cmp.compare(stix_obj, return_obj)

                            self.assertTrue(check)

if __name__ == '__main__':
    unittest.main()
