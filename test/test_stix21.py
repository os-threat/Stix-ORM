import os
import pathlib
import json
import itertools as it
import glob
import logging

import pytest

from stixorm.module.typedb import TypeDBSource, TypeDBSink
from stixorm.module.typedb_lib.factories.import_type_factory import ImportTypeFactory

logger = logging.getLogger(__name__)

from stix2 import (v21, parse)


import re
s = "Example String"
replaced = re.sub('[ES]', 'a', s)

class StixComparator(object):

    def selector_mask(self,list_str):
        list_mask = [re.sub(pattern='\.\[(\d+)\]', repl='[*]', string=v) for v in list_str]

        return list_mask

    def property_check(self,a,b,key,property_type):
        if property_type == 'ListProperty':
            if len(a._inner[key]) != len(b._inner[key]):
                return False
            else:
                # Equivalent
                matched = 0
                # recursion is kicking in here
                for r in it.product(a._inner[key], b._inner[key]):
                    if key == 'granular_markings':
                        check, p_ok, p_not = self.compare(r[0],r[1],skip_type=True)
                        if check: matched += 1
                    elif key == 'selectors':
                        if type(r[0]) == str and type(r[1])==str:
                            # required for comparison of array notations that are not preserved in TypeDB
                            a_re = re.sub(pattern='\.\[(\d+)\]', repl='.[*]', string=r[0])
                            b_re = re.sub(pattern='\.\[(\d+)\]', repl='.[*]', string=r[1])
                            if a_re == b_re: matched+=1
                        else:
                            raise Exception('Type comparison not supported')
                    elif r[0] == r[1]: matched += 1

                return matched == len(a._inner[key])

        elif property_type == 'StringProperty':
            if key == 'pattern':
                print('PATTERN')
            else:
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
        elif property_type == 'IntegerProperty':
            return a._inner[key] == b._inner[key]
        elif property_type == 'HashesProperty':
            return a._inner[key] == b._inner[key]
        else:
            raise NotImplementedError(f'Property type {property_type} not considered')

    def compare(self,a,b,skip_type = False):
        if (skip_type == False) and (a._type != b._type):
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
                    if property_name == 'pattern':
                        logger.info('This will fail with escape hell')
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

@pytest.fixture
def typedb_connection(generate_connection):
    import_type = ImportTypeFactory().get_default_import()
    typedb_sink = TypeDBSink(connection=generate_connection, clear=True, import_type=import_type)
    typedb_source = TypeDBSource(connection=generate_connection, import_type=import_type)
    data_folder = pathlib.Path(__file__).parents[0].joinpath("data/examples/")
    example = str(pathlib.Path(__file__).parents[0].joinpath("data/examples/"))

    yield typedb_sink, typedb_source, data_folder, example
    # Teardown code, if needed

class TestDatabase:



    def test_markings(self, typedb_connection):
        typedb_sink, _, data_folder, _ = typedb_connection

        assert os.path.exists(data_folder)

        filename = data_folder.joinpath("marking_definitions.json")

        logging.info(f'Loading file {filename}')
        with open(filename, mode="r", encoding="utf-8") as file:
            stix_dict = json.load(file)
            stix_obj = parse(stix_dict)
            typedb_sink.add(stix_obj)

    def test_others(self, typedb_connection):
        typedb_sink, typedb_source, data_folder, example = typedb_connection

        assert os.path.exists(data_folder)

        for filename in sorted(glob.glob(example + '*.json')):
            logging.info(f'Testing file {filename}')
            with open(filename, mode="r", encoding="utf-8") as file:
                if filename.endswith('marking_definitions.json'):
                    continue
                else:
                    logging.info(f'Loading file {filename}')
                    json_blob = json.load(file)

                    if isinstance(json_blob, list):
                        for item in json_blob:
                            stix_obj = parse(item)
                            typedb_sink.add(stix_obj)
                            return_dict = typedb_source.get(stix_obj.id)
                            return_obj = parse(return_dict)
                            cmp = StixComparator()
                            check, p_ok, p_not = cmp.compare(stix_obj, return_obj)
                            assert check
                    else:
                        bundle = parse(json_blob)
                        for stix_obj in bundle.objects:
                            typedb_sink.add(stix_obj)
                            return_dict = typedb_source.get(stix_obj.id)
                            return_obj = parse(return_dict)
                            cmp = StixComparator()
                            check, p_ok, p_not = cmp.compare(stix_obj, return_obj)
                            logging.info(f'OK properties {p_ok}')
                            logging.info(f'KO properties {p_not}')
                            assert check