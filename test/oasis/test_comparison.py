import pathlib
import pytest
from hamcrest import *
import pickle
import json
import json
from stix2 import (v21, parse)

from loguru import logger

import itertools as it

class StixComparator(object):

    def __init__(self):
        folder_path = pathlib.Path(__file__).parents[2]
        file_path = folder_path.joinpath('stixorm/module/definitions/common/mappings/is_list_sro.json')
        file_path.exists()
        with open(str(file_path),  'r') as file:
            self._sro_list = json.load(file)

    def property_check(self,a,b,key,property_type):
        if property_type == 'ListProperty':
            if len(a._inner[key]) != len(b._inner[key]):
                return False
            else:
                # Equivalent
                matched = 0
                for r in it.product(a._inner[key], b._inner[key]):
                    if r[0] == r[1]: matched += 1
                return matched == len(a._inner[key])
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
                    logger.error(f'Property {property_name} has different class')
                    return False
                if property_name in a._inner and property_name in b._inner:
                    a_obj = a._inner[property_name]
                    b_obj = b._inner[property_name]
                    is_equal = self.property_check(a,b,property_name,a_class)
                    if is_equal: equals.append(property_name)
                    else: not_equals.append(property_name)
                    logger.info(f'{property_name} of {a_class} = {is_equal} in objects')
                elif property_name in a._inner and property_name not in b._inner:
                    logger.warning(f'Property {property_name} not available in a')
                    not_equals.append(property_name)
                elif property_name in b._inner and property_name not in a._inner:
                    logger.warning(f'Property {property_name} not available in a')
                    not_equals.append(property_name)
                else:
                    logger.warning(f'Property {property_name} not available in both objects')
                    continue

            return len(not_equals)==0,equals,not_equals

#TODO: Fix this
@pytest.mark.skip(reason="Find these files referenced")
def test_compare_objects():
    folder_path = pathlib.Path(__file__).parents[0]


    with open('../debug/indicator--26ffb872-1dd9-446e-b6f5-d58527e5b5d2_o.pl', 'rb') as handle:
        stix_obj = pickle.load(handle)

    with open('../debug/indicator--26ffb872-1dd9-446e-b6f5-d58527e5b5d2_r.pl', 'rb') as handle:
        return_obj = pickle.load(handle)

    cmp = StixComparator()
    check, p_ok, p_not = cmp.compare(stix_obj, return_obj)

    assert check


def test_granular_markings():
    def test_loop(a, b):
        matched = 0
        for r in it.product(a, b):
            if r[0] == r[1]:
                matched += 1
        return matched

    top_dir_path = pathlib.Path(__file__).parents[1]
    file_path = 'data/examples/granular_markings.json'
    filename = top_dir_path.joinpath(file_path)

    assert filename.exists()

    with open(str(filename), mode="r", encoding="utf-8") as file:
        json_blob = json.load(file)

        stix_obj = parse(json_blob)
        clone_obj = parse(json_blob)

        matched = test_loop(stix_obj._inner['objects'], clone_obj._inner['objects'])

        assert matched == len(stix_obj._inner['objects'])

        mix_objects = stix_obj._inner['objects']

        with pytest.raises(TypeError):
            sorted_objects = sorted(mix_objects)

        with pytest.raises(TypeError):
            set_objects = set(mix_objects)