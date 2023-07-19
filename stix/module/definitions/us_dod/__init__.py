#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Loader module for all US DoD data model
"""

__author__ = "Brett Forbes"
__credits__ = ["Paolo Di Prodi"]
__license__ = "GPL"
__version__ = "0.1.0"
__maintainer__ = "Paolo Di Prodi"
__email__ = "paolo@priam.ai"
__status__ = "Production"

import json
from glob import glob

import pathlib
from loguru import logger
import os
from pathlib import Path

from stix.module.definitions.property_definitions import get_definitions, DefinitionNames
from stix.module.definitions.domain_definition import DomainDefinition

path = os.path.abspath(__file__)
dir_path = os.path.dirname(path)

us_dod_models = {}
us_dod_models["data"] = {}
for file_path in glob(f'{dir_path}/data/*.json'):
    # Opening JSON file
    file_name = Path(file_path).stem

    with open(file_path) as json_file:
        # create well formed key
        key = f'{file_name}'

        us_dod_models["data"][key] = json.load(json_file)
        

us_dod_models["base"] = {}
for file_path in glob(f'{dir_path}/base/*.json'):
    # Opening JSON file
    file_name = Path(file_path).stem

    with open(file_path) as json_file:
        # create well formed key
        key = f'{file_name}'

        us_dod_models["base"][key] = json.load(json_file)
        

us_dod_definitions_dir = pathlib.Path(__file__).parent
us_dod_definition = DomainDefinition(DefinitionNames.US_DoD.value,
                                            us_dod_definitions_dir)
us_dod_models["mappings"] = us_dod_definition.get_mappings()



us_dod_models["sub_objects"] = {}
for file_path in glob(f'{dir_path}/sub_objects/*.json'):
    # Opening JSON file
    file_name = Path(file_path).stem

    with open(file_path) as json_file:
        # create well formed key
        key = f'{file_name}'

        us_dod_models["sub_objects"][key] = json.load(json_file)

us_dod_models["classes"] = {}
us_dod_models["classes"]["sdo"] = {}
us_dod_models["classes"]["sco"] = {}
us_dod_models["classes"]["sro"] = {}
us_dod_models["classes"]["sub"] = {}


total_len = len(us_dod_models["data"])+len(us_dod_models["base"])+len(us_dod_models["mappings"])
total_len += len(us_dod_models["sub_objects"])+len(us_dod_models["classes"]["sdo"])
total_len += len(us_dod_models["classes"]["sub"])+len(us_dod_models["classes"]["sco"])
total_len += len(us_dod_models["classes"]["sro"])
logger.debug('Loaded %d us_dod_models dictionary objects' % total_len)