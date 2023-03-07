#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Loader module for all os_threat data model
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
from loguru import logger
import os
from pathlib import Path

path = os.path.abspath(__file__)
dir_path = os.path.dirname(path)

os_threat_models = {}
os_threat_models["data"] = {}
for file_path in glob(f'{dir_path}/data/*.json'):
    # Opening JSON file
    file_name = Path(file_path).stem

    with open(file_path) as json_file:
        # create well formed key
        key = f'{file_name}'

        os_threat_models["data"][key] = json.load(json_file)
        

os_threat_models["base"] = {}
for file_path in glob(f'{dir_path}/base/*.json'):
    # Opening JSON file
    file_name = Path(file_path).stem

    with open(file_path) as json_file:
        # create well formed key
        key = f'{file_name}'

        os_threat_models["base"][key] = json.load(json_file)
        

os_threat_models["mappings"] = {}
for file_path in glob(f'{dir_path}/mappings/*.json'):
    # Opening JSON file
    file_name = Path(file_path).stem

    with open(file_path) as json_file:
        # create well formed key
        key = f'{file_name}'

        os_threat_models["mappings"][key] = json.load(json_file)


os_threat_models["sub_objects"] = {}
for file_path in glob(f'{dir_path}/sub_objects/*.json'):
    # Opening JSON file
    file_name = Path(file_path).stem

    with open(file_path) as json_file:
        # create well formed key
        key = f'{file_name}'

        os_threat_models["sub_objects"][key] = json.load(json_file)

os_threat_models["classes"] = {}
os_threat_models["classes"]["sdo"] = {}
os_threat_models["classes"]["sco"] = {}
os_threat_models["classes"]["sro"] = {}
os_threat_models["classes"]["sub"] = {}

total_len = len(os_threat_models["data"])+len(os_threat_models["base"])+len(os_threat_models["mappings"])+len(os_threat_models["sub_objects"])

logger.debug('Loaded %d os-threat dictionary objects' % total_len)