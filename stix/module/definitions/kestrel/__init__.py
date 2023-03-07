#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Loader module for all kestrel data model
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

kestrel_models = {}
kestrel_models["data"] = {}
for file_path in glob(f'{dir_path}/data/*.json'):
    # Opening JSON file
    file_name = Path(file_path).stem

    with open(file_path) as json_file:
        # create well formed key
        key = f'{file_name}'

        kestrel_models["data"][key] = json.load(json_file)
        

kestrel_models["base"] = {}
for file_path in glob(f'{dir_path}/base/*.json'):
    # Opening JSON file
    file_name = Path(file_path).stem

    with open(file_path) as json_file:
        # create well formed key
        key = f'{file_name}'

        kestrel_models["base"][key] = json.load(json_file)
        

kestrel_models["mappings"] = {}
for file_path in glob(f'{dir_path}/mappings/*.json'):
    # Opening JSON file
    file_name = Path(file_path).stem

    with open(file_path) as json_file:
        # create well formed key
        key = f'{file_name}'

        kestrel_models["mappings"][key] = json.load(json_file)


kestrel_models["sub_objects"] = {}
for file_path in glob(f'{dir_path}/sub_objects/*.json'):
    # Opening JSON file
    file_name = Path(file_path).stem

    with open(file_path) as json_file:
        # create well formed key
        key = f'{file_name}'

        kestrel_models["sub_objects"][key] = json.load(json_file)

kestrel_models["classes"] = {}
kestrel_models["classes"]["sdo"] = {}
kestrel_models["classes"]["sco"] = {}
kestrel_models["classes"]["sro"] = {}
kestrel_models["classes"]["sub"] = {}

total_len = len(kestrel_models["data"])+len(kestrel_models["base"])+len(kestrel_models["mappings"])
total_len += len(kestrel_models["sub_objects"])+len(kestrel_models["classes"]["sdo"])
total_len += len(kestrel_models["classes"]["sub"])+len(kestrel_models["classes"]["sco"])
total_len += len(kestrel_models["classes"]["sro"])
logger.debug('Loaded %d kestrel dictionary objects' % total_len)