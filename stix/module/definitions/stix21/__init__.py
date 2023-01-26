#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Loader module for all STIX data model
"""

__author__ = "Paolo Di Prodi"
__credits__ = ["Brett Forbes"]
__license__ = "GPL"
__version__ = "0.1.0"
__maintainer__ = "Paolo Di Prodi"
__email__ = "paolo@priam.ai"
__status__ = "Production"

import json
from glob import glob
import logging
import os
from pathlib import Path

path = os.path.abspath(__file__)
dir_path = os.path.dirname(path)
logger = logging.getLogger(__name__)

stix_models = {}
stix_models["data"] = {}
for file_path in glob(f'{dir_path}/data/*.json'):
    # Opening JSON file
    file_name = Path(file_path).stem

    with open(file_path) as json_file:
        # create well formed key
        key = f'{file_name}'

        stix_models["data"][key] = json.load(json_file)


stix_models["base"] = {}
for file_path in glob(f'{dir_path}/base/*.json'):
    # Opening JSON file
    file_name = Path(file_path).stem

    with open(file_path) as json_file:
        # create well formed key
        key = f'{file_name}'

        stix_models["base"][key] = json.load(json_file)


stix_models["mappings"] = {}
for file_path in glob(f'{dir_path}/mappings/*.json'):
    # Opening JSON file
    file_name = Path(file_path).stem

    with open(file_path) as json_file:
        # create well formed key
        key = f'{file_name}'

        stix_models["mappings"][key] = json.load(json_file)


stix_models["sub_objects"] = {}
for file_path in glob(f'{dir_path}/sub_objects/*.json'):
    # Opening JSON file
    file_name = Path(file_path).stem

    with open(file_path) as json_file:
        # create well formed key
        key = f'{file_name}'

        stix_models["sub_objects"][key] = json.load(json_file)

logger.debug('Loaded %d stix dictionary objects' % len(stix_models))