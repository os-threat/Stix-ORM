#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Loader module for all ATT&CK data model
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

attack_models = {}
for file_path in glob(f'{dir_path}/data/*.json'):
    # Opening JSON file
    file_name = Path(file_path).stem

    with open(file_path) as json_file:
        # create well formed key
        key = f'{file_name}'

        attack_models[key] = json.load(json_file)

logger.debug('Loaded %d attack dictionary objects' % len(attack_models))