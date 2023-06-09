#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
This history all the dictionary definitions and save them as JSON objects
"""

__author__ = "Paolo Di Prodi"
__credits__ = ["Brett Forbes"]
__license__ = "GPL"
__version__ = "0.1.0"
__maintainer__ = "Paolo Di Prodi"
__email__ = "paolo@priam.ai"
__status__ = "Production"

import json
import definitions
import os

os.makedirs('data', exist_ok=True)

for id in dir(definitions):
    obj = getattr(definitions,id)

    # filter the dictionary objects only
    if isinstance(obj, dict) and id!='__builtins__':
        # save the object as dictionary
        with open(f'data/{id}.json', 'w') as file:
            json.dump(obj,file)

    if isinstance(obj, list) and id!='__builtins__':
        # save the object as dictionary
        with open(f'data/{id}.json', 'w') as file:
            json.dump(obj,file)

