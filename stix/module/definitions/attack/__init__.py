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
from .classes import (
    Matrix, Tactic, Technique, SubTechnique, Mitigation, Group, SoftwareMalware,
    SoftwareTool, DataSource, DataComponent, AttackCampaign, Collection,
    ObjectVersion, AttackIdentity
)

from stix.module.definitions.attack.classes import (
    Matrix, Tactic, Technique, SubTechnique, Mitigation, Group, SoftwareMalware,
    SoftwareTool, DataSource, DataComponent, AttackCampaign, Collection,
    ObjectVersion, AttackRelation
)

path = os.path.abspath(__file__)
dir_path = os.path.dirname(path)

attack_models = {}
attack_models["data"] = {}
for file_path in glob(f'{dir_path}/data/*.json'):
    # Opening JSON file
    file_name = Path(file_path).stem

    with open(file_path) as json_file:
        # create well formed key
        key = f'{file_name}'

        attack_models["data"][key] = json.load(json_file)
        

attack_models["base"] = {}
for file_path in glob(f'{dir_path}/base/*.json'):
    # Opening JSON file
    file_name = Path(file_path).stem

    with open(file_path) as json_file:
        # create well formed key
        key = f'{file_name}'

        attack_models["base"][key] = json.load(json_file)
        

attack_models["mappings"] = {}
for file_path in glob(f'{dir_path}/mappings/*.json'):
    # Opening JSON file
    file_name = Path(file_path).stem

    with open(file_path) as json_file:
        # create well formed key
        key = f'{file_name}'

        attack_models["mappings"][key] = json.load(json_file)


attack_models["sub_objects"] = {}
for file_path in glob(f'{dir_path}/sub_objects/*.json'):
    # Opening JSON file
    file_name = Path(file_path).stem

    with open(file_path) as json_file:
        # create well formed key
        key = f'{file_name}'

        attack_models["sub_objects"][key] = json.load(json_file)


attack_models["classes"] = {}
attack_models["classes"]["sdo"] = {
    "Matrix": Matrix,
    "Tactic": Tactic,
    "Technique": Technique,
    "SubTechnique": SubTechnique,
    "Mitigation": Mitigation,
    "Group": Group,
    "SoftwareMalware": SoftwareMalware,
    "SoftwareTool": SoftwareTool,
    "DataSource": DataSource,
    "DataComponent": DataComponent,
    "AttackCampaign": AttackCampaign,
    "Collection": Collection,
    "AttackIdentity": AttackIdentity
}
attack_models["classes"]["sub"] = {
    "ObjectVersion": ObjectVersion
}
attack_models["classes"]["sco"] = {}
attack_models["classes"]["sro"] = {
    "AttackRelation": AttackRelation
}

__all__ = """
    Matrix, Tactic, Technique, SubTechnique, 
    Mitigation, Group, SoftwareMalware,
    SoftwareTool, DataSource, DataComponent, 
    AttackCampaign, Collection, ObjectVersion
""".replace(",", " ").split()

total_len = len(attack_models["data"])+len(attack_models["base"])+len(attack_models["mappings"])
total_len += len(attack_models["sub_objects"])+len(attack_models["classes"]["sdo"])
total_len += len(attack_models["classes"]["sub"])

logger.debug('Loaded %d attack dictionary objects' % total_len)