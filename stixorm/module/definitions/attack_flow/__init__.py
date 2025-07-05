#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Loader module for all attack flow data model
"""

__author__ = "Brett Forbes"
__credits__ = ["Paolo Di Prodi"]
__license__ = "Apache-2.0"
__version__ = "0.1.0"
__maintainer__ = "Paolo Di Prodi"
__email__ = "paolo@osthreat.com"
__status__ = "Production"


import json
from glob import glob

import pathlib
from loguru import logger
import os
from pathlib import Path

from stixorm.module.definitions.attack_flow.classes import (
	AttackFlow, FlowAsset, AttackFlowExt
)




name = "attack_flow"
class_model = {}
class_model["sdo"] = {
    "AttackFlow": AttackFlow,
    "FlowAsset": FlowAsset,
}
class_model["sco"] = {}
class_model["sro"] = {}
class_model["sub"] = {
    "AttackFlowExt": AttackFlowExt
}
class_model["meta"] = {}