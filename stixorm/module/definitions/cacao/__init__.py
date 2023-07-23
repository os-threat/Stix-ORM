#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Loader module for all cacao data model
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


name = "cacao"
class_model = {}
class_model["sdo"] = {}
class_model["sco"] = {}
class_model["sro"] = {}
class_model["sub"] = {}
class_model["meta"] = {}


