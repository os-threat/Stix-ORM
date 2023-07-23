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

import pathlib
from loguru import logger
import os
from pathlib import Path

from stixorm.module.definitions.os_threat.classes import (
    Feeds, Feed, ThreatSubObject, StateChangeObject, EventCoreExt,
    Event, EntityCountObject, ImpactCoreExt, Availability, Confidentiality,
    External, Integrity, Monetary, Physical, Traceability, Impact,
    IncidentScoreObject, IncidentCoreExt, TaskCoreExt, Task,
    EvidenceCoreExt, Evidence
)





name = "os_threat"
class_model = {}
class_model["sdo"] = {
    "Feeds": Feeds,
    "Feed": Feed,
    "Evidence": Evidence,
    "Event": Event,
    "Impact": Impact,
    "Task": Task
}
class_model["sco"] = {}
class_model["sro"] = {}
class_model["sub"] = {
    "ThreatSubObject" : ThreatSubObject,
    "StateChangeObject": StateChangeObject,
    "EventCoreExt": EventCoreExt,
    "EntityCountObject": EntityCountObject,
    "ImpactCoreExt": ImpactCoreExt,
    "Availability": Availability,
    "Confidentiality": Confidentiality,
    "External": External,
    "Integrity": Integrity,
    "Monetary": Monetary,
    "Physical": Physical,
    "Traceability": Traceability,
    "IncidentScoreObject": IncidentScoreObject,
    "IncidentCoreExt": IncidentCoreExt,
    "TaskCoreExt": TaskCoreExt,
    "EvidenceCoreExt": EvidenceCoreExt
}
class_model["meta"] = {}