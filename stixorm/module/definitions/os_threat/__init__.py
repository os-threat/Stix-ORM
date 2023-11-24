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
    Event, ImpactCoreExt, Availability, Confidentiality,
    External, Integrity, Monetary, Physical, Traceability, Impact,
    IncidentScoreObject, IncidentCoreExt, TaskCoreExt, Task, SightingEvidence,
    SightingAnecdote, SightingAlert, SightingContext, SightingExclusion,
    SightingEnrichment, SightingHunt, SightingFramework, SightingExternal,
    Sequence, Anecdote, SequenceExt, ContactNumber, EmailContact,
    SocialMediaContact,IdentityContact, AnecdoteExt
)


name = "os_threat"
class_model = {}
class_model["sdo"] = {
    "Feeds": Feeds,
    "Feed": Feed,
    "Event": Event,
    "Impact": Impact,
    "Task": Task,
    "Sequence": Sequence
}
class_model["sco"] = {
    "Anecdote": Anecdote
}
class_model["sro"] = {}
class_model["sub"] = {
    "ThreatSubObject" : ThreatSubObject,
    "StateChangeObject": StateChangeObject,
    "EventCoreExt": EventCoreExt,
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
    "SequenceExt": SequenceExt,
    "SightingEvidence": SightingEvidence,
    "SightingAnecdote": SightingAnecdote,
    "SightingAlert": SightingAlert,
    "SightingContext": SightingContext,
    "SightingExclusion": SightingExclusion,
    "SightingEnrichment": SightingEnrichment,
    "SightingHunt": SightingHunt,
    "SightingFramework": SightingFramework,
    "SightingExternal": SightingExternal,
    "TaskCoreExt": TaskCoreExt,
    "ContactNumber": ContactNumber,
    "EmailContact": EmailContact,
    "SocialMediaContact": SocialMediaContact,
    "IdentityContact": IdentityContact,
    "AnecdoteExt": AnecdoteExt
}
class_model["meta"] = {}