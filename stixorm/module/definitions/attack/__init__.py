#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Loader module for all attack data model
"""

__author__ = "Brett Forbes"
__credits__ = ["Paolo Di Prodi"]
__license__ = "Apache-2.0"
__version__ = "0.1.0"
__maintainer__ = "Paolo Di Prodi"
__email__ = "paolo@osthreat.com"
__status__ = "Production"





from stixorm.module.definitions.attack.classes import (
    Matrix, Tactic, Technique, SubTechnique, Mitigation, Group, SoftwareMalware,
    SoftwareTool, DataSource, DataComponent, AttackCampaign, Collection,
    ObjectVersion, AttackRelation, AttackMarking, AttackIdentity, AttackAsset
)
name = "attack"
class_model={}
class_model["sdo"] = {
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
    "AttackIdentity": AttackIdentity,
    "AttackAsset": AttackAsset
}
class_model["sub"] = {
    "ObjectVersion": ObjectVersion
}
class_model["sco"] = {}
class_model["meta"] = {
    "AttackMarking": AttackMarking
}
class_model["sro"] = {
    "AttackRelation": AttackRelation
}

