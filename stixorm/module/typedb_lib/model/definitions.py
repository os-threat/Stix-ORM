import json
import os
from enum import Enum
from typing import Optional

from pydantic import BaseModel

class DefinitionName(str, Enum):
    ATTACK = "attack"
    ATTACK_FLOW = "attack_flow"
    CACAO = "cacao"
    MBC = "mbc"
    OCA = "oca"
    OS_THREAT = "os_threat"
    STIX_21 = "stix21"


class ImportTypeToDefinitionMapper():

    @staticmethod
    def corresponding_definition_name(import_type: str) -> Optional[DefinitionName]:
        lookup = {
            "ATTACK": DefinitionName.ATTACK,
            "ATTACK_FLOW": DefinitionName.ATTACK_FLOW,
            "CACAO": DefinitionName.CACAO,
            "MBC": DefinitionName.MBC,
            "OCA": DefinitionName.OCA,
            "OS_THREAT": DefinitionName.OS_THREAT,
            "STIX21": DefinitionName.STIX_21
        }
        return lookup.get(import_type, None)

class ObjectKeys(str, Enum):
    SDO = "sdo"
    SRO = "sro"
    SCO = "sco"
    SUB = "sub"
    META = "meta"

class ModelClassDefinition(BaseModel):
    sdo: dict
    sro: dict
    meta: dict
    sub: dict
    sco: dict







class ModelDefinition(BaseModel):
    base: dict
    mappings: dict
    sub_objects: dict
    data: dict
    class_def: ModelClassDefinition