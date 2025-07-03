#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Loader module for all kestrel data model
"""

__author__ = "Brett Forbes"
__credits__ = ["Paolo Di Prodi"]
__license__ = "GPL"
__version__ = "0.1.0"
__maintainer__ = "Paolo Di Prodi"
__email__ = "paolo@priam.ai"
__status__ = "Production"

from stixorm.module.definitions.oca.classes import (
    Behavior, CoAPlaybookExt, PlaybookExt, Playbook, OCAAnalyticSubObject,
    DetectionExt, Detection, DetectorExt, Detector, HighValueToolExt,
    UnixFileSubObject, CodeSignatureSubObject, OCAFileExt, OCAFile,
    OCANetworkTrafficRITAExt, NameRefSubObject, DNSExt, NetworkTrafficVLanSubObject,
    OCANetworkTraffic, OCAProcess, OCAProcessExt, OCASoftware, UserGroupSubObject,
    OCAUserAccount, OCAWindowsRegistryKeyExt, OCAFinding, OCATaggingExt,
    OCATagging, OCAIntefaceSubObject, OCATrafficSubObject, OCAPodExt,
    OCAContainerExt, OCAAsset, OCAIAMExt, OCACoordinatesSubObject, OCAGeo
)

name = "oca"
class_model = {}
class_model["sdo"] = {
    "Behavior": Behavior,
    "Detection": Detection,
    "Detector": Detector,
    "Playbook": Playbook
}
class_model["sco"] = {
    "OCAFile": OCAFile,
    "OCANetworkTraffic": OCANetworkTraffic,
    "OCAProcess": OCAProcess,
    "OCASoftware": OCASoftware,
    "OCAUserAccount": OCAUserAccount,
    "OCAFinding": OCAFinding,
    "OCATagging": OCATagging,
    "OCAAsset": OCAAsset,
    "OCAGeo": OCAGeo
}
class_model["sro"] = {}
class_model["sub"] = {
    "CoAPlaybookExt": CoAPlaybookExt,
    "PlaybookExt": PlaybookExt,
    "OCAAnalyticSubObject": OCAAnalyticSubObject,
    "DetectionExt": DetectionExt,
    "DetectorExt": DetectorExt,
    "HighValueToolExt": HighValueToolExt,
    "UnixFileSubObject": UnixFileSubObject,
    "CodeSignatureSubObject": CodeSignatureSubObject,
    "OCAFileExt": OCAFileExt,
    "OCANetworkTrafficRITAExt": OCANetworkTrafficRITAExt,
    "NameRefSubObject": NameRefSubObject,
    "DNSExt": DNSExt,
    "NetworkTrafficVLanSubObject": NetworkTrafficVLanSubObject,
    "OCAProcessExt": OCAProcessExt,
    "UserGroupSubObject": UserGroupSubObject,
    "OCAWindowsRegistryKeyExt": OCAWindowsRegistryKeyExt,
    "OCATaggingExt": OCATaggingExt,
    "OCAIntefaceSubObject": OCAIntefaceSubObject,
    "OCATrafficSubObject": OCATrafficSubObject,
    "OCAPodExt": OCAPodExt,
    "OCAContainerExt": OCAContainerExt,
    "OCAIAMExt": OCAIAMExt,
    "OCACoordinatesSubObject": OCACoordinatesSubObject
}
class_model["meta"] = {}

