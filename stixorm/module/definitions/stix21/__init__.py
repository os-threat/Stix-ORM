#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Loader module for all STIX data model
"""

__author__ = "Paolo Di Prodi"
__credits__ = ["Brett Forbes"]
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
from stix2.v21.sdo import (
    AttackPattern, Campaign, CourseOfAction, CustomObject, Grouping, Identity,
    Incident, Indicator, Infrastructure, IntrusionSet, Location, Malware,
    MalwareAnalysis, Note, ObservedData, Opinion, Report, ThreatActor, Tool,
    Vulnerability,
)
from stix2.v21.observables import (
    URL, AlternateDataStream, ArchiveExt, Artifact, AutonomousSystem,
    CustomObservable, Directory, DomainName, EmailAddress, EmailMessage,
    EmailMIMEComponent, File, HTTPRequestExt, ICMPExt, IPv4Address,
    IPv6Address, MACAddress, Mutex, NetworkTraffic, NTFSExt, PDFExt, Process,
    RasterImageExt, SocketExt, Software, TCPExt, UNIXAccountExt, UserAccount,
    WindowsPEBinaryExt, WindowsPEOptionalHeaderType, WindowsPESection,
    WindowsProcessExt, WindowsRegistryKey, WindowsRegistryValueType,
    WindowsServiceExt, X509Certificate, X509V3ExtensionsType,
)
from stix2.v21.sro import Relationship, Sighting
from stix2.v21.common import MarkingDefinition

path = os.path.abspath(__file__)
dir_path = os.path.dirname(path)
#logger = logging.getLogger(__name__)

stix_models = {}
stix_models["data"] = {}
for file_path in glob(f'{dir_path}/data/*.json'):
    # Opening JSON file
    file_name = Path(file_path).stem

    with open(file_path) as json_file:
        # create well formed key
        key = f'{file_name}'

        stix_models["data"][key] = json.load(json_file)


stix_models["base"] = {}
for file_path in glob(f'{dir_path}/base/*.json'):
    # Opening JSON file
    file_name = Path(file_path).stem

    with open(file_path) as json_file:
        # create well formed key
        key = f'{file_name}'

        stix_models["base"][key] = json.load(json_file)


stix_models["mappings"] = {}
for file_path in glob(f'{dir_path}/mappings/*.json'):
    # Opening JSON file
    file_name = Path(file_path).stem
    #if file_name != "object_conversion":
    with open(file_path, encoding='utf-8') as json_file:
        # create well formed key
        key = f'{file_name}'
        file_data = json_file.read()

        stix_models["mappings"][key] = json.loads(file_data)


stix_models["sub_objects"] = {}
for file_path in glob(f'{dir_path}/sub_objects/*.json'):
    # Opening JSON file
    file_name = Path(file_path).stem

    with open(file_path) as json_file:
        # create well formed key
        key = f'{file_name}'

        stix_models["sub_objects"][key] = json.load(json_file)

stix_models["classes"] = {}
stix_models["classes"]["sro"] = {
    "Relationship": Relationship,
    "Sighting": Sighting
}
stix_models["classes"]["sdo"] = {
    "AttackPattern":AttackPattern,
    "Campaign":Campaign,
    "CourseOfAction":CourseOfAction,
    "CustomObject":CustomObject,
    "Grouping":Grouping,
    "Identity":Identity,
    "Incident":Incident,
    "Indicator":Indicator,
    "Infrastructure":Infrastructure,
    "IntrusionSet":IntrusionSet,
    "Location":Location,
    "Malware":Malware,
    "MalwareAnalysis":MalwareAnalysis,
    "Note":Note,
    "ObservedData":ObservedData,
    "Opinion":Opinion,
    "Report":Report,
    "ThreatActor":ThreatActor,
    "Tool":Tool,
    "Vulnerability":Vulnerability,
}
stix_models["classes"]["sub"] = {
    "AlternateDataStream":AlternateDataStream,
    "ArchiveExt":ArchiveExt,
    "EmailMIMEComponent": EmailMIMEComponent,
    "HTTPRequestExt":HTTPRequestExt,
    "ICMPExt":ICMPExt,
    "NTFSExt":NTFSExt,
    "PDFExt":PDFExt,
    "RasterImageExt":RasterImageExt,
    "SocketExt":SocketExt,
    "TCPExt":TCPExt,
    "UNIXAccountExt":UNIXAccountExt,
    "WindowsPEBinaryExt":WindowsPEBinaryExt,
    "WindowsPEOptionalHeaderType":WindowsPEOptionalHeaderType,
    "WindowsPESection":WindowsPESection,
    "WindowsProcessExt":WindowsProcessExt,
    "WindowsRegistryValueType":WindowsRegistryValueType,
    "WindowsServiceExt":WindowsServiceExt,
    "X509V3ExtensionsType":X509V3ExtensionsType
}
stix_models["classes"]["sco"] = {
    "URL":URL,
    "Artifact":Artifact,
    "AutonomousSystem":AutonomousSystem,
    "CustomObservable":CustomObservable,
    "Directory":Directory,
    "DomainName":DomainName,
    "EmailAddress":EmailAddress,
    "EmailMessage":EmailMessage,
    "File":File,
    "IPv4Address":IPv4Address,
    "IPv6Address":IPv6Address,
    "MACAddress":MACAddress,
    "Mutex":Mutex,
    "NetworkTraffic":NetworkTraffic,
    "Process":Process,
    "Software":Software,
    "UserAccount":UserAccount,
    "WindowsRegistryKey":WindowsRegistryKey,
    "X509Certificate":X509Certificate,
}
stix_models["classes"]["meta"] = {
    "MarkingDefinition":MarkingDefinition
}

total_len = len(stix_models["data"])+len(stix_models["base"])+len(stix_models["mappings"])
total_len += len(stix_models["sub_objects"])+len(stix_models["classes"]["sdo"])
total_len += len(stix_models["classes"]["sub"])+len(stix_models["classes"]["sco"])
total_len += len(stix_models["classes"]["sro"])

logger.debug('Loaded %d stix dictionary objects' % total_len)