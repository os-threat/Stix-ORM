#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Loader module for all stix data model
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
from stixorm.module.definitions.stix21.classes import (
    Note, ObservedData, Incident, Report, Relationship, Sighting, Identity, CourseOfAction, Tool,
    File, NetworkTraffic, ExtensionDefinition, Malware, Process, WindowsProcessExt, WindowsServiceExt
)
from stix2.v21.sdo import (
    AttackPattern, Campaign, CustomObject, Grouping,
    Indicator, Infrastructure, IntrusionSet, Location,
    MalwareAnalysis, Opinion, ThreatActor,
    Vulnerability,
)
from stix2.v21.observables import (
    URL, AlternateDataStream, ArchiveExt, Artifact, AutonomousSystem,
    CustomObservable, Directory, DomainName, EmailAddress, EmailMessage,
    EmailMIMEComponent, HTTPRequestExt, ICMPExt, IPv4Address,
    IPv6Address, MACAddress, Mutex, NTFSExt, PDFExt, Process,
    RasterImageExt, SocketExt, Software, TCPExt, UNIXAccountExt, UserAccount,
    WindowsPEBinaryExt, WindowsPEOptionalHeaderType, WindowsPESection,
    WindowsRegistryKey, WindowsRegistryValueType,
    X509Certificate, X509V3ExtensionsType,
)
from stix2.v21.bundle import Bundle
from stix2.v21.common import MarkingDefinition

name = "stix21"
class_model = {}
class_model["sro"] = {
    "Relationship": Relationship,
    "Sighting": Sighting
}
class_model["sdo"] = {
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
    "Bundle": Bundle,
	"ExtensionDefinition": ExtensionDefinition
}
class_model["sub"] = {
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
class_model["sco"] = {
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
class_model["meta"] = {
    "MarkingDefinition":MarkingDefinition
}

