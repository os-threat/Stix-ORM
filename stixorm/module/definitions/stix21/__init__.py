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

import pathlib
from loguru import logger
import os
from pathlib import Path
from stixorm.module.definitions.stix21.classes import (
    Note, ObservedData, Incident, Report, Relationship, Sighting, Identity
)
from stix2.v21.sdo import (
    AttackPattern, Campaign, CourseOfAction, CustomObject, Grouping,
    Indicator, Infrastructure, IntrusionSet, Location, Malware,
    MalwareAnalysis, Opinion, ThreatActor, Tool,
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
    "Bundle": Bundle
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

