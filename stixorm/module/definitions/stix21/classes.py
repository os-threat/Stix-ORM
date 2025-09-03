"""Python Mitre ATT&CK Stix Class Definitions """
from stix2.v20 import WindowsRegistryValueType

from stixorm.module.typedb_lib.factories.mappings_factory import get_mapping_factory_instance

"""Python Mitre ATT&CK Stix Class Definitions """
import json
import pathlib
import warnings
from collections import OrderedDict

from stix2.exceptions import (
    PropertyPresenceError, STIXDeprecationWarning, AtLeastOnePropertyError, )
from stix2.properties import (
    BooleanProperty, ExtensionsProperty, IDProperty, IntegerProperty, ListProperty,
    OpenVocabProperty, ReferenceProperty, StringProperty, DictionaryProperty, EnumProperty,
    TimestampProperty, TypeProperty, EmbeddedObjectProperty, ObservableProperty, HexProperty, HashesProperty,
    FloatProperty
)
from stix2.utils import NOW, _get_dict
from stix2.markings import _MarkingsMixin
from stix2.markings.utils import check_tlp_marking
from stix2.v21.base import _DomainObject, _STIXBase21, _RelationshipObject, _Extension, _Observable
from stix2.v21.common import (
    ExternalReference, GranularMarking, KillChainPhase,
    MarkingProperty, TLPMarking, StatementMarking,
)
from stix2.v21.vocab import (
    ATTACK_MOTIVATION, ATTACK_RESOURCE_LEVEL, IMPLEMENTATION_LANGUAGE, MALWARE_CAPABILITIES, MALWARE_TYPE,
    PROCESSOR_ARCHITECTURE, TOOL_TYPE, IDENTITY_CLASS, INDUSTRY_SECTOR, REPORT_TYPE,HASHING_ALGORITHM,
    EXTENSION_TYPE, WINDOWS_INTEGRITY_LEVEL, WINDOWS_SERVICE_START_TYPE, WINDOWS_SERVICE_TYPE, WINDOWS_SERVICE_STATUS,
    WINDOWS_PEBINARY_TYPE, NETWORK_SOCKET_ADDRESS_FAMILY, NETWORK_SOCKET_TYPE
)

import logging

from stixorm.module.definitions.property_definitions import ThreatReference, ThreatExtensionsProperty


logger = logging.getLogger(__name__)

valid_obj =  get_mapping_factory_instance().get_all_types()

##################################################################################
#       SDO
##################################################################################



class CourseOfAction(_DomainObject):
    """For more detailed information on this object's properties, see
    `the STIX 2.1 specification <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_a925mpw39txn>`__.
    """

    _type = 'course-of-action'
    _properties = OrderedDict([
        ('type', TypeProperty(_type, spec_version='2.1')),
        ('spec_version', StringProperty(fixed='2.1')),
        ('id', IDProperty(_type, spec_version='2.1')),
        ('created_by_ref', ReferenceProperty(valid_types='identity', spec_version='2.1')),
        ('created', TimestampProperty(default=lambda: NOW, precision='millisecond', precision_constraint='min')),
        ('modified', TimestampProperty(default=lambda: NOW, precision='millisecond', precision_constraint='min')),
        ('name', StringProperty(required=True)),
        ('description', StringProperty()),
        ('revoked', BooleanProperty(default=lambda: False)),
        ('labels', ListProperty(StringProperty)),
        ('confidence', IntegerProperty()),
        ('lang', StringProperty()),
        ('external_references', ListProperty(ExternalReference)),
        ('object_marking_refs', ListProperty(ReferenceProperty(valid_types='marking-definition', spec_version='2.1'))),
        ('granular_markings', ListProperty(GranularMarking)),
        ('extensions', ThreatExtensionsProperty(spec_version='2.1')),
    ])



class Incident(_DomainObject):
    """For more detailed information on this object's properties, see
    `the STIX 2.1 specification <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_sczfhw64pjxt>`__.
    """

    _type = 'incident'
    _properties = OrderedDict([
        ('type', TypeProperty(_type, spec_version='2.1')),
        ('spec_version', StringProperty(fixed='2.1')),
        ('id', IDProperty(_type, spec_version='2.1')),
        ('created_by_ref', ReferenceProperty(valid_types='identity', spec_version='2.1')),
        ('created', TimestampProperty(default=lambda: NOW, precision='millisecond', precision_constraint='min')),
        ('modified', TimestampProperty(default=lambda: NOW, precision='millisecond', precision_constraint='min')),
        ('name', StringProperty(required=True)),
        ('description', StringProperty()),
        ('kill_chain_phases', ListProperty(KillChainPhase)),
        ('revoked', BooleanProperty(default=lambda: False)),
        ('labels', ListProperty(StringProperty)),
        ('confidence', IntegerProperty()),
        ('lang', StringProperty()),
        ('external_references', ListProperty(ExternalReference)),
        ('object_marking_refs', ListProperty(ReferenceProperty(valid_types='marking-definition', spec_version='2.1'))),
        ('granular_markings', ListProperty(GranularMarking)),
        ('extensions', ThreatExtensionsProperty(spec_version='2.1')),
    ])



class Identity(_DomainObject):
    """For more detailed information on this object's properties, see
    `the STIX 2.1 specification <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_wh296fiwpklp>`__.
    """

    _type = 'identity'
    _properties = OrderedDict([
        ('type', TypeProperty(_type, spec_version='2.1')),
        ('spec_version', StringProperty(fixed='2.1')),
        ('id', IDProperty(_type, spec_version='2.1')),
        ('created_by_ref', ReferenceProperty(valid_types='identity', spec_version='2.1')),
        ('created', TimestampProperty(default=lambda: NOW, precision='millisecond', precision_constraint='min')),
        ('modified', TimestampProperty(default=lambda: NOW, precision='millisecond', precision_constraint='min')),
        ('name', StringProperty(required=True)),
        ('description', StringProperty()),
        ('roles', ListProperty(StringProperty)),
        ('identity_class', OpenVocabProperty(IDENTITY_CLASS)),
        ('sectors', ListProperty(OpenVocabProperty(INDUSTRY_SECTOR))),
        ('contact_information', StringProperty()),
        ('revoked', BooleanProperty(default=lambda: False)),
        ('labels', ListProperty(StringProperty)),
        ('confidence', IntegerProperty()),
        ('lang', StringProperty()),
        ('external_references', ListProperty(ExternalReference)),
        ('object_marking_refs', ListProperty(ReferenceProperty(valid_types='marking-definition', spec_version='2.1'))),
        ('granular_markings', ListProperty(GranularMarking)),
        ('extensions', ThreatExtensionsProperty(spec_version='2.1')),
    ])


class Malware(_DomainObject):
    """For more detailed information on this object's properties, see
    `the STIX 2.1 specification <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_s5l7katgbp09>`__.
    """

    _type = 'malware'
    _properties = OrderedDict([
        ('type', TypeProperty(_type, spec_version='2.1')),
        ('spec_version', StringProperty(fixed='2.1')),
        ('id', IDProperty(_type, spec_version='2.1')),
        ('created_by_ref', ReferenceProperty(valid_types='identity', spec_version='2.1')),
        ('created', TimestampProperty(default=lambda: NOW, precision='millisecond', precision_constraint='min')),
        ('modified', TimestampProperty(default=lambda: NOW, precision='millisecond', precision_constraint='min')),
        ('name', StringProperty()),
        ('description', StringProperty()),
        ('malware_types', ListProperty(OpenVocabProperty(MALWARE_TYPE))),
        ('is_family', BooleanProperty(required=True)),
        ('aliases', ListProperty(StringProperty)),
        ('kill_chain_phases', ListProperty(KillChainPhase)),
        ('first_seen', TimestampProperty()),
        ('last_seen', TimestampProperty()),
        ('operating_system_refs', ListProperty(ReferenceProperty(valid_types='software', spec_version='2.1'))),
        ('architecture_execution_envs', ListProperty(OpenVocabProperty(PROCESSOR_ARCHITECTURE))),
        ('implementation_languages', ListProperty(OpenVocabProperty(IMPLEMENTATION_LANGUAGE))),
        ('capabilities', ListProperty(OpenVocabProperty(MALWARE_CAPABILITIES))),
        ('sample_refs', ListProperty(ReferenceProperty(valid_types=['artifact', 'file'], spec_version='2.1'))),
        ('revoked', BooleanProperty(default=lambda: False)),
        ('labels', ListProperty(StringProperty)),
        ('confidence', IntegerProperty()),
        ('lang', StringProperty()),
        ('external_references', ListProperty(ExternalReference)),
        ('object_marking_refs', ListProperty(ReferenceProperty(valid_types='marking-definition', spec_version='2.1'))),
        ('granular_markings', ListProperty(GranularMarking)),
        ('extensions', ThreatExtensionsProperty(spec_version='2.1')),
    ])

    def _check_object_constraints(self):
        super(Malware, self)._check_object_constraints()

        first_seen = self.get('first_seen')
        last_seen = self.get('last_seen')

        if first_seen and last_seen and last_seen < first_seen:
            msg = "{0.id} 'last_seen' must be greater than or equal to 'first_seen'"
            raise ValueError(msg.format(self))

        if self.is_family and "name" not in self:
            raise PropertyPresenceError(
                "'name' is a required property for malware families",
                Malware,
            )



class Note(_DomainObject):
    """For more detailed information on this object's properties, see
    `the STIX 2.1 specification <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_gudodcg1sbb9>`__.
    """

    _type = 'note'
    _properties = OrderedDict([
        ('type', TypeProperty(_type, spec_version='2.1')),
        ('spec_version', StringProperty(fixed='2.1')),
        ('id', IDProperty(_type, spec_version='2.1')),
        ('created_by_ref', ReferenceProperty(valid_types='identity', spec_version='2.1')),
        ('created', TimestampProperty(default=lambda: NOW, precision='millisecond', precision_constraint='min')),
        ('modified', TimestampProperty(default=lambda: NOW, precision='millisecond', precision_constraint='min')),
        ('abstract', StringProperty()),
        ('content', StringProperty(required=True)),
        ('authors', ListProperty(StringProperty)),
        ('object_refs', ListProperty(ThreatReference(valid_types=valid_obj, spec_version='2.1'), required=True)),
        ('revoked', BooleanProperty(default=lambda: False)),
        ('labels', ListProperty(StringProperty)),
        ('confidence', IntegerProperty()),
        ('lang', StringProperty()),
        ('external_references', ListProperty(ExternalReference)),
        ('object_marking_refs', ListProperty(ReferenceProperty(valid_types='marking-definition', spec_version='2.1'))),
        ('granular_markings', ListProperty(GranularMarking)),
        ('extensions', ExtensionsProperty(spec_version='2.1')),
    ])


class ObservedData(_DomainObject):
    """For more detailed information on this object's properties, see
    `the STIX 2.1 specification <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_p49j1fwoxldc>`__.
    """

    _type = 'observed-data'
    _properties = OrderedDict([
        ('type', TypeProperty(_type, spec_version='2.1')),
        ('spec_version', StringProperty(fixed='2.1')),
        ('id', IDProperty(_type, spec_version='2.1')),
        ('created_by_ref', ReferenceProperty(valid_types='identity', spec_version='2.1')),
        ('created', TimestampProperty(default=lambda: NOW, precision='millisecond', precision_constraint='min')),
        ('modified', TimestampProperty(default=lambda: NOW, precision='millisecond', precision_constraint='min')),
        ('first_observed', TimestampProperty(required=True)),
        ('last_observed', TimestampProperty(required=True)),
        ('number_observed', IntegerProperty(min=1, max=999999999, required=True)),
        ('objects', ObservableProperty(spec_version='2.1')),
        ('object_refs', ListProperty(ThreatReference(valid_types=valid_obj, spec_version='2.1'), required=True)),
        ('revoked', BooleanProperty(default=lambda: False)),
        ('labels', ListProperty(StringProperty)),
        ('confidence', IntegerProperty()),
        ('lang', StringProperty()),
        ('external_references', ListProperty(ExternalReference)),
        ('object_marking_refs', ListProperty(ReferenceProperty(valid_types='marking-definition', spec_version='2.1'))),
        ('granular_markings', ListProperty(GranularMarking)),
        ('extensions', ExtensionsProperty(spec_version='2.1')),
    ])

    def __init__(self, *args, **kwargs):

        if "objects" in kwargs:
            warnings.warn(
                "The 'objects' property of observed-data is deprecated in "
                "STIX 2.1.",
                STIXDeprecationWarning,
            )

        super(ObservedData, self).__init__(*args, **kwargs)

    def _check_object_constraints(self):
        super(ObservedData, self)._check_object_constraints()

        first_observed = self.get('first_observed')
        last_observed = self.get('last_observed')

        if first_observed and last_observed and last_observed < first_observed:
            msg = "{0.id} 'last_observed' must be greater than or equal to 'first_observed'"
            raise ValueError(msg.format(self))

        self._check_mutually_exclusive_properties(
            ["objects", "object_refs"],
        )

valid_obj =  get_mapping_factory_instance().get_all_types()


class Report(_DomainObject):
    """For more detailed information on this object's properties, see
    `the STIX 2.1 specification <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_n8bjzg1ysgdq>`__.
    """

    _type = 'report'
    _properties = OrderedDict([
        ('type', TypeProperty(_type, spec_version='2.1')),
        ('spec_version', StringProperty(fixed='2.1')),
        ('id', IDProperty(_type, spec_version='2.1')),
        ('created_by_ref', ReferenceProperty(valid_types='identity', spec_version='2.1')),
        ('created', TimestampProperty(default=lambda: NOW, precision='millisecond', precision_constraint='min')),
        ('modified', TimestampProperty(default=lambda: NOW, precision='millisecond', precision_constraint='min')),
        ('name', StringProperty(required=True)),
        ('description', StringProperty()),
        ('report_types', ListProperty(OpenVocabProperty(REPORT_TYPE))),
        ('published', TimestampProperty(required=True)),
        ('object_refs', ListProperty(ThreatReference(valid_types=valid_obj, spec_version='2.1'), required=True)),
        ('revoked', BooleanProperty(default=lambda: False)),
        ('labels', ListProperty(StringProperty)),
        ('confidence', IntegerProperty()),
        ('lang', StringProperty()),
        ('external_references', ListProperty(ExternalReference)),
        ('object_marking_refs', ListProperty(ReferenceProperty(valid_types='marking-definition', spec_version='2.1'))),
        ('granular_markings', ListProperty(GranularMarking)),
        ('extensions', ExtensionsProperty(spec_version='2.1')),
    ])




class Tool(_DomainObject):
    """For more detailed information on this object's properties, see
    `the STIX 2.1 specification <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_z4voa9ndw8v>`__.
    """

    _type = 'tool'
    _properties = OrderedDict([
        ('type', TypeProperty(_type, spec_version='2.1')),
        ('spec_version', StringProperty(fixed='2.1')),
        ('id', IDProperty(_type, spec_version='2.1')),
        ('created_by_ref', ReferenceProperty(valid_types='identity', spec_version='2.1')),
        ('created', TimestampProperty(default=lambda: NOW, precision='millisecond', precision_constraint='min')),
        ('modified', TimestampProperty(default=lambda: NOW, precision='millisecond', precision_constraint='min')),
        ('name', StringProperty(required=True)),
        ('description', StringProperty()),
        ('tool_types', ListProperty(OpenVocabProperty(TOOL_TYPE))),
        ('aliases', ListProperty(StringProperty)),
        ('kill_chain_phases', ListProperty(KillChainPhase)),
        ('tool_version', StringProperty()),
        ('revoked', BooleanProperty(default=lambda: False)),
        ('labels', ListProperty(StringProperty)),
        ('confidence', IntegerProperty()),
        ('lang', StringProperty()),
        ('external_references', ListProperty(ExternalReference)),
        ('object_marking_refs', ListProperty(ReferenceProperty(valid_types='marking-definition', spec_version='2.1'))),
        ('granular_markings', ListProperty(GranularMarking)),
        ('extensions', ThreatExtensionsProperty(spec_version='2.1')),
    ])


#############################################################################################################
#   SCO Objects
#############################################################################################################



class ArchiveExt(_Extension):
    """For more detailed information on this object's properties, see
    `the STIX 2.1 specification <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_xi3g7dwaigs6>`__.
    """

    _type = 'archive-ext'
    _properties = OrderedDict([
        ('contains_refs', ListProperty(ReferenceProperty(valid_types=['file', 'directory'], spec_version='2.1'), required=True)),
        ('comment', StringProperty()),
    ])


class AlternateDataStream(_STIXBase21):
    """For more detailed information on this object's properties, see
    `the STIX 2.1 specification <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_8i2ts0xicqea>`__.
    """

    _properties = OrderedDict([
        ('name', StringProperty(required=True)),
        ('hashes', HashesProperty(HASHING_ALGORITHM, spec_version="2.1")),
        ('size', IntegerProperty()),
    ])


class NTFSExt(_Extension):
    """For more detailed information on this object's properties, see
    `the STIX 2.1 specification <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_o6cweepfrsci>`__.
    """

    _type = 'ntfs-ext'
    _properties = OrderedDict([
        ('sid', StringProperty()),
        ('alternate_data_streams', ListProperty(EmbeddedObjectProperty(type=AlternateDataStream))),
    ])


class PDFExt(_Extension):
    """For more detailed information on this object's properties, see
    `the STIX 2.1 specification <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_8xmpb2ghp9km>`__.
    """

    _type = 'pdf-ext'
    _properties = OrderedDict([
        ('version', StringProperty()),
        ('is_optimized', BooleanProperty()),
        ('document_info_dict', DictionaryProperty(spec_version='2.1')),
        ('pdfid0', StringProperty()),
        ('pdfid1', StringProperty()),
    ])


class RasterImageExt(_Extension):
    """For more detailed information on this object's properties, see
    `the STIX 2.1 specification <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_u5z7i2ox8w4x>`__.
    """

    _type = 'raster-image-ext'
    _properties = OrderedDict([
        ('image_height', IntegerProperty()),
        ('image_width', IntegerProperty()),
        ('bits_per_pixel', IntegerProperty()),
        ('exif_tags', DictionaryProperty(spec_version='2.1')),
    ])


class WindowsPEOptionalHeaderType(_STIXBase21):
    """For more detailed information on this object's properties, see
    `the STIX 2.1 specification <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_29l09w731pzc>`__.
    """

    _properties = OrderedDict([
        ('magic_hex', HexProperty()),
        ('major_linker_version', IntegerProperty()),
        ('minor_linker_version', IntegerProperty()),
        ('size_of_code', IntegerProperty(min=0)),
        ('size_of_initialized_data', IntegerProperty(min=0)),
        ('size_of_uninitialized_data', IntegerProperty(min=0)),
        ('address_of_entry_point', IntegerProperty()),
        ('base_of_code', IntegerProperty()),
        ('base_of_data', IntegerProperty()),
        ('image_base', IntegerProperty()),
        ('section_alignment', IntegerProperty()),
        ('file_alignment', IntegerProperty()),
        ('major_os_version', IntegerProperty()),
        ('minor_os_version', IntegerProperty()),
        ('major_image_version', IntegerProperty()),
        ('minor_image_version', IntegerProperty()),
        ('major_subsystem_version', IntegerProperty()),
        ('minor_subsystem_version', IntegerProperty()),
        ('win32_version_value_hex', HexProperty()),
        ('size_of_image', IntegerProperty(min=0)),
        ('size_of_headers', IntegerProperty(min=0)),
        ('checksum_hex', HexProperty()),
        ('subsystem_hex', HexProperty()),
        ('dll_characteristics_hex', HexProperty()),
        ('size_of_stack_reserve', IntegerProperty(min=0)),
        ('size_of_stack_commit', IntegerProperty(min=0)),
        ('size_of_heap_reserve', IntegerProperty()),
        ('size_of_heap_commit', IntegerProperty()),
        ('loader_flags_hex', HexProperty()),
        ('number_of_rva_and_sizes', IntegerProperty()),
        ('hashes', HashesProperty(HASHING_ALGORITHM, spec_version="2.1")),
    ])

    def _check_object_constraints(self):
        super(WindowsPEOptionalHeaderType, self)._check_object_constraints()
        self._check_at_least_one_property()


class WindowsPESection(_STIXBase21):
    """For more detailed information on this object's properties, see
    `the STIX 2.1 specification <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_ioapwyd8oimw>`__.
    """

    _properties = OrderedDict([
        ('name', StringProperty(required=True)),
        ('size', IntegerProperty(min=0)),
        ('entropy', FloatProperty()),
        ('hashes', HashesProperty(HASHING_ALGORITHM, spec_version="2.1")),
    ])


class WindowsPEBinaryExt(_Extension):
    """For more detailed information on this object's properties, see
    `the STIX 2.1 specification <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_gg5zibddf9bs>`__.
    """

    _type = 'windows-pebinary-ext'
    _properties = OrderedDict([
        ('pe_type', OpenVocabProperty(WINDOWS_PEBINARY_TYPE, required=True)),
        ('imphash', StringProperty()),
        ('machine_hex', HexProperty()),
        ('number_of_sections', IntegerProperty(min=0)),
        ('time_date_stamp', TimestampProperty(precision='second')),
        ('pointer_to_symbol_table_hex', HexProperty()),
        ('number_of_symbols', IntegerProperty(min=0)),
        ('size_of_optional_header', IntegerProperty(min=0)),
        ('characteristics_hex', HexProperty()),
        ('file_header_hashes', HashesProperty(HASHING_ALGORITHM, spec_version="2.1")),
        ('optional_header', EmbeddedObjectProperty(type=WindowsPEOptionalHeaderType)),
        ('sections', ListProperty(EmbeddedObjectProperty(type=WindowsPESection))),
    ])



class File(_Observable):
    """For more detailed information on this object's properties, see
    `the STIX 2.1 specification <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_99bl2dibcztv>`__.
    """

    _type = 'file'
    _properties = OrderedDict([
        ('type', TypeProperty(_type, spec_version='2.1')),
        ('spec_version', StringProperty(fixed='2.1')),
        ('id', IDProperty(_type, spec_version='2.1')),
        ('hashes', HashesProperty(HASHING_ALGORITHM, spec_version="2.1")),
        ('size', IntegerProperty(min=0)),
        ('name', StringProperty()),
        ('name_enc', StringProperty()),
        ('magic_number_hex', HexProperty()),
        ('mime_type', StringProperty()),
        ('ctime', TimestampProperty()),
        ('mtime', TimestampProperty()),
        ('atime', TimestampProperty()),
        ('parent_directory_ref', ReferenceProperty(valid_types='directory', spec_version='2.1')),
        ('contains_refs', ListProperty(ReferenceProperty(valid_types=["SCO"], spec_version='2.1'))),
        ('content_ref', ReferenceProperty(valid_types='artifact', spec_version='2.1')),
        ('object_marking_refs', ListProperty(ReferenceProperty(valid_types='marking-definition', spec_version='2.1'))),
        ('granular_markings', ListProperty(GranularMarking)),
        ('defanged', BooleanProperty(default=lambda: False)),
        ('extensions', ExtensionsProperty(spec_version='2.1')),
    ])
    _id_contributing_properties = ["hashes", "name", "parent_directory_ref", "extensions"]

    def _check_object_constraints(self):
        super(File, self)._check_object_constraints()
        self._check_at_least_one_property(['hashes', 'name'])



class HTTPRequestExt(_Extension):
    """For more detailed information on this object's properties, see
    `the STIX 2.1 specification <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_b0e376hgtml8>`__.
    """

    _type = 'http-request-ext'
    _properties = OrderedDict([
        ('request_method', StringProperty(required=True)),
        ('request_value', StringProperty(required=True)),
        ('request_version', StringProperty()),
        ('request_header', DictionaryProperty(spec_version='2.1')),
        ('message_body_length', IntegerProperty()),
        ('message_body_data_ref', ReferenceProperty(valid_types='artifact', spec_version='2.1')),
    ])


class ICMPExt(_Extension):
    """For more detailed information on this object's properties, see
    `the STIX 2.1 specification <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_ozypx0lmkebv>`__.
    """

    _type = 'icmp-ext'
    _properties = OrderedDict([
        ('icmp_type_hex', HexProperty(required=True)),
        ('icmp_code_hex', HexProperty(required=True)),
    ])


class SocketExt(_Extension):
    """For more detailed information on this object's properties, see
    `the STIX 2.1 specification <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_8jamupj9ubdv>`__.
    """

    _type = 'socket-ext'
    _properties = OrderedDict([
        ('address_family', EnumProperty(NETWORK_SOCKET_ADDRESS_FAMILY, required=True)),
        ('is_blocking', BooleanProperty()),
        ('is_listening', BooleanProperty()),
        ('options', DictionaryProperty(spec_version='2.1')),
        ('socket_type', EnumProperty(NETWORK_SOCKET_TYPE)),
        ('socket_descriptor', IntegerProperty(min=0)),
        ('socket_handle', IntegerProperty()),
    ])

    def _check_object_constraints(self):
        super(SocketExt, self)._check_object_constraints()

        options = self.get('options')

        if options is not None:
            acceptable_prefixes = ["SO_", "ICMP_", "ICMP6_", "IP_", "IPV6_", "MCAST_", "TCP_", "IRLMP_"]
            for key, val in options.items():
                if key[:key.find('_') + 1] not in acceptable_prefixes:
                    raise ValueError("Incorrect options key")
                if not isinstance(val, int):
                    raise ValueError("Options value must be an integer")


class TCPExt(_Extension):
    """For more detailed information on this object's properties, see
    `the STIX 2.1 specification <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_k2njqio7f142>`__.
    """

    _type = 'tcp-ext'
    _properties = OrderedDict([
        ('src_flags_hex', HexProperty()),
        ('dst_flags_hex', HexProperty()),
    ])




# class NetworkTraffic(_Observable):
#     """For more detailed information on this object's properties, see
#     `the STIX 2.1 specification <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_rgnc3w40xy>`__.
#     """

#     _type = 'network-traffic'
#     _properties = OrderedDict([
#         ('type', TypeProperty(_type, spec_version='2.1')),
#         ('spec_version', StringProperty(fixed='2.1')),
#         ('id', IDProperty(_type, spec_version='2.1')),
#         ('start', TimestampProperty()),
#         ('end', TimestampProperty()),
#         ('is_active', BooleanProperty()),
#         ('src_ref', ReferenceProperty(valid_types=['ipv4-addr', 'ipv6-addr', 'mac-addr', 'domain-name'], spec_version='2.1')),
#         ('dst_ref', ReferenceProperty(valid_types=['ipv4-addr', 'ipv6-addr', 'mac-addr', 'domain-name'], spec_version='2.1')),
#         ('src_port', IntegerProperty(min=0, max=65535)),
#         ('dst_port', IntegerProperty(min=0, max=65535)),
#         ('protocols', ListProperty(StringProperty, required=True)),
#         ('src_byte_count', IntegerProperty(min=0)),
#         ('dst_byte_count', IntegerProperty(min=0)),
#         ('src_packets', IntegerProperty(min=0)),
#         ('dst_packets', IntegerProperty(min=0)),
#         ('ipfix', DictionaryProperty(spec_version='2.1')),
#         ('src_payload_ref', ReferenceProperty(valid_types='artifact', spec_version='2.1')),
#         ('dst_payload_ref', ReferenceProperty(valid_types='artifact', spec_version='2.1')),
#         ('encapsulates_refs', ListProperty(ReferenceProperty(valid_types='network-traffic', spec_version='2.1'))),
#         ('encapsulated_by_ref', ReferenceProperty(valid_types='network-traffic', spec_version='2.1')),
#         ('object_marking_refs', ListProperty(ReferenceProperty(valid_types='marking-definition', spec_version='2.1'))),
#         ('granular_markings', ListProperty(GranularMarking)),
#         ('defanged', BooleanProperty(default=lambda: False)),
#         ('extensions', ThreatExtensionsProperty(spec_version='2.1')),
#     ])
#     _id_contributing_properties = ["start", "end", "src_ref", "dst_ref", "src_port", "dst_port", "protocols", "extensions"]

#     def _check_object_constraints(self):
#         super(NetworkTraffic, self)._check_object_constraints()
#         self._check_at_least_one_property(['src_ref', 'dst_ref'])

#         start = self.get('start')
#         end = self.get('end')
#         is_active = self.get('is_active')

#         if end and is_active is not False:
#             msg = "{0.id} 'is_active' must be False if 'end' is present"
#             raise ValueError(msg.format(self))

#         if end and is_active is True:
#             msg = "{0.id} if 'is_active' is True, 'end' must not be included"
#             raise ValueError(msg.format(self))

#         if start and end and end < start:
#             msg = "{0.id} 'end' must be greater than or equal to 'start'"
#             raise ValueError(msg.format(self))
        



class WindowsProcessExt(_Extension):
    """For more detailed information on this object's properties, see
    `the STIX 2.1 specification <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_oyegq07gjf5t>`__.
    """

    _type = 'windows-process-ext'
    _properties = OrderedDict([
        ('aslr_enabled', BooleanProperty()),
        ('dep_enabled', BooleanProperty()),
        ('priority', StringProperty()),
        ('owner_sid', StringProperty()),
        ('window_title', StringProperty()),
        ('startup_info', DictionaryProperty(spec_version='2.1')),
        ('integrity_level', EnumProperty(WINDOWS_INTEGRITY_LEVEL)),
    ])


class WindowsServiceExt(_Extension):
    """For more detailed information on this object's properties, see
    `the STIX 2.1 specification <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_lbcvc2ahx1s0>`__.
    """

    _type = 'windows-service-ext'
    _properties = OrderedDict([
        ('service_name', StringProperty()),
        ('descriptions', ListProperty(StringProperty)),
        ('display_name', StringProperty()),
        ('group_name', StringProperty()),
        ('start_type', EnumProperty(WINDOWS_SERVICE_START_TYPE)),
        ('service_dll_refs', ListProperty(ReferenceProperty(valid_types='file', spec_version='2.1'))),
        ('service_type', EnumProperty(WINDOWS_SERVICE_TYPE)),
        ('service_status', EnumProperty(WINDOWS_SERVICE_STATUS)),
    ])


class Process(_Observable):
    """For more detailed information on this object's properties, see
    `the STIX 2.1 specification <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_hpppnm86a1jm>`__.
    """

    _type = 'process'
    _properties = OrderedDict([
        ('type', TypeProperty(_type, spec_version='2.1')),
        ('spec_version', StringProperty(fixed='2.1')),
        ('id', IDProperty(_type, spec_version='2.1')),
        ('is_hidden', BooleanProperty()),
        ('pid', IntegerProperty()),
        # this is not the created timestamps of the object itself
        ('created_time', TimestampProperty()),
        ('cwd', StringProperty()),
        ('command_line', StringProperty()),
        ('environment_variables', DictionaryProperty(spec_version='2.1')),
        ('opened_connection_refs', ListProperty(ReferenceProperty(valid_types='network-traffic', spec_version='2.1'))),
        ('creator_user_ref', ReferenceProperty(valid_types='user-account', spec_version='2.1')),
        ('image_ref', ReferenceProperty(valid_types='file', spec_version='2.1')),
        ('parent_ref', ReferenceProperty(valid_types='process', spec_version='2.1')),
        ('child_refs', ListProperty(ReferenceProperty(valid_types='process', spec_version='2.1'))),
        ('object_marking_refs', ListProperty(ReferenceProperty(valid_types='marking-definition', spec_version='2.1'))),
        ('granular_markings', ListProperty(GranularMarking)),
        ('defanged', BooleanProperty(default=lambda: False)),
        ('extensions', ThreatExtensionsProperty(spec_version='2.1')),
    ])
    _id_contributing_properties = []

    def _check_object_constraints(self):
        # no need to check windows-service-ext, since it has a required property
        super(Process, self)._check_object_constraints()
        try:
            self._check_at_least_one_property()
            if 'windows-process-ext' in self.get('extensions', {}):
                self.extensions['windows-process-ext']._check_at_least_one_property()
        except AtLeastOnePropertyError as enclosing_exc:
            if 'extensions' not in self:
                raise enclosing_exc
            else:
                if 'windows-process-ext' in self.get('extensions', {}):
                    self.extensions['windows-process-ext']._check_at_least_one_property()




class WindowsRegistryKey(_Observable):
    """For more detailed information on this object's properties, see
    `the STIX 2.1 specification <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_luvw8wjlfo3y>`__.
    """

    _type = 'windows-registry-key'
    _properties = OrderedDict([
        ('type', TypeProperty(_type, spec_version='2.1')),
        ('spec_version', StringProperty(fixed='2.1')),
        ('id', IDProperty(_type, spec_version='2.1')),
        ('key', StringProperty()),
        ('values', ListProperty(EmbeddedObjectProperty(type=WindowsRegistryValueType))),
        # this is not the modified timestamps of the object itself
        ('modified_time', TimestampProperty()),
        ('creator_user_ref', ReferenceProperty(valid_types='user-account', spec_version='2.1')),
        ('number_of_subkeys', IntegerProperty()),
        ('object_marking_refs', ListProperty(ReferenceProperty(valid_types='marking-definition', spec_version='2.1'))),
        ('granular_markings', ListProperty(GranularMarking)),
        ('defanged', BooleanProperty(default=lambda: False)),
        ('extensions', ThreatExtensionsProperty(spec_version='2.1')),
    ])
    _id_contributing_properties = ["key", "values"]



#############################################################################################################
#   SRO Objects
#############################################################################################################

class Relationship(_RelationshipObject):
    """For more detailed information on this object's properties, see
    `the STIX 2.1 specification <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_e2e1szrqfoan>`__.
    """

    _invalid_source_target_types = ['bundle', 'language-content', 'marking-definition', 'relationship', 'sighting']

    _type = 'relationship'
    _properties = OrderedDict([
        ('type', TypeProperty(_type, spec_version='2.1')),
        ('spec_version', StringProperty(fixed='2.1')),
        ('id', IDProperty(_type, spec_version='2.1')),
        ('created_by_ref', ReferenceProperty(valid_types='identity', spec_version='2.1')),
        ('created', TimestampProperty(default=lambda: NOW, precision='millisecond', precision_constraint='min')),
        ('modified', TimestampProperty(default=lambda: NOW, precision='millisecond', precision_constraint='min')),
        ('relationship_type', StringProperty(required=True)),
        ('description', StringProperty()),
        ('source_ref', ThreatReference(valid_types=valid_obj, spec_version='2.1', required=True)),
        ('target_ref', ThreatReference(valid_types=valid_obj, spec_version='2.1', required=True)),
        ('start_time', TimestampProperty()),
        ('stop_time', TimestampProperty()),
        ('revoked', BooleanProperty(default=lambda: False)),
        ('labels', ListProperty(StringProperty)),
        ('confidence', IntegerProperty()),
        ('lang', StringProperty()),
        ('external_references', ListProperty(ExternalReference)),
        ('object_marking_refs', ListProperty(ReferenceProperty(valid_types='marking-definition', spec_version='2.1'))),
        ('granular_markings', ListProperty(GranularMarking)),
        ('extensions', ExtensionsProperty(spec_version='2.1')),
    ])

    # Explicitly define the first three kwargs to make readable Relationship declarations.
    # def __init__(
    #     self, source_ref=None, relationship_type=None,
    #     target_ref=None, **kwargs
    # ):
    #     # Allow (source_ref, relationship_type, target_ref) as positional args.
    #     if source_ref and not kwargs.get('source_ref'):
    #         kwargs['source_ref'] = source_ref
    #     if relationship_type and not kwargs.get('relationship_type'):
    #         kwargs['relationship_type'] = relationship_type
    #     if target_ref and not kwargs.get('target_ref'):
    #         kwargs['target_ref'] = target_ref
    #
    #     super(Relationship, self).__init__(**kwargs)

    def _check_object_constraints(self):
        super(self.__class__, self)._check_object_constraints()

        start_time = self.get('start_time')
        stop_time = self.get('stop_time')

        if start_time and stop_time and stop_time <= start_time:
            msg = "{0.id} 'stop_time' must be later than 'start_time'"
            raise ValueError(msg.format(self))

class Sighting(_RelationshipObject):
    """For more detailed information on this object's properties, see
    `the STIX 2.1 specification <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_a795guqsap3r>`__.
    """

    _type = 'sighting'
    _properties = OrderedDict([
        ('type', TypeProperty(_type, spec_version='2.1')),
        ('spec_version', StringProperty(fixed='2.1')),
        ('id', IDProperty(_type, spec_version='2.1')),
        ('created_by_ref', ReferenceProperty(valid_types='identity', spec_version='2.1')),
        ('created', TimestampProperty(default=lambda: NOW, precision='millisecond', precision_constraint='min')),
        ('modified', TimestampProperty(default=lambda: NOW, precision='millisecond', precision_constraint='min')),
        ('description', StringProperty()),
        ('first_seen', TimestampProperty()),
        ('last_seen', TimestampProperty()),
        ('count', IntegerProperty(min=0, max=999999999)),
        ('sighting_of_ref', ReferenceProperty(valid_types="SDO", spec_version='2.1', required=True)),
        ('observed_data_refs', ListProperty(ReferenceProperty(valid_types='observed-data', spec_version='2.1'))),
        ('where_sighted_refs', ListProperty(ReferenceProperty(valid_types=['identity', 'location'], spec_version='2.1'))),
        ('summary', BooleanProperty(default=lambda: False)),
        ('revoked', BooleanProperty(default=lambda: False)),
        ('labels', ListProperty(StringProperty)),
        ('confidence', IntegerProperty()),
        ('lang', StringProperty()),
        ('external_references', ListProperty(ExternalReference)),
        ('object_marking_refs', ListProperty(ReferenceProperty(valid_types='marking-definition', spec_version='2.1'))),
        ('granular_markings', ListProperty(GranularMarking)),
        ('extensions', ThreatExtensionsProperty(spec_version='2.1')),
    ])

    # Explicitly define the first kwargs to make readable Sighting declarations.
    def __init__(self, sighting_of_ref=None, **kwargs):
        # Allow sighting_of_ref as a positional arg.
        if sighting_of_ref and not kwargs.get('sighting_of_ref'):
            kwargs['sighting_of_ref'] = sighting_of_ref

        super(Sighting, self).__init__(**kwargs)

    def _check_object_constraints(self):
        super(self.__class__, self)._check_object_constraints()

        first_seen = self.get('first_seen')
        last_seen = self.get('last_seen')

        if first_seen and last_seen and last_seen < first_seen:
            msg = "{0.id} 'last_seen' must be greater than or equal to 'first_seen'"
            raise ValueError(msg.format(self))





class ExtensionDefinition(_STIXBase21):
    """For more detailed information on this object's properties, see
    `the STIX 2.1 specification <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_32j232tfvtly>`__.
    """

    _type = 'extension-definition'
    _properties = OrderedDict([
        ('type', TypeProperty(_type, spec_version='2.1')),
        ('spec_version', StringProperty(fixed='2.1')),
        ('id', IDProperty(_type, spec_version='2.1')),
        ('created_by_ref', ReferenceProperty(valid_types='identity', spec_version='2.1', required=True)),
        ('created', TimestampProperty(default=lambda: NOW, precision='millisecond', precision_constraint='min')),
        ('modified', TimestampProperty(default=lambda: NOW, precision='millisecond', precision_constraint='min')),
        ('name', StringProperty(required=True)),
        ('description', StringProperty()),
        ('schema', StringProperty(required=True)),
        ('version', StringProperty(required=True)),
        ('extension_types', ListProperty(EnumProperty(allowed=EXTENSION_TYPE), required=True)),
        ('extension_properties', ListProperty(StringProperty)),
        ('revoked', BooleanProperty(default=lambda: False)),
        ('labels', ListProperty(StringProperty)),
        ('external_references', ListProperty(ExternalReference)),
        ('object_marking_refs', ListProperty(ReferenceProperty(valid_types='marking-definition', spec_version='2.1'))),
        ('granular_markings', ListProperty(GranularMarking)),
    ])