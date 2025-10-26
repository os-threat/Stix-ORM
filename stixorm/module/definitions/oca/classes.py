"""Python CACAO Stix Class Definitions """
from typing import Self
import json
import pathlib
from collections import OrderedDict

from stixorm.module.typedb_lib.factories.mappings_factory import get_mapping_factory_instance

from stix2.exceptions import (
    AtLeastOnePropertyError
)
from stix2.properties import (
    BooleanProperty, BinaryProperty, ExtensionsProperty, IDProperty, IntegerProperty, ListProperty,
    OpenVocabProperty, ReferenceProperty, StringProperty, FloatProperty, HexProperty,
    TimestampProperty, TypeProperty, EmbeddedObjectProperty, DictionaryProperty,
    HashesProperty
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
    PROCESSOR_ARCHITECTURE, TOOL_TYPE, HASHING_ALGORITHM, ACCOUNT_TYPE,
)


import logging

from stixorm.module.definitions.property_definitions import OSThreatReference, OSThreatExtensionsProperty


logger = logging.getLogger(__name__)

valid_obj =  get_mapping_factory_instance().get_all_types()
# i) allows x- prefix see properties.py line 592 obj_type.startswith("x-") and
# ii) allows non stix definitiosn to be added see properties.py line 592 is_object(obj_type, self.spec_version)


############################################################################################
#
# SDO Definitions
#
############################################################################################



class BehaviorExt(_Extension):
    """For more detailed information on this object's properties, see
    `the  https://github.com/os-threat/oca-stix-extensions/blob/main/2.x/SDO/x-oca-behavior.md`__.
    """

    _type = "extension-definition--9c59fd79-4215-4ba2-920d-3e4f320e1e62"
    _properties = OrderedDict([
        ('extension_type', StringProperty(fixed='new-sdo')),
    ])


class Behavior(_DomainObject):
    """For more detailed information on this object's properties, see
    `the OCA documentation  https://github.com/os-threat/oca-stix-extensions/blob/main/2.x/SDO/x-oca-behavior.md`__.
    """
    _type = 'x-oca-behavior'
    _properties = OrderedDict([
        ('type', TypeProperty(_type, spec_version='2.1')),
        ('spec_version', StringProperty(fixed='2.1')),
        ('id', IDProperty(_type, spec_version='2.1')),
        ('created_by_ref', ReferenceProperty(valid_types='identity', spec_version='2.1')),
        ('created', TimestampProperty(default=lambda: NOW, precision='millisecond', precision_constraint='min')),
        ('modified', TimestampProperty(default=lambda: NOW, precision='millisecond', precision_constraint='min')),
        ('name', StringProperty(required=True)),
        ('description', StringProperty()),
        ('behavior_class', StringProperty()),
        ('tactic', StringProperty()),
        ('technique', StringProperty()),
        ('first_seen', TimestampProperty(default=lambda: NOW, precision='millisecond', precision_constraint='min')),
        ('platforms',  DictionaryProperty(spec_version='2.1')),
        ('labels', ListProperty(StringProperty)),
        ('confidence', IntegerProperty()),
        ('lang', StringProperty()),
        ('external_references', ListProperty(ExternalReference)),
        ('object_marking_refs', ListProperty(ReferenceProperty(valid_types='marking-definition', spec_version='2.1'))),
        ('granular_markings', ListProperty(GranularMarking)),
        ('revoked', BooleanProperty(default=lambda: False)),
        ('extensions', OSThreatExtensionsProperty(spec_version='2.1')),
    ])



class CoAPlaybookExt(_Extension):
    """For more detailed information on this object's properties, see
    `the  https://github.com/os-threat/oca-stix-extensions/blob/main/2.x/SDO/x-oca-coa-playbook-ext.md
    """

    _type = 'extension-definition--bbc1d5c8-7ddc-4e89-be9c-f33ad02d71dd'
    _properties = OrderedDict([
        ('extension_type', StringProperty(fixed='property-extension')),
        ('playbooks', DictionaryProperty(spec_version='2.1')),
    ])


class PlaybookExt(_Extension):
    """For more detailed information on this object's properties, see
    `the  https://github.com/os-threat/oca-stix-extensions/blob/main/2.x/SDO/x-oca-playbook.md`__.
    """

    _type = "extension-definition--809c4d84-7a6e-4039-97b4-da9fea03fcf9"
    _properties = OrderedDict([
        ('extension_type', StringProperty(fixed='new-sdo')),
    ])


class Playbook(_DomainObject):
    """For more detailed information on this object's properties, see
    `the OCA documentation  https://github.com/os-threat/oca-stix-extensions/blob/main/2.x/SDO/x-oca-playbook.md
    """
    _type = 'x-oca-playbook'
    _properties = OrderedDict([
        ('type', TypeProperty(_type, spec_version='2.1')),
        ('spec_version', StringProperty(fixed='2.1')),
        ('id', IDProperty(_type, spec_version='2.1')),
        ('created_by_ref', ReferenceProperty(valid_types='identity', spec_version='2.1')),
        ('created', TimestampProperty(default=lambda: NOW, precision='millisecond', precision_constraint='min')),
        ('modified', TimestampProperty(default=lambda: NOW, precision='millisecond', precision_constraint='min')),
        ('name', StringProperty(required=True)),
        ('description', StringProperty()),
        ('playbook_id', StringProperty()),
        ('playbook_creator', ReferenceProperty(valid_types='identity', spec_version='2.1')),
        ('playbook_creation_time', TimestampProperty(default=lambda: NOW, precision='millisecond', precision_constraint='min')),
        ('playbook_modification_time', TimestampProperty(default=lambda: NOW, precision='millisecond', precision_constraint='min')),
        ('playbook_format',  ListProperty(StringProperty)),
        ('is_playbook_template', BooleanProperty()),
        ('playbook_type', ListProperty(StringProperty)),
        ('playbook_impact', IntegerProperty()),
        ('playbook_severity', IntegerProperty()),
        ('playbook_priority', IntegerProperty()),
        ('playbook_bin', StringProperty()),
        ('playbook_url', StringProperty()),
        ('playbook_hashes', HashesProperty(HASHING_ALGORITHM, spec_version="2.1")),
        ('labels', ListProperty(StringProperty)),
        ('confidence', IntegerProperty()),
        ('lang', StringProperty()),
        ('external_references', ListProperty(ExternalReference)),
        ('object_marking_refs', ListProperty(ReferenceProperty(valid_types='marking-definition', spec_version='2.1'))),
        ('granular_markings', ListProperty(GranularMarking)),
        ('revoked', BooleanProperty(default=lambda: False)),
        ('extensions', OSThreatExtensionsProperty(spec_version='2.1')),
    ])




class OCAAnalyticSubObject(_STIXBase21):
    """For more detailed information on this object's properties, see
    https://github.com/os-threat/oca-stix-extensions/blob/main/2.x/SDO/x-oca-detection.md
    """
    _properties = OrderedDict([
        ('type', StringProperty()),
        ('rule', StringProperty()),
    ])


class DetectionExt(_Extension):
    """For more detailed information on this object's properties, see
    `the  https://github.com/os-threat/oca-stix-extensions/blob/main/2.x/SDO/x-oca-detection.md
    """

    _type = "extension-definition--c4690e13-107e-4796-8158-0dcf1ae7bc89"
    _properties = OrderedDict([
        ('extension_type', StringProperty(fixed='new-sdo')),
    ])


class Detection(_DomainObject):
    """For more detailed information on this object's properties, see
    `the https://github.com/os-threat/oca-stix-extensions/blob/main/2.x/SDO/x-oca-detection.md
    """
    _type = 'x-oca-detection'
    _properties = OrderedDict([
        ('type', TypeProperty(_type, spec_version='2.1')),
        ('spec_version', StringProperty(fixed='2.1')),
        ('id', IDProperty(_type, spec_version='2.1')),
        ('created_by_ref', ReferenceProperty(valid_types='identity', spec_version='2.1')),
        ('created', TimestampProperty(default=lambda: NOW, precision='millisecond', precision_constraint='min')),
        ('modified', TimestampProperty(default=lambda: NOW, precision='millisecond', precision_constraint='min')),
        ('name', StringProperty(required=True)),
        ('description', StringProperty()),
        ('analytic', EmbeddedObjectProperty(type=OCAAnalyticSubObject)),
        ('labels', ListProperty(StringProperty)),
        ('confidence', IntegerProperty()),
        ('lang', StringProperty()),
        ('external_references', ListProperty(ExternalReference)),
        ('object_marking_refs', ListProperty(ReferenceProperty(valid_types='marking-definition', spec_version='2.1'))),
        ('granular_markings', ListProperty(GranularMarking)),
        ('revoked', BooleanProperty(default=lambda: False)),
        ('extensions', OSThreatExtensionsProperty(spec_version='2.1')),
    ])


class DetectorExt(_Extension):
    """For more detailed information on this object's properties, see
    `the  https://github.com/os-threat/oca-stix-extensions/blob/main/2.x/SDO/x-oca-detector.md
    """

    _type = "extension-definition--5cccba5c-0be4-450c-8672-b66e98515754"
    _properties = OrderedDict([
        ('extension_type', StringProperty(fixed='new-sdo')),
    ])


class Detector(_DomainObject):
    """For more detailed information on this object's properties, see
    `the https://github.com/os-threat/oca-stix-extensions/blob/main/2.x/SDO/x-oca-detector.md
    """
    _type = 'x-oca-detector'
    _properties = OrderedDict([
        ('type', TypeProperty(_type, spec_version='2.1')),
        ('spec_version', StringProperty(fixed='2.1')),
        ('id', IDProperty(_type, spec_version='2.1')),
        ('created_by_ref', ReferenceProperty(valid_types='identity', spec_version='2.1')),
        ('created', TimestampProperty(default=lambda: NOW, precision='millisecond', precision_constraint='min')),
        ('modified', TimestampProperty(default=lambda: NOW, precision='millisecond', precision_constraint='min')),
        ('name', StringProperty(required=True)),
        ('description', StringProperty()),
        ('cpe', StringProperty()),
        ('valid_until', TimestampProperty(default=lambda: NOW, precision='millisecond', precision_constraint='min')),
        ('vendor', StringProperty()),
        ('vendor_url', StringProperty()),
        ('product', StringProperty()),
        ('product_url', StringProperty()),
        ('product_version', StringProperty()),
        ('detection_types', ListProperty(StringProperty)),
        ('detector_data_categories', ListProperty(StringProperty)),
        ('detector_data_sources', ListProperty(StringProperty)),
        ('labels', ListProperty(StringProperty)),
        ('confidence', IntegerProperty()),
        ('lang', StringProperty()),
        ('external_references', ListProperty(ExternalReference)),
        ('object_marking_refs', ListProperty(ReferenceProperty(valid_types='marking-definition', spec_version='2.1'))),
        ('granular_markings', ListProperty(GranularMarking)),
        ('revoked', BooleanProperty(default=lambda: False)),
        ('extensions', OSThreatExtensionsProperty(spec_version='2.1')),
    ])



class HighValueToolExt(_Extension):
    """For more detailed information on this object's properties, see
    `the  https://github.com/os-threat/oca-stix-extensions/blob/main/2.x/SDO/x-oca-coa-playbook-ext.md
    """

    _type = 'extension-definition--fb58a27d-32d2-4b8d-9705-e3cfd2d3dcdf'
    _properties = OrderedDict([
        ('extension_type', StringProperty(fixed='property-extension')),
        ('high_value_target_attributes', ListProperty(StringProperty)),
    ])





############################################################################################
#
# OCA Extensions to Existing SCO's
#
############################################################################################
#
# OCA Extended File SCO
class UnixFileSubObject(_STIXBase21):
    """For more detailed information on this object's properties, see
    `https://github.com/os-threat/oca-stix-extensions/blob/main/2.x/SCO/custom-file.md
    """
    _properties = OrderedDict([
        ('device', StringProperty()),
        ('gid', IntegerProperty()),
        ('group', StringProperty()),
        ('inode', IntegerProperty()),
        ('mode', StringProperty()),
    ])


class CodeSignatureSubObject(_STIXBase21):
    """For more detailed information on this object's properties, see
    https://github.com/os-threat/oca-stix-extensions/blob/main/2.x/SCO/custom-file.md
    """
    _properties = OrderedDict([
        ('exists', BooleanProperty()),
        ('status', StringProperty()),
        ('subject_name', StringProperty()),
        ('trusted', BooleanProperty()),
        ('valid', BooleanProperty()),
    ])


class OCAFileExt(_Extension):
    """For more detailed information on this object's properties, see
    `the __.
    """

    _type = 'extension-definition--23676abf-481e-4fee-ac8c-e3d0947287a4'
    _properties = OrderedDict([
        ('extension_type', StringProperty(fixed='new-sco'))
    ])

class OCAFile(_Observable):
    """For more detailed information on this object's properties, see
    `the OCA https://github.com/os-threat/oca-stix-extensions/blob/main/2.x/SCO/custom-file.md
    """

    _type = 'file'
    _properties = OrderedDict([
        ('type', TypeProperty(_type, spec_version='2.1')),
        ('spec_version', StringProperty(fixed='2.1')),
        ('id', IDProperty(_type, spec_version='2.1')),
        ('created', TimestampProperty(default=lambda: NOW, precision='millisecond', precision_constraint='min')),
        ('x_attributes', ListProperty(StringProperty)),
        ('x_extension', StringProperty()),
        ('x_path', StringProperty()),
        ('x_target_path', StringProperty()),
        ('x_type', StringProperty()),
        ('x_unix', EmbeddedObjectProperty(type=UnixFileSubObject)),
        ('x_owner_ref', ReferenceProperty(valid_types='user-account', spec_version='2.1')),
        ('x_win_drive_letter', StringProperty()),
        ('x_software_ref', ReferenceProperty(valid_types='software', spec_version='2.1')),
        ('x_code_signature', EmbeddedObjectProperty(type=CodeSignatureSubObject)),
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
        ('extensions', OSThreatExtensionsProperty(spec_version='2.1')),
    ])
    _id_contributing_properties = ["hashes", "name", "parent_directory_ref", "extensions"]

################################################################################
# OCA Extended Nwtwork Traffic SCO

# OCA Network Traffic RITA extension
class OCANetworkTrafficRITAExt(_Extension):
    """For more detailed information on this object's properties, see
    `https://github.com/os-threat/oca-stix-extensions/blob/main/2.x/SCO/network-traffic-ext.md
    """
    _type = 'extension-definition--3b7505ce-2a18-496e-aa58-311dac6c1473'
    _properties = OrderedDict([
        ('extension_type', StringProperty(fixed='property-extension')),
        ('connections', IntegerProperty()),
        ('score', FloatProperty()),
        ('computer', StringProperty()),
    ])



# Name Ref Object
class NameRefSubObject(_STIXBase21):
    """For more detailed information on this object's properties, see
    https://github.com/os-threat/oca-stix-extensions/blob/main/2.x/SCO/network-traffic-ext.md
    """
    _properties = OrderedDict([
        ('name_ref', ReferenceProperty(valid_types='domain-name', spec_version='2.1')),
    ])



# DNS extensions

class DNSExt(_Extension):
    """For more detailed information on this object's properties, see
    `https://github.com/os-threat/oca-stix-extensions/blob/main/2.x/SCO/dns-ext.md
    """
    _type = 'dns-ext'
    _properties = OrderedDict([
        ('question', EmbeddedObjectProperty(type=NameRefSubObject)),
        ('resolved_ip_refs', ListProperty(ReferenceProperty(valid_types=['ipv4-addr', 'ipv6-addr'], spec_version='2.1'))),
    ])


# VLan Sub Object
class NetworkTrafficVLanSubObject(_STIXBase21):
    """For more detailed information on this object's properties, see
    https://github.com/os-threat/oca-stix-extensions/blob/main/2.x/SCO/network-traffic-ext.md
    """
    _properties = OrderedDict([
        ('id', StringProperty()),
        ('name', StringProperty()),
        ('inner',  EmbeddedObjectProperty(type=Self)),
    ])


# OCA Network Traffic Class
class OCANetworkTraffic(_Observable):
    """For more detailed information on this object's properties, see
    `https://github.com/os-threat/oca-stix-extensions/blob/main/2.x/SCO/network-traffic-ext.md
    """

    _type = 'network-traffic'
    _properties = OrderedDict([
        ('type', TypeProperty(_type, spec_version='2.1')),
        ('spec_version', StringProperty(fixed='2.1')),
        ('id', IDProperty(_type, spec_version='2.1')),
        ('x_name', StringProperty()),
        ('x_application', StringProperty()),
        ('x_direction', StringProperty()),
        ('x_forwarded_ip', ReferenceProperty(valid_types=['ipv4-addr', 'ipv6-addr'], spec_version='2.1')),
        ('x_community_id', StringProperty()),
        ('x_vlan',  EmbeddedObjectProperty(type=NetworkTrafficVLanSubObject)),
        ('start', TimestampProperty()),
        ('end', TimestampProperty()),
        ('is_active', BooleanProperty()),
        ('src_ref', ReferenceProperty(valid_types=['ipv4-addr', 'ipv6-addr', 'mac-addr', 'domain-name'], spec_version='2.1')),
        ('dst_ref', ReferenceProperty(valid_types=['ipv4-addr', 'ipv6-addr', 'mac-addr', 'domain-name'], spec_version='2.1')),
        ('src_port', IntegerProperty(min=0, max=65535)),
        ('dst_port', IntegerProperty(min=0, max=65535)),
        ('protocols', ListProperty(StringProperty, required=True)),
        ('src_byte_count', IntegerProperty(min=0)),
        ('dst_byte_count', IntegerProperty(min=0)),
        ('src_packets', IntegerProperty(min=0)),
        ('dst_packets', IntegerProperty(min=0)),
        ('ipfix', DictionaryProperty(spec_version='2.1')),
        ('src_payload_ref', ReferenceProperty(valid_types='artifact', spec_version='2.1')),
        ('dst_payload_ref', ReferenceProperty(valid_types='artifact', spec_version='2.1')),
        ('encapsulates_refs', ListProperty(ReferenceProperty(valid_types='network-traffic', spec_version='2.1'))),
        ('encapsulated_by_ref', ReferenceProperty(valid_types='network-traffic', spec_version='2.1')),
        ('object_marking_refs', ListProperty(ReferenceProperty(valid_types='marking-definition', spec_version='2.1'))),
        ('granular_markings', ListProperty(GranularMarking)),
        ('defanged', BooleanProperty(default=lambda: False)),
        ('extensions', OSThreatExtensionsProperty(spec_version='2.1')),
    ])
    _id_contributing_properties = ["start", "end", "src_ref", "dst_ref", "src_port", "dst_port", "protocols", "extensions"]

    def _check_object_constraints(self):
        super(OCANetworkTraffic, self)._check_object_constraints()
        self._check_at_least_one_property(['src_ref', 'dst_ref'])

        start = self.get('start')
        end = self.get('end')
        is_active = self.get('is_active')

        if end and is_active is not False:
            msg = "{0.id} 'is_active' must be False if 'end' is present"
            raise ValueError(msg.format(self))

        if end and is_active is True:
            msg = "{0.id} if 'is_active' is True, 'end' must not be included"
            raise ValueError(msg.format(self))

        if start and end and end < start:
            msg = "{0.id} 'end' must be greater than or equal to 'start'"
            raise ValueError(msg.format(self))



#####################################################################################################
# OCA Extended Process SCO
class OCAProcess(_Observable):
    """For more detailed information on this object's properties, see
    `https://github.com/os-threat/oca-stix-extensions/blob/main/2.x/SCO/custom-process.md
    """

    _type = 'process'
    _properties = OrderedDict([
        ('type', TypeProperty(_type, spec_version='2.1')),
        ('spec_version', StringProperty(fixed='2.1')),
        ('id', IDProperty(_type, spec_version='2.1')),
        ('x_window_title', StringProperty()),
        ('x_thread_id', IntegerProperty()),
        ('x_unique_id', StringProperty()),
        ('x_exit_code', IntegerProperty()),
        ('x_uptime', IntegerProperty()),
        ('name', StringProperty()),
        ('x_tags', ListProperty(StringProperty)),
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
        ('extensions', OSThreatExtensionsProperty(spec_version='2.1')),
    ])
    _id_contributing_properties = []

    def _check_object_constraints(self):
        # no need to check windows-service-ext, since it has a required property
        super(OCAProcess, self)._check_object_constraints()
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

#
# OCA Extended Process SCO Extension


class OCAProcessExt(_Extension):
    """For more detailed information on this object's properties, see
    `the  https://github.com/os-threat/oca-stix-extensions/blob/main/2.x/SCO/process-ext.md
    """

    _type = 'extension-definition--f9dbe89c-0030-4a9d-8b78-0dcd0a0de874'
    _properties = OrderedDict([
        ('extension_type', StringProperty(fixed='property-extension')),
        ('operation_type', StringProperty()),
        ('computer', StringProperty()),
        ('name', StringProperty()),
        ('win_event_code', StringProperty()),
        ('creator_user', StringProperty()),
    ])






############################################################################################
# OCA Extended Software SCO
class OCASoftware(_Observable):
    """For more detailed information on this object's properties, see
    `the STIX 2.1 specification <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_7rkyhtkdthok>`__.
    """

    _type = 'software'
    _properties = OrderedDict([
        ('type', TypeProperty(_type, spec_version='2.1')),
        ('spec_version', StringProperty(fixed='2.1')),
        ('id', IDProperty(_type, spec_version='2.1')),
        ('x_product', StringProperty()),
        ('x_description', StringProperty()),
        ('name', StringProperty(required=True)),
        ('cpe', StringProperty()),
        ('swid', StringProperty()),
        ('languages', ListProperty(StringProperty)),
        ('vendor', StringProperty()),
        ('version', StringProperty()),
        ('object_marking_refs', ListProperty(ReferenceProperty(valid_types='marking-definition', spec_version='2.1'))),
        ('granular_markings', ListProperty(GranularMarking)),
        ('defanged', BooleanProperty(default=lambda: False)),
        ('extensions', OSThreatExtensionsProperty(spec_version='2.1')),
    ])
    _id_contributing_properties = ["name", "cpe", "swid", "vendor", "version"]



#
# OCA Extended User Account SCO
class UserGroupSubObject(_STIXBase21):
    """For more detailed information on this object's properties, see
    https://github.com/os-threat/oca-stix-extensions/blob/main/2.x/SCO/network-traffic-ext.md
    """
    _properties = OrderedDict([
        ('domain', StringProperty()),
        ('gid', StringProperty()),
        ('name', StringProperty()),
    ])




class OCAUserAccount(_Observable):
    """For more detailed information on this object's properties, see
    `the STIX 2.1 specification <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_azo70vgj1vm2>`__.
    """

    _type = 'user-account'
    _properties = OrderedDict([
        ('type', TypeProperty(_type, spec_version='2.1')),
        ('spec_version', StringProperty(fixed='2.1')),
        ('id', IDProperty(_type, spec_version='2.1')),
        ('x_domain', StringProperty()),
        ('x_hash', StringProperty()),
        ('x_group',  EmbeddedObjectProperty(type=UserGroupSubObject)),
        ('user_id', StringProperty()),
        ('credential', StringProperty()),
        ('account_login', StringProperty()),
        ('account_type', OpenVocabProperty(ACCOUNT_TYPE)),
        ('display_name', StringProperty()),
        ('is_service_account', BooleanProperty()),
        ('is_privileged', BooleanProperty()),
        ('can_escalate_privs', BooleanProperty()),
        ('is_disabled', BooleanProperty()),
        ('account_created', TimestampProperty()),
        ('account_expires', TimestampProperty()),
        ('credential_last_changed', TimestampProperty()),
        ('account_first_login', TimestampProperty()),
        ('account_last_login', TimestampProperty()),
        ('object_marking_refs', ListProperty(ReferenceProperty(valid_types='marking-definition', spec_version='2.1'))),
        ('granular_markings', ListProperty(GranularMarking)),
        ('defanged', BooleanProperty(default=lambda: False)),
        ('extensions', OSThreatExtensionsProperty(spec_version='2.1')),
    ])
    _id_contributing_properties = ["account_type", "user_id", "account_login"]




############################################################################################
# OCA Extended Windows Registry Key SCO


class OCAWindowsRegistryKeyExt(_Extension):
    """For more detailed information on this object's properties, see
    `the https://github.com/os-threat/oca-stix-extensions/blob/main/2.x/SCO/windows-registry-key-ext.md
    """

    _type = 'extension-definition--2cf8c8c2-69f5-40f7-aa34-efcef2b912b1'
    _properties = OrderedDict([
        ('extension_type', StringProperty(fixed='property-extension')),
        ('operation_type', StringProperty()),
        ('computer', StringProperty()),
        ('new_value', StringProperty()),
        ('win_event_code', StringProperty()),
        ('process_id', StringProperty()),
        ('process_name', StringProperty()),
    ])



############################################################################################
#
# OCA New SCO's
#
############################################################################################

##########################################################################################
# OCA Extended File SCO



class OCAFinding(_Observable):
    """For more detailed information on this object's properties, see
    `https://github.com/os-threat/oca-stix-extensions/blob/main/2.x/SCO/x-ibm-finding.md
    """

    _type = 'x-ibm-finding'
    _properties = OrderedDict([
        ('type', TypeProperty(_type, spec_version='2.1')),
        ('spec_version', StringProperty(fixed='2.1')),
        ('id', IDProperty(_type, spec_version='2.1')),
        ('finding_type', StringProperty(required=True)),
        ('x_window_title', StringProperty()),
        ('name', StringProperty()),
        ('description', StringProperty()),
        ('alert_id', StringProperty()),
        ('src_ip_ref', ReferenceProperty(valid_types=['ipv4-addr', 'ipv6-addr'], spec_version='2.1')),
        ('dst_ip_ref', ReferenceProperty(valid_types=['ipv4-addr', 'ipv6-addr'], spec_version='2.1')),
        ('src_os_ref', ReferenceProperty(valid_types='software', spec_version='2.1')),
        ('dst_os_ref', ReferenceProperty(valid_types='software', spec_version='2.1')),
        ('src_application_ref', ReferenceProperty(valid_types='software', spec_version='2.1')),
        ('dst_application_ref', ReferenceProperty(valid_types='software', spec_version='2.1')),
        ('src_geo_ref', OSThreatReference(valid_types='x-oca-geo', spec_version='2.1')),
        ('src_device', StringProperty()),
        ('dst_device', StringProperty()),
        ('src_application_user_ref', ReferenceProperty(valid_types='user-account', spec_version='2.1')),
        ('dst_application_user_ref', ReferenceProperty(valid_types='user-account', spec_version='2.1')),
        ('src_database_user_ref', ReferenceProperty(valid_types='user-account', spec_version='2.1')),
        ('dst_database_user_ref', ReferenceProperty(valid_types='user-account', spec_version='2.1')),
        ('src_os_user_ref', ReferenceProperty(valid_types='user-account', spec_version='2.1')),
        ('dst_os_user_ref', ReferenceProperty(valid_types='user-account', spec_version='2.1')),
        ('severity', StringProperty()),
        ('confidence', StringProperty()),
        ('magnitude', IntegerProperty()),
        ('rule_trigger_count', IntegerProperty()),
        ('rule_names', StringProperty()),
        ('event_count', StringProperty()),
        ('time_observed', StringProperty()),
        ('start', IntegerProperty()),
        ('end', IntegerProperty()),
        ('ttp_tagging_refs', ListProperty(OSThreatReference(valid_types=['x-ibm-ttp-tagging'], spec_version='2.1'))),
        ('ioc_refs', ListProperty(ReferenceProperty(valid_types=['file', 'ipv4-addr', 'ipv6-addr', 'domain', 'url'], spec_version='2.1'))),
        ('object_marking_refs', ListProperty(ReferenceProperty(valid_types='marking-definition', spec_version='2.1'))),
        ('granular_markings', ListProperty(GranularMarking)),
        ('defanged', BooleanProperty(default=lambda: False)),
        ('extensions', OSThreatExtensionsProperty(spec_version='2.1')),
    ])
    _id_contributing_properties = ["value"]


##########################################################################################
# OCA Extended TTP-Tagging SCO



class OCATaggingExt(_Extension):
    """For more detailed information on this object's properties, see
    `https://github.com/os-threat/oca-stix-extensions/blob/main/2.x/SCO/x-ibm-ttp-tagging.md
    """

    _type = 'mitre-attack-ext'
    _properties = OrderedDict([
        ('tactic_id', StringProperty()),
        ('tactic_url', StringProperty()),
        ('tactic_name', StringProperty()),
        ('technique_id', StringProperty()),
        ('technique_url', StringProperty()),
        ('technique_name', StringProperty()),
    ])


class OCATagging(_Observable):
    """For more detailed information on this object's properties, see
    `the xxxxxxxxx`__.
    """

    _type = 'x-ibm-ttp-tagging'
    _properties = OrderedDict([
        ('type', TypeProperty(_type, spec_version='2.1')),
        ('spec_version', StringProperty(fixed='2.1')),
        ('id', IDProperty(_type, spec_version='2.1')),
        ('name', StringProperty(required=True)),
        ('url', StringProperty()),
        ('confidence', FloatProperty()),
        ('kill_chain_phases', ListProperty(KillChainPhase)),
        ('object_marking_refs', ListProperty(ReferenceProperty(valid_types='marking-definition', spec_version='2.1'))),
        ('granular_markings', ListProperty(GranularMarking)),
        ('defanged', BooleanProperty(default=lambda: False)),
        ('extensions', OSThreatExtensionsProperty(spec_version='2.1')),
    ])
    _id_contributing_properties = ["value"]


##########################################################################################
# OCA Asset SCO


#
# OCA Asset Sub Object

class OCAIntefaceSubObject(_STIXBase21):
    """For more detailed information on this object's properties, see
    https://github.com/os-threat/oca-stix-extensions/blob/main/2.x/SCO/x-oca-asset.md
    """
    _properties = OrderedDict([
        ('alias', StringProperty()),
        ('interface_id', StringProperty()),
        ('name', StringProperty()),
    ])


class OCATrafficSubObject(_STIXBase21):
    """For more detailed information on this object's properties, see
    https://github.com/os-threat/oca-stix-extensions/blob/main/2.x/SCO/x-oca-asset.md
    """
    _properties = OrderedDict([
        ('zone', StringProperty()),
        ('interfaces', ListProperty(EmbeddedObjectProperty(type=OCAIntefaceSubObject))),
    ])


class OCAPodExt(_Extension):
    """For more detailed information on this object's properties, see
    https://github.com/os-threat/oca-stix-extensions/blob/main/2.x/SCO/x-oca-asset.md
    """

    _type = 'x-oca-pod-ext'
    _properties = OrderedDict([
        ('type', StringProperty()),
        ('name', StringProperty()),
        ('ip_refs',  ListProperty(ReferenceProperty(valid_types=['ipv4-addr', 'ipv6-addr'], spec_version='2.1'))),
    ])


class OCAContainerExt(_Extension):
    """For more detailed information on this object's properties, see
    https://github.com/os-threat/oca-stix-extensions/blob/main/2.x/SCO/x-oca-asset.md
    """

    _type = 'x-oca-container-ext'
    _properties = OrderedDict([
        ('name', StringProperty()),
        ('container_id', StringProperty()),
        ('image_name', StringProperty()),
        ('image_id', StringProperty()),
        ('container_type', StringProperty()),
        ('privileged', BooleanProperty()),
    ])

class OCAAsset(_Observable):
    """For more detailed information on this object's properties, see
    `https://github.com/os-threat/oca-stix-extensions/blob/main/2.x/SCO/x-oca-asset.md
    """

    _type = 'x-oca-asset'
    _properties = OrderedDict([
        ('type', TypeProperty(_type, spec_version='2.1')),
        ('spec_version', StringProperty(fixed='2.1')),
        ('id', IDProperty(_type, spec_version='2.1')),
        ('created', TimestampProperty(default=lambda: NOW, precision='millisecond', precision_constraint='min')),
        ('modified', TimestampProperty(default=lambda: NOW, precision='millisecond', precision_constraint='min')),
        ('device_id', StringProperty()),
        ('hostname', StringProperty()),
        ('ip_refs',  ListProperty(ReferenceProperty(valid_types=['ipv4-addr', 'ipv6-addr'], spec_version='2.1'))),
        ('mac_refs', ListProperty(ReferenceProperty(valid_types='mac-addr', spec_version='2.1'))),
        ('os_ref', ReferenceProperty(valid_types='software', spec_version='2.1')),
        ('architecture', StringProperty()),
        ('uptime', StringProperty()),
        ('host_type', StringProperty()),
        ('host_id', StringProperty()),
        ('ingress', EmbeddedObjectProperty(type=OCATrafficSubObject)),
        ('egress', EmbeddedObjectProperty(type=OCATrafficSubObject)),
        ('geo_ref', OSThreatReference(valid_types='x-oca-geo', spec_version='2.1')),
        ('object_marking_refs', ListProperty(ReferenceProperty(valid_types='marking-definition', spec_version='2.1'))),
        ('granular_markings', ListProperty(GranularMarking)),
        ('defanged', BooleanProperty(default=lambda: False)),
        ('extensions', OSThreatExtensionsProperty(spec_version='2.1')),
    ])
    _id_contributing_properties = ["value"]



##########################################################################################
# OCA Event SCO


class OCAIAMExt(_Extension):
    """For more detailed information on this object's properties, see
    https://github.com/os-threat/oca-stix-extensions/blob/main/2.x/SCO/x-oca-event.md
    """

    _type = 'x-iam-ext'
    _properties = OrderedDict([
        ('result', StringProperty()),
        ('name', StringProperty()),
        ('sub_category', StringProperty()),
        ('realm', StringProperty()),
        ('application_id', StringProperty()),
        ('user_id', StringProperty()),
        ('application_type', StringProperty()),
        ('browser_agent', StringProperty()),
        ('application_name', StringProperty()),
        ('cause', StringProperty()),
        ('messageid', StringProperty()),
        ('target', StringProperty()),
        ('targetid', StringProperty()),
        ('targetid_realm', StringProperty()),
        ('targetid_username', StringProperty()),
        ('performedby_clientname', StringProperty()),
        ('performedby_realm', StringProperty()),
        ('performedby_username', StringProperty()),
        ('continent_name', StringProperty()),
        ('country_iso_code', StringProperty()),
        ('country_name', StringProperty()),
        ('city_name', StringProperty()),
        ('policy_action', StringProperty()),
        ('policy_name', StringProperty()),
        ('rule_name', StringProperty()),
        ('decision_reason', StringProperty()),
        ('location_lat', StringProperty()),
        ('location_lon', StringProperty()),
        ('risk_level', StringProperty()),
        ('risk_score', StringProperty()),
        ('deviceid', StringProperty()),
        ('is_device_compliant', StringProperty()),
        ('is_device_managed', StringProperty()),
        ('mdm_customerid', StringProperty()),
    ])

class OCAEvent(_Observable):
    """For more detailed information on this object's properties, see
    https://github.com/os-threat/oca-stix-extensions/blob/main/2.x/SCO/x-oca-event.md
    """

    _type = 'x-oca-event'
    _properties = OrderedDict([
        ('type', TypeProperty(_type, spec_version='2.1')),
        ('spec_version', StringProperty(fixed='2.1')),
        ('id', IDProperty(_type, spec_version='2.1')),
        ('created', TimestampProperty(default=lambda: NOW, precision='millisecond', precision_constraint='min')),
        ('modified', TimestampProperty(default=lambda: NOW, precision='millisecond', precision_constraint='min')),
        ('action', StringProperty()),
        ('category', ListProperty(StringProperty)),
        ('code', StringProperty()),
        ('description', StringProperty()),
        ('created', TimestampProperty(default=lambda: NOW, precision='millisecond', precision_constraint='min')),
        ('start', TimestampProperty(default=lambda: NOW, precision='millisecond', precision_constraint='min')),
        ('end', TimestampProperty(default=lambda: NOW, precision='millisecond', precision_constraint='min')),
        ('duration', IntegerProperty()),
        ('module', StringProperty()),
        ('original_ref',  ReferenceProperty(valid_types='artifact', spec_version='2.1')),
        ('provider', StringProperty()),
        ('agent', StringProperty()),
        ('host_ref',  OSThreatReference(valid_types='x-oca-asset', spec_version='2.1')),
        ('url_ref',  ReferenceProperty(valid_types='url', spec_version='2.1')),
        ('file_ref',  ReferenceProperty(valid_types='file', spec_version='2.1')),
        ('process_ref',  ReferenceProperty(valid_types='process', spec_version='2.1')),
        ('parent_process_ref',  ReferenceProperty(valid_types='process', spec_version='2.1')),
        ('cross_process_target_ref',  ReferenceProperty(valid_types='process', spec_version='2.1')),
        ('domain_ref',  ReferenceProperty(valid_types='domain-name', spec_version='2.1')),
        ('registry_ref',  ReferenceProperty(valid_types='windows-registry-key', spec_version='2.1')),
        ('network_ref',  ReferenceProperty(valid_types='network-traffic', spec_version='2.1')),
        ('ip_refs', ListProperty(ReferenceProperty(valid_types=['ipv4-addr', 'ipv6-addr'], spec_version='2.1'))),
        ('user_ref', ReferenceProperty(valid_types='user-account', spec_version='2.1')),
        ('severity', IntegerProperty()),
        ('timezone', StringProperty()),
        ('dataset', StringProperty()),
        ('pipe_name', StringProperty()),
        ('x_ttp_tagging_refs', ListProperty(OSThreatReference(valid_types='x-ibm-ttp-tagging', spec_version='2.1'))),
        ('object_marking_refs', ListProperty(ReferenceProperty(valid_types='marking-definition', spec_version='2.1'))),
        ('granular_markings', ListProperty(GranularMarking)),
        ('defanged', BooleanProperty(default=lambda: False)),
        ('extensions', OSThreatExtensionsProperty(spec_version='2.1')),
    ])
    _id_contributing_properties = ["value"]




##########################################################################################
# OCA locations SCO



class OCACoordinatesSubObject(_STIXBase21):
    """For more detailed information on this object's properties, see
    https://github.com/os-threat/oca-stix-extensions/blob/main/2.x/SCO/x-oca-geo.md
    """
    _properties = OrderedDict([
        ('lon', FloatProperty()),
        ('lat', FloatProperty()),
    ])


class OCAGeo(_Observable):
    """For more detailed information on this object's properties, see
    https://github.com/os-threat/oca-stix-extensions/blob/main/2.x/SCO/x-oca-geo.md
    """

    _type = 'x-oca-geo'
    _properties = OrderedDict([
        ('type', TypeProperty(_type, spec_version='2.1')),
        ('spec_version', StringProperty(fixed='2.1')),
        ('id', IDProperty(_type, spec_version='2.1')),
        ('created', TimestampProperty(default=lambda: NOW, precision='millisecond', precision_constraint='min')),
        ('modified', TimestampProperty(default=lambda: NOW, precision='millisecond', precision_constraint='min')),
        ('city_name', StringProperty()),
        ('continent_name', StringProperty()),
        ('country_iso_code', StringProperty()),
        ('country_name', StringProperty()),
        ('location', EmbeddedObjectProperty(type=OCACoordinatesSubObject)),
        ('name', StringProperty()),
        ('region_iso_code', StringProperty()),
        ('region_name', StringProperty()),
        ('time_zone', StringProperty()),
        ('object_marking_refs', ListProperty(ReferenceProperty(valid_types='marking-definition', spec_version='2.1'))),
        ('granular_markings', ListProperty(GranularMarking)),
        ('defanged', BooleanProperty(default=lambda: False)),
        ('extensions', OSThreatExtensionsProperty(spec_version='2.1')),
    ])
    _id_contributing_properties = ["value"]

