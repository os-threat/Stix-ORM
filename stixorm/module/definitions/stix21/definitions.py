##################################################
# 2. Dispatch Dicts to convert between:
#      - Stix2 Object Property Name --> TypeQL Name
#      - Stix 2 Object Type --> Dict Name
###################################################

#---------------------------------------------------
# 2.1) Stix Domain Object Dicts
#---------------------------------------------------
sdo_typeql_dict = {
  "type" :  "stix-type",
  "spec_version" : "spec-version",
  "id"  : "stix-id",
  "created_by_ref"  : "",
  "created"  : "created",
  "modified" : "modified",
  "revoked"  : "revoked",
  "labels"  : "labels",
  "confidence"  : "confidence",
  "lang"  : "langs",
  "external_references"  : "",
  "object_marking_refs"  : "",
  "granular_markings"  : "",
  "extensions"  : ""
}

attack_pattern_typeql_dict = {
  "name": "name",
  "description": "description",
  "aliases": "aliases",
  "kill_chain_phases": ""
}

campaign_typeql_dict = {
  "name": "name",
  "description": "description",
  "aliases": "aliases",
  "first_seen": "first-seen",
  "last_seen": "last-seen",
  "objective": "objective"
}

grouping_typeql_dict = {
  "name": "name",
  "description": "description",
  "context": "context",
  "object_refs": ""
}

course_of_action_typeql_dict = {
  "name": "name",
  "description": "description",	
  "action": "action"
}

identity_typeql_dict = {
  "name" :  "name",
  "description" :  "description",
  "roles" :  "stix-role",
  "identity_class" :  "identity-class",
  "sectors" :  "sector",
  "contact_information" :  "contact-information"
}

incident_typeql_dict = {
  "name": "name",
  "description": "description",
}

indicator_typeql_dict = {
  "name": "name",
  "description": "description",
  "pattern_version": "pattern-version",
  "indicator_types": "indicator-type",
  "pattern": "pattern",
  "pattern_type": "pattern-type",
  "valid_from": "valid-from",
  "valid_until": "valid-until",
  "kill_chain_phases": ""
}

infrastructure_typeql_dict = {
  "name": "name",
  "description": "description",
  "infrastructure_types": "infrastructure-types",
  "aliases": "aliases",
  "kill_chain_phases": "",
  "first_seen": "first-seen",
  "last_seen": "last-seen"
}

intrusion_set_typeql_dict = {
  "name": "name",
  "description": "description",
  "aliases": "aliases",
  "first_seen": "first-seen",
  "last_seen": "last-seen",
  "goals": "goals",
  "resource_level": "resource-level",
  "primary_motivation": "primary-motivation",
  "secondary_motivations": "secondary-motivations"
}

location_typeql_dict = {
  "name": "name",
  "description": "description",
  "latitude": "latitude",
  "longitude": "longitude",
  "precision": "precision",
  "region": "region",
  "country": "country",
  "administrative_area": "administrative-area",
  "city": "city",
  "street_address": "street-address",
  "postal_code": "postal-code"
}

malware_typeql_dict = {
  "name": "name",	
  "description": "description",
  "malware_types": "malware-types",
  "is_family": "is-family",
  "aliases": "aliases",
  "kill_chain_phases": "",
  "first_seen": "first-seen",
  "last_seen": "last-seen",
  "operating_system_refs": "",
  "architecture_execution_envs": "architecture-execution-envs",
  "implementation_languages": "implementation-languages",
  "capabilities": "capabilities",
  "sample_refs": ""
}

malware_analysis_typeql_dict = {
  "product": "product",
  "version": "version",
  "host_vm_ref": "",
  "operating_system_ref": "",
  "installed_software_refs": "",
  "configuration_version": "configuration-version",
  "modules": "modules",
  "analysis_engine_version": "analysis-engine-version",
  "analysis_definition_version": "analysis-definition-version",
  "submitted": "submitted",
  "analysis_started": "analysis-started",
  "analysis_ended": "analysis-ended",
  "result_name": "result-name",
  "result": "result",
  "analysis_sco_refs": "",
  "sample_ref": ""
}

note_type_dict = {
  "abstract": "abstract",
  "content": "content",
  "authors": "authors",
  "object_refs": ""
}

observed_data_typeql_dict = {
  "first_observed": "first-observed",
  "last_observed": "last-observed",
  "number_observed": "number-observed",
  "object_refs": ""
}

opinion_typeql_dict = {
  "explanation": "explanation",
  "authors": "authors",
  "opinion": "opinion-enum",
  "object_refs": ""
}

report_typeql_dict = {
  "name": "name",
  "description": "description",
  "report_types": "report-type",
  "published": "published",
  "object_refs": ""
}

threat_actor_typeql_dict = {        
  "name"  : "name",
  "description"  : "description",
  "threat_actor_types"  : "threat-actor-type",
  "aliases"  : "aliases",
  "first_seen"  : "first-seen",
  "last_seen"  : "last-seen",
  "roles"  : "stix-role",
  "goals"  : "goals",
  "sophistication"  : "sophistication",
  "resource_level"  : "resource-level",
  "primary_motivation"  : "primary-motivation",
  "secondary_motivations"  : "secondary-motivations",
  "personal_motivations"  : "personal-motivations"        
}

tool_typeql_dict = {
  "name": "name",
  "description": "description",
  "tool_types": "tool-type",
  "aliases": "aliases",
  "kill_chain_phases": "",
  "tool_version": "tool-version"
}

vulnerability_typeql_dict = {
  "name": "name",
  "description": "description"
}

kill_chain_phases_typeql_dict = {
  "kill_chain_name": "kill-chain-name",
  "phase_name": "phase-name"
  
}


#---------------------------------------------------
# 2.2) Stix Cyber Observable Object Dicts
#---------------------------------------------------

sco_base_typeql_dict = {
  "type" :  "stix-type",
  "spec_version" : "spec-version",
  "id"  : "stix-id",
  "created_by_ref"  : "",
  "revoked"  : "revoked",
  "labels"  : "labels",
  "confidence"  : "confidence",
  "lang"  : "langs",
  "external_references"  : "",
  "object_marking_refs"  : "",
  "granular_markings"  : "",
  "defanged"  : "defanged",
  "extensions"  : ""
}

artifact_typeql_dict = {
  "mime_type": "mime-type",
  "payload_bin": "payload-bin",
  "url": "url-link",
  "hashes": "",
  "encryption_algorithm": "encryption-algorithm",
  "decryption_key": "decryption-key"
}

autonomous_system_typeql_dict = {
    "number": "number",
    "name": "name",
    "rir": "rir"
}

directory_typeql_dict = {
    "path": "path",
    "path_enc": "path-enc",
    "ctime": "ctime",
    "mtime": "mtime",
    "atime": "atime",
    "contains_refs": "",
}


domain_name_typeql_dict = {
    "value": "stix-value",
    "resolves_to_refs": ""
}

email_addr_typeql_dict = {
    "value": "stix-value",
    "display_name": "display-name",
    "belongs_to_ref": ""
}

email_message_typeql_dict = {
    "is_multipart": "is-multipart",
    "date": "date",
    "content_type": "content-type",
    "from_ref": "",
    "sender_ref": "",
    "to_refs": "",
    "cc_refs": "",
    "bcc_refs": "",
    "message_id": "message-id",
    "subject": "subject",
    "received_lines": "received-lines",
    "additional_header_fields": "",
    "body": "body",
    "body_multipart": "",
    "raw_email_ref": ""
}

file_typeql_dict = {
    "hashes": "",
    "size": "size",
    "name": "name",
    "name_enc": "name-enc",
    "magic_number_hex": "magic-number-hex",
    "mime_type": "mime-type",
    "ctime": "ctime",
    "dtime": "dtime",
    "atime": "atime",
    "parent_directory_ref": "",
    "contains_refs": "",
    "content_ref": ""
}

ipv4_addr_typeql_dict = {
    "value": "stix-value",
    "resolves_to_refs": "",
    "belongs_to_refs": ""
}

ipv6_addr_typeql_dict = {
    "value": "stix-value",
    "resolves_to_refs": "",
    "belongs_to_refs": ""
}

mac_addr_typeql_dict = {
    "value": "stix-value"
}

mutex_typeql_dict = {
    "name": "name"
}

network_traffic_typeql_dict = {
    "start": "start",
    "end": "end",
    "is_active": "is-active",
    "src_ref": "",
    "dst_ref": "",
    "src_port": "src-port",
    "dst_port": "dst-port",
    "protocols": "protocols",
    "src_byte_count": "src-byte-count",
    "dst_byte_count": "dst-byte-count",
    "src_packets": "src-packets",
    "dst_packets": "dst-packets",
    "ipfix": "",
    "src_payload_ref": "",
    "dst_payload_ref": "",
    "encapsulates_refs": "",
    "encapsulated_by_ref": ""    
}

process_typeql_dict = {
    "is_hidden": "is-hidden",
    "pid": "pid",
    "created_time": "created-time",
    "cwd": "cwd",
    "command_line": "command-line",
    "environment_variables": "",
    "opened_connection_refs": "",
    "creator_user_ref": "",
    "image_ref": "",
    "parent_ref": "",
    "child_refs": ""   
    
}

software_typeql_dict = {
    "name": "name",
    "cpe": "cpe",
    "swid": "swid",
    "languages": "language",
    "vendor": "vendor",
    "version": "version"
}


url_typeql_dict = {
    "value": "stix-value"
}

user_account_typeql_dict = {
    "user_id": "user-id",
    "credential": "credential",
    "account_login": "account-login",
    "account_type": "account-type",
    "display_name": "display-name",
    "is_service_account": "is-service-account",
    "is_privileged": "is-privileged",
    "can_escalate_privs": "can-escalate-privs",
    "is_disabled": "is-disabled",
    "account_created": "account-created",
    "account_expires": "account-expires",
    "credential_last_changed": "credential-last-changed",
    "account_first_login": "account-first-login",
    "account_last_login": "account-last-login"
}

windows_registry_key_typeql_dict = {
    "key": "attribute-key",
    "values": "",
    "modified_time": "modified-time",
    "creator_user_ref": "",
    "number_of_subkeys": "number-subkeys"
}

windows_registry_value_typeql_dict = {
    "name": "name",
    "data": "data",
    "data_type": "data-type"
}

x509_certificate_typeql_dict = {
    "is_self_signed": "is-self-signed",
    "hashes": "",
    "version": "version",
    "serial_number": "serial-number",
    "signature_algorithm": "signature-algorithm",
    "issuer": "issuer",
    "validity_not_before": "validity-not-before",
    "validity_not_after": "validity-not-after",
    "subject": "subject",
    "subject_public_key_algorithm": "subject-public-key-algorithm",
    "subject_public_key_modulus": "subject-public-key-modulus",
    "subject_public_key_exponent": "subject-public-key-exponent",
    "x509_v3_extensions": ""
}




#---------------------------------------------------
# 2.2b) SCO Extensions and Similar
#---------------------------------------------------

email_mime_part_typeql_dict = {
    "body": "body",
    "content_type": "content-type",
    "content_disposition": "content-disposition",
    "body_raw_ref": ""
}

archive_ext_typeql_dict = {
    "comment": "comment",
    "contains_refs": ""
}

ntfs_ext_typeql_dict = {
    "sid": "sid",
    "alternate_data_streams": ""
}

alternate_data_stream_ext_typeql_dict = {
    "name": "name",
    "size": "size",
    "hashes": ""
}

pdf_ext_typeql_dict = {
    "version": "version",
    "is_optimized": "is-optimized",
    "document_info_dict": "",
    "pdfid0": "pdfid0",
    "pdfid1": "pdfid1"
}

raster_image_ext_typeql_dict = {
    "image_height": "image-height",
    "image_width": "image-width",
    "exif_tags": "",
    "bits_per_pixel": "bits-per-pixel"
}

windows_pebinary_ext_typeql_dict = {
    "pe_type": "pe-type",
    "imphash": "imphash",
    "machine_hex": "machine-hex",
    "number_of_sections": "number-of-sections",
    "time_date_stamp": "time-date-stamp",
    "pointer_to_symbol_table_hex": "pointer-to-symbol-table-hex",
    "number_of_symbols": "number-of-symbols",
    "size_of_optional_header": "size-of-optional-header",
    "characteristics_hex": "characteristics-hex",
    "file_header_hashes": "",
    "optional_header": "",
    "sections": ""
}

windows_optional_header_ext_typeql_dict = {
    "magic_hex": "magic-hex",
    "major_linker_version": "major-linker-version",
    "minor_linker_version": "minor-linker-version",
    "size_of_code": "size-of-code",
    "size_of_initialized_data": "size-of-initialized-data",
    "size_of_uninitialized_data": "size-of-uninitialized-data",
    "address_of_entry_point": "address-of-entry-point",
    "base_of_code": "base-of-code",
    "base_of_data": "base-of-data",
    "image_base": "image-base",
    "section_alignment": "section-alignment",
    "file_alignment": "file-alignment",
    "major_os_version": "major-os-version",
    "minor_os_version": "minor-os-version",
    "major_image_version": "major-image-version",
    "minor_image_version": "minor-image-version",
    "major_subsystem_version": "major-subsystem-version",
    "minor_subsystem_version": "minor-subsystem-version",
    "win32_version_value_hex": "win32-version-value-hex",
    "size_of_image": "size-of-image",
    "size_of_headers": "size-of-headers",
    "checksum_hex": "checksum-hex",
    "subsystem_hex": "subsystem-hex",
    "dll_characteristics_hex": "dll-characteristics-hex",
    "size_of_stack_reserve": "size-of-stack-reserve",
    "size_of_stack_commit": "size-of-stack-commit",
    "size_of_heap_reserve": "size-of-heap-reserve",
    "size_of_heap_commit": "size-of-heap-commit",
    "loader_flags_hex": "loader-flags-hex",
    "number_of_rva_and_sizes": "number-of-rva-and-sizes",
    "hashes": ""
}

windows_pe_section_ext_typeql_dict = {
    "name": "name",
    "size": "size",
    "entropy": "entropy",
    "hashes": ""
}

HTTP_request_ext_typeql_dict = {
    "request_method": "request-method",
    "request_value": "request-value",
    "request_version": "request-version",
    "request_header": "",
    "message_body_length": "message-body-length",
    "message_body_data_ref": ""
}

icmp_ext_typeql_dict = {
    "icmp_type_hex": "icmp-type-hex",
    "icmp_code_hex": "icmp-code-hex"
}

socket_ext_typeql_dict = {
    "address_family": "address-family",
    "is_blocking": "is-blocking",
    "is_listening": "is-listening",
    "options": "",
    "socket_type": "socket-type",
    "socket_description": "socket-description",
    "socket_handle": "socket-handle"
}


tcp_ext_typeql_dict = {
    "src_flags_hex": "src-flags-hex",
    "dst_flags_hex": "dst-flags-hex"
}

windows_process_ext_typeql_dict = {
    "aslr_enabled": "aslr-enabled",
    "dep_enabled": "dep-enabled",
    "priority": "priority",
    "owner_sid": "owner-sid",
    "window_title": "window-title",
    "startup_info": "",
    "integrity_level": "integrity-level"
}

windows_service_ext_typeql_dict = {
    "service_name": "service-name",
    "descriptions": "description",
    "display_name": "display-name",
    "group_name": "group-name",
    "start_type": "start-type",
    "service_dll_refs": "",
    "service_type": "service-type",
    "service_status": "service-status"
}

unix_account_ext_typeql_dict = {
    "gid": "gid",
    "groups": "unix-group",
    "home_dir": "home-dir",
    "shell": "shell"
}

x509_v3_ext_typeql_dict = {
    "basic_constraints": "basic-constraints",
    "name_constraints": "name-constraints",
    "policy_constraints": "policy-constraints",
    "key_usage": "key-usage",
    "extended_key_usage": "extended-key-usage",
    "subject_key_identifier": "subject-key-identifier",
    "authority_key_identifier": "authority-key-identifier",
    "subject_alternative_name": "subject-alternative-name",
    "issuer_alternative_name": "issuer-alternative-name",
    "subject_directory_attributes": "subject-directory-attributes",
    "crl_distribution_points": "crl-distribution-points",
    "inhibit_any_policy": "inhibit-any-policy",
    "private_key_usage_period_not_before": "private-key-usage-period-not-before",
    "private_key_usage_period_not_after": "private-key-usage-period-not-after",
    "certificate_policies": "certificate-policies",
    "policy mapping": "policy-mapping"
}



ext_typeql_dict_list = [
    {   "stix": "archive-ext",
        "dict": archive_ext_typeql_dict,
        "object": "archive-ext",
        "relation": "archive-extension", 
        "owner": "file",
        "pointed-to": "an-archive"},
    {   "stix": "ntfs-ext",
        "dict": ntfs_ext_typeql_dict,
        "object": "ntfs-ext",
        "relation": "ntfs-extension", 
        "owner": "file",
        "pointed-to": "ntfs"},
    {   "stix": "alternate_data_streams",
        "dict": alternate_data_stream_ext_typeql_dict,
        "object": "alternate-data-stream",
        "relation": "alt-data-streams",
        "owner": "ntfs-ext",
        "pointed-to": "alt-data-stream"},
    {   "stix": "pdf-ext",
        "dict": pdf_ext_typeql_dict,
        "object": "pdf-ext",
        "relation": "pdf-extension", 
        "owner": "file",
        "pointed-to": "pdf"},
    {   "stix": "raster-image-ext",
        "dict": raster_image_ext_typeql_dict,
        "object": "raster-image-ext",
        "relation": "raster-image-extension", 
        "owner": "file",
        "pointed-to": "image"},
    {   "stix": "windows-pebinary-ext",
        "dict": windows_pebinary_ext_typeql_dict,
        "object": "windows-pebinary-ext",
        "relation": "windows-pebinary-extension", 
        "owner": "file",
        "pointed-to": "pebinary"},
    {   "stix": "windows-pe-section-type",
        "dict": windows_pe_section_ext_typeql_dict,
        "object": "windows-pe-section",
        "relation": "sections", 
        "owner": "pebinary",
        "pointed-to": "pe-section"},
    {   "stix": "http-request-ext",
        "dict": HTTP_request_ext_typeql_dict,
        "object": "http-request-ext",
        "relation": "http-request-extension", 
        "owner": "traffic",
        "pointed-to": "request"},
    {   "stix": "icmp-ext",
        "dict": icmp_ext_typeql_dict,
        "object": "icmp-ext",
        "relation": "icmp-extension", 
        "owner": "traffic",
        "pointed-to": "icmp"},
    {   "stix": "socket-ext",
        "dict": socket_ext_typeql_dict,
        "object": "socket-ext",
        "relation": "socket-extension", 
        "owner": "traffic",
        "pointed-to": "socket"},
    {   "stix": "tcp-ext",
        "dict": tcp_ext_typeql_dict,
        "object": "tcp-ext",
        "relation": "tcp-extension", 
        "owner": "traffic",
        "pointed-to": "tcp"},
    {   "stix": "windows-process-ext",
        "dict": windows_process_ext_typeql_dict,
        "object": "windows-process-ext",
        "relation": "windows-process-extension", 
        "owner": "process",
        "pointed-to": "win-process"},
    {   "stix": "windows-service-ext",
        "dict": windows_service_ext_typeql_dict,
        "object": "windows-service-ext",
        "relation": "windows-service-extension", 
        "owner": "process",
        "pointed-to": "win-service"},
    {   "stix": "unix-account-ext",
        "dict": unix_account_ext_typeql_dict,
        "object": "unix-account-ext",
        "relation": "unix-account-extension", 
        "owner": "account",
        "pointed-to": "unix"},
    {   "stix": "x509_v3_extensions",
        "dict": x509_v3_ext_typeql_dict,
        "object": "x509-v3-extension",
        "relation": "v3-extensions", 
        "owner": "cert",
        "pointed-to": "v3-extension"},
    {   "stix": "optional_header",
        "dict": windows_optional_header_ext_typeql_dict,
        "object": "windows-pe-optional-header-type",
        "relation": "optional-headers", 
        "owner": "pebinary",
        "pointed-to": "optional-header"}
]
  
  
  

#---------------------------------------------------
# 2.3) Marking Definition
#---------------------------------------------------

marking_typeql_dict = {
  "type": "stix-type",
  "id": "stix-id",
  "spec_version": "spec-version",
  "created": "created",
  "name": "name",
  "statement": "statement"
  
}

ext_ref_typeql_dict = {
  "source_name": "source-name",
  "description": "description",
  "url": "url-link",
  "hashes": "",
  "external_id": "external-id"	
}

hash_typeql_dict = {
  "MD5": "md-5",
  "SHA-1": "sha-1",
  "SHA-256": "sha-256",
  "SHA-512": "sha-512",
  "SHA3-256": "sha3-256",
  "SHA3-512": "sha3-512",
  "SSDEEP": "ssdeep",
  "TLSH": "tlsh"
}



#---------------------------------------------------
# 2.4) Stix type_ql_relationhip Object Dict and TypeQL Roles List of Dicts
#---------------------------------------------------

sro_base_typeql_dict = {
  "type" :  "stix-type",
  "spec_version" :  "spec-version",
  "id" :  "stix-id",
  "created_by_ref" :  "",
  "created" :  "created",
  "modified" :  "modified",
  "revoked" :  "revoked",
  "labels" :  "labels",
  "confidence" :  "confidence",
  "lang" :  "langs",
  "external_references" :  "",
  "object_marking_refs" :  "",
  "granular_markings" :  "",
  "extensions" :  ""
}

relationship_typeql_dict = {        
  "relationship_type" :  "relationship-type",
  "description" :  "description",
  "source_ref" :  "",
  "target_ref" :  "",
  "start_time" :  "start-time",
  "stop_time" :  "stop-time"        
}

sighting_typeql_dict = {
  "description" :  "description",
  "first_seen" :  "first-seen",
  "last_seen" :  "last-seen",
  "count" :  "count",
  "sighting_of_ref" :  "",
  "observed_data_refs" :  "",
  "where_sighted_refs" :  "",
  "summary" :  "summary"
}
    

stix_rel_roles = [
 {   "stix": "delivers",    "typeql": "delivers",    "source": "delivering",    "target": "delivered" }, 
 {   "stix": "targets",    "typeql": "targets",   "source": "targetter",   "target": "targetted" }, 
 {   "stix": "uses",   "typeql": "uses",   "source": "used-by",   "target": "used" }, 
 {   "stix": "attributed-to",   "typeql": "attributed-to",   "source": "result",   "target": "fault-of" }, 
 {   "stix": "compromises",   "typeql": "compromises",   "source": "compromising",   "target": "compromised" }, 
 {   "stix": "originates-from", "typeql": "originates-from",   "source": "originating",   "target": "originated-from" }, 
 {   "stix": "investigates",   "typeql": "investigates",   "source": "investigating",   "target": "investigated" }, 
 {   "stix": "mitigates",   "typeql": "mitigates",   "source": "mitigator",   "target": "mitigated" }, 
 {   "stix": "located-at",   "typeql": "located-at",   "source": "locating",   "target": "located" }, 
 {   "stix": "indicates",   "typeql": "indicates",   "source": "indicating",   "target": "indicated" }, 
 {   "stix": "based-on",   "typeql": "based-on",   "source": "basing-on",   "target": "basis" }, 
 {   "stix": "communicates-with",   "typeql": "communicates-with",   "source": "communicating",   "target": "communicated" }, 
 {   "stix": "consists-of",   "typeql": "consist",   "source": "consisting",   "target": "consisted" }, 
 {   "stix": "controls",   "typeql": "control",   "source": "controlling",   "target": "controlled" }, 
 {   "stix": "has",   "typeql": "have",   "source": "having",   "target": "had" }, 
 {   "stix": "hosts",   "typeql": "hosts",   "source": "hosting",   "target": "hosted" }, 
 {   "stix": "owns",   "typeql": "ownership",   "source": "owning",   "target": "owned" }, 
 {   "stix": "authored-by",   "typeql": "authored-by",   "source": "authoring",   "target": "authored" }, 
 {   "stix": "beacons-to",   "typeql": "beacon",   "source": "beaconing-to",   "target": "beaconed-to" }, 
 {   "stix": "exfiltrate-to",   "typeql": "exfiltrate",   "source": "exfiltrating-to",   "target": "exfiltrated-to" }, 
 {   "stix": "downloads",   "typeql": "download",   "source": "downloading",   "target": "downloaded" }, 
 {   "stix": "drops",   "typeql": "drop",   "source": "dropping",   "target": "dropped" }, 
 {   "stix": "exploits",   "typeql": "exploit",   "source": "exploiting",   "target": "exploited" }, 
 {   "stix": "variant-of",   "typeql": "variant",   "source": "variant-source",   "target": "variant-target" }, 
 {   "stix": "characterizes",   "typeql": "characterise",   "source": "characterising",   "target": "characterised" }, 
 {   "stix": "analysis-of",   "typeql": "av-analysis",   "source": "analysing",   "target": "analysed" }, 
 {   "stix": "static-analysis-of",   "typeql": "static-analysis",   "source": "analysing",   "target": "analysed" }, 
 {   "stix": "dynamic-analysis-of",   "typeql": "dynamic-analysis",   "source": "analysing",   "target": "analysed" }, 
 {   "stix": "impersonates",   "typeql": "impersonate",   "source": "impersonating",   "target": "impersonated" }
]

embedded_relations_typeql = [
  {"rel": "object_refs", "owner": "object", "pointed-to": "referred", "typeql": "obj-ref"},
  {"rel": "created_by_ref", "owner": "created", "pointed-to": "creator", "typeql": "created-by"},
  {"rel": "object_marking_refs", "owner": "marked", "pointed-to": "marking", "typeql": "object-marking"},
  {"rel": "sample_refs", "owner": "sample-for", "pointed-to": "sco-sample", "typeql": "malware-sample"},
  {"rel": "sample_ref", "owner": "sample-for", "pointed-to": "sco-sample", "typeql": "malware-analysis-sample"},
  {"rel": "host_vm_ref", "owner": "object", "pointed-to": "env", "typeql": "host-vm-ref"},
  {"rel": "operating_system_ref", "owner": "object", "pointed-to": "env", "typeql": "operating-system"},
  {"rel": "installed_software_refs", "owner": "object", "pointed-to": "env", "typeql": "installed-software"},
  {"rel": "contains_refs", "owner": "container", "pointed-to": "contained", "typeql": "directory-contains"},
  {"rel": "parent_directory_ref", "owner": "contained", "pointed-to": "container", "typeql": "directory-parent"},
  {"rel": "resolves_to_refs", "owner": "resolve", "pointed-to": "resolves-to", "typeql": "resolves"},
  {"rel": "belongs_to_ref", "owner": "belonged", "pointed-to": "belongs-to", "typeql": "belongs"},
  {"rel": "belongs_to_refs", "owner": "belonged", "pointed-to": "belongs-to", "typeql": "belongs-to-autonomous"},
  {"rel": "analysis_sco_refs", "owner": "object", "pointed-to": "env", "typeql": "captured-objects"},
  {"rel": "raw_email_ref", "owner": "email", "pointed-to": "binary", "typeql": "raw-email-references"},
  {"rel": "from_ref", "owner": "email", "pointed-to": "email-address", "typeql": "from-email"},
  {"rel": "sender_ref", "owner": "email", "pointed-to": "email-address", "typeql": "sender-email"},
  {"rel": "to_refs", "owner": "email", "pointed-to": "email-address", "typeql": "to-email"},
  {"rel": "cc_refs", "owner": "email", "pointed-to": "email-address", "typeql": "cc-email"},
  {"rel": "bcc_refs", "owner": "email", "pointed-to": "email-address", "typeql": "bcc-email"},
  {"rel": "body_raw_ref", "owner": "containing-mime", "pointed-to": "non-textual", "typeql": "body-raw-references"},
  {"rel": "content_ref", "owner": "containing-file", "pointed-to": "content", "typeql": "content-file"},
  {"rel": "src_ref", "owner": "traffic", "pointed-to": "source", "typeql": "traffic-src"},
  {"rel": "src_payload_ref", "owner": "traffic", "pointed-to": "source", "typeql": "payload-src"},
  {"rel": "dst_ref", "owner": "traffic", "pointed-to": "destination", "typeql": "traffic-dst"},
  {"rel": "dst_payload_ref", "owner": "traffic", "pointed-to": "payload", "typeql": "payload-dst"},
  {"rel": "encapsulates_refs", "owner": "container", "pointed-to": "contained", "typeql": "encapsulate"},
  {"rel": "encapsulated_by_ref", "owner": "contained", "pointed-to": "container", "typeql": "encapsulated"},
  {"rel": "message_body_data_ref", "owner": "HTPP-message", "pointed-to": "container", "typeql": "HTTP-body-data"},
  {"rel": "opened_connection_refs", "owner": "process", "pointed-to": "opened-connection", "typeql": "open-connections"},
  {"rel": "creator_user_ref", "owner": "created", "pointed-to": "creator", "typeql": "user-created-by"},
  {"rel": "image_ref", "owner": "process", "pointed-to": "executed-image", "typeql": "process-image"},
  {"rel": "parent_ref", "owner": "process", "pointed-to": "parent", "typeql": "process-parent"},
  {"rel": "child_refs", "owner": "process", "pointed-to": "child", "typeql": "process-child"},
  {"rel": "service_dll_refs", "owner": "process", "pointed-to": "loaded-dll", "typeql": "service-dll"}
]



key_value_typeql_list = [
    {
        "name": "additional_header_fields", 
        "typeql": "additional-header", 
        "owner": "email", 
        "pointed_to": "item", 
        "key": "header-key",
        "value": "header-value"
    },{
        "name": "document_info_dict", 
        "typeql": "doc-info", 
        "owner": "pdf", 
        "pointed_to": "info", 
        "key": "doc-key",
        "value": "doc-value"
    },{
        "name": "exif_tags", 
        "typeql": "EXIF-tags", 
        "owner": "image", 
        "pointed_to": "info", 
        "key": "EXIF-key",
        "value": "EXIF-value"
    },{
        "name": "ipfix", 
        "typeql": "IPFIX-store", 
        "owner": "traffic", 
        "pointed_to": "item", 
        "key": "IPFIX-key",
        "value": "IPFIX-value"
    },{
        "name": "request_header", 
        "typeql": "HTTP-header", 
        "owner": "request", 
        "pointed_to": "header", 
        "key": "HTTP-key",
        "value": "HTTP-value"
    },{
        "name": "options", 
        "typeql": "socket-options", 
        "owner": "socket", 
        "pointed_to": "option", 
        "key": "socket-key",
        "value": "socket-value"
    },{
        "name": "environment_variables", 
        "typeql": "environment-variables", 
        "owner": "process", 
        "pointed_to": "env-variable", 
        "key": "environment-key",
        "value": "environment-value"
    },{
        "name": "startup_info", 
        "typeql": "startup-info", 
        "owner": "process", 
        "pointed_to": "option", 
        "key": "startup-key",
        "value": "startup-value"
    }
]



list_of_object_typeql = [
    {
        "name": "body_multipart", 
        "typeql": "body-multipart", 
        "typeql_props": email_mime_part_typeql_dict, 
        "owner": "email", 
        "pointed_to": "mime-part", 
        "object": "email-mime-part"
    },{
        "name": "external_references", 
        "typeql": "external-references", 
        "typeql_props": ext_ref_typeql_dict, 
        "owner": "referencing", 
        "pointed_to": "referenced", 
        "object": "external-reference"
    },{
        "name": "kill_chain_phases", 
        "typeql": "kill-chain-usage", 
        "typeql_props": kill_chain_phases_typeql_dict, 
        "owner": "kill-chain-used", 
        "pointed_to": "kill-chain-install",
        "object": "kill-chain-phase"
    },{
        "name": "alternate_data_streams", 
        "typeql": "alt-data-streams",
        "typeql_props": alternate_data_stream_ext_typeql_dict, 
        "owner": "ntfs-ext", 
        "pointed_to": "alt-data-stream",
        "object": "alternate-data-stream"
    },{
        "name": "sections",
        "typeql_props": windows_pe_section_ext_typeql_dict,
        "object": "windows-pe-section",
        "typeql": "sections", 
        "owner": "pebinary",
        "pointed_to": "pe-section"
    },{
        "name": "values",
        "typeql_props": windows_registry_value_typeql_dict,
        "object": "windows-registry-value-type",
        "typeql": "reg-val", 
        "owner": "reg-key",
        "pointed_to": "reg-value"
    }
]
 

    

#---------------------------------------------------
# 2.5) Object to Dict Mapping
#---------------------------------------------------

dispatch_stix = {
    
    "attack-pattern" :  attack_pattern_typeql_dict,
    "campaign" :  campaign_typeql_dict,
    "course-of-action" :  course_of_action_typeql_dict,
    "grouping" :  grouping_typeql_dict,
    "identity": identity_typeql_dict,
    "incident": incident_typeql_dict,
    "indicator": indicator_typeql_dict,
    "infrastructure": infrastructure_typeql_dict,
    "intrusion-set": intrusion_set_typeql_dict,
    "location": location_typeql_dict,
    "malware": malware_typeql_dict,
    "malware-analysis": malware_analysis_typeql_dict,
    "note" :  note_type_dict,
    "observed-data" :  observed_data_typeql_dict,
    "opinion" :  opinion_typeql_dict,
    "report" :  report_typeql_dict,
    "threat-actor": threat_actor_typeql_dict,
    "tool": tool_typeql_dict,
    "vulnerability": vulnerability_typeql_dict,
    "relationship": relationship_typeql_dict,
    "sighting": sighting_typeql_dict,
    "artifact": artifact_typeql_dict,
    "autonomous-system": autonomous_system_typeql_dict,
    "directory": directory_typeql_dict,
    "domain-name": domain_name_typeql_dict,
    "email-addr": email_addr_typeql_dict,
    "email-message": email_message_typeql_dict,
    "file": file_typeql_dict,
    "ipv4-addr": ipv4_addr_typeql_dict,
    "ipv6-addr": ipv6_addr_typeql_dict,
    "mac-addr": mac_addr_typeql_dict,
    "mutex": mutex_typeql_dict,
    "network-traffic": network_traffic_typeql_dict,
    "process": process_typeql_dict,
    "software": software_typeql_dict,
    "url": url_typeql_dict,
    "user-account": user_account_typeql_dict,
    "windows-registry-key": windows_registry_key_typeql_dict,
    "windows-registry-value-type": windows_registry_value_typeql_dict,
    "x509-certificate": x509_certificate_typeql_dict,
    "external-reference": ext_ref_typeql_dict,
    "email-mime-part": email_mime_part_typeql_dict,
    "archive-ext":  archive_ext_typeql_dict,
    "ntfs-ext":  ntfs_ext_typeql_dict,
    "alternate-data-stream": alternate_data_stream_ext_typeql_dict,
    "pdf-ext": pdf_ext_typeql_dict,
    "raster-image-ext": raster_image_ext_typeql_dict,
    "windows-pebinary-ext": windows_pebinary_ext_typeql_dict,
    "windows-pe-optional-header-type": windows_optional_header_ext_typeql_dict,
    "windows-pe-section": windows_pe_section_ext_typeql_dict,
    "http-request-ext": HTTP_request_ext_typeql_dict,
    "icmp-ext": icmp_ext_typeql_dict,
    "socket-ext": socket_ext_typeql_dict,
    "tcp-ext": tcp_ext_typeql_dict,
    "unix-account-ext": unix_account_ext_typeql_dict,
    "windows-process-ext": windows_process_ext_typeql_dict,
    "windows-service-ext": windows_service_ext_typeql_dict,
    "kill-chain-phase": kill_chain_phases_typeql_dict,
    "x509-v3-extension": x509_v3_ext_typeql_dict
}

sdo_obj = [
    "attack-pattern",
    "campaign" ,
    "course-of-action",
    "grouping",
    "identity",
    "incident",
    "indicator",
    "infrastructure",
    "intrusion-set",
    "location",
    "malware",
    "malware-analysis",
    "note",
    "observed-data" ,
    "opinion",
    "report",
    "threat-actor",
    "tool",
    "vulnerability"
]

sro_obj = [    
    "relationship",
    "sighting",
    "delivers",
    "targets",
    "uses",
    "attributed-to",
    "compromises",
    "originates-from",
    "investigates",
    "mitigates",
    "located-at",
    "indicates",
    "based-on",
    "communicates-with",
    "consist",
    "control",
    "have",
    "hosts",
    "ownership",
    "authored-by",
    "beacon",
    "exfiltrate",
    "download",
    "drop",
    "exploit",
    "variant",
    "characterise",
    "impersonate",
    "av-analysis",
    "static-analysis",
    "dynamic-analysis",
    "remediation"
]

sco_obj =[   
    "artifact",
    "autonomous-system",
    "directory",
    "domain-name",
    "email-addr",
    "email-message",
    "file",
    "ipv4-addr",
    "ipv6-addr",
    "mac-addr",
    "mutex",
    "network-traffic",
    "process",
    "software",
    "url",
    "user-account",
    "windows-registry-key",
    "windows-registry-value-type",
    "x509-certificate"
]    
    
meta_obj = [
    "marking-definition",
    "tlp-white",
    "tlp-green",
    "tlp-amber",
    "tlp-red",
    "statement-marking"
]
    

dispatch_attack = {}

extensions_only = [
    "archive-extension",
    "ntfs-extension",
    "pdf-extension",
    "raster-image-extension",
    "windows-pebinary-extension",
    "http-request-extension",
    "icmp-extension",
    "socket-extension",
    "tcp-extension",
    "unix-account-extension",
    "windows-process-extension",
    "windows-service-extension"
]

object_is_list = {
    "external-reference": [],
    "email-mime-part": [],
    "archive-ext":  ["contains_refs"],
    "ntfs-ext":  ["alternate_data_streams"],
    "alternate-data-stream": [],
    "pdf-ext": [],
    "raster-image-ext": [],
    "windows-pebinary-ext": ["sections"],
    "windows-pe-optional-header-type": [],
    "windows-pe-section": [],
    "http-request-ext": [],
    "icmp-ext": [],
    "socket-ext": [],
    "tcp-ext": [],
    "unix-account-ext": ["groups"],
    "windows-process-ext": [],
    "windows-service-ext": ["descriptions", "service_dll_refs"],
    "kill-chain-phase": [],
    "windows-registry-value-type": [],
    "x509-v3-extension": []
}

sdo_is_list = {
    "sdo": ["labels","external_references", "object_marking_refs", "granular_markings"],
    "attack-pattern": ["aliases", "kill_chain_phases"],
    "campaign": ["aliases"],
    "course-of-action": [],
    "grouping": ["object_refs"],
    "identity": ["roles", "sectors"],
    "incident": [],
    "indicator": ["indicator_types", "kill_chain_phases"],
    "infrastructure": ["infrastructure_types", "aliases", "kill_chain_phases"],
    "intrusion-set": ["aliases", "goals", "secondary_motivations" ],
    "location": [],
    "malware": ["malware_types", "kill_chain_phases","aliases", "operating_system_refs", "architecture_execution_envs", "implementation_languages", "capabilities", "sample_refs"],
    "malware-analysis": ["installed_software_refs", "modules", "analysis_sco_refs"],
    "note": ["authors", "object_refs"],
    "observed-data": ["object_refs"],
    "opinion": ["authors", "object_refs"],
    "report": ["report_types", "object_refs"],
    "threat-actor": ["threat_actor_types", "aliases", "roles", "goals","resource-level", "secondary_motivations", "personal_motivations"],
    "tool": ["tool_types", "kill_chain_phases", "aliases"],
    "vulnerability": []
}

sro_is_list = {
    "sro": ["labels","external_references", "object_marking_refs", "granular_markings"],
    "sighting": [ "observed_data_refs", "where_sighted_refs"]
}

sco_is_list = {
    "sco": ["labels","external_references", "object_marking_refs", "granular_markings"],
    "artifact": [],
    "autonomous-system": [],
    "directory": ["contains_refs"],
    "domain-name": ["resolves_to_refs"],
    "email-addr": [],
    "email-message": ["to_refs", "cc_refs", "bcc_refs", "received_lines", "body_multipart"],
    "email-mime-part": [],
    "file": ["contains_refs"],    
    "archive-ext":  ["contains_refs"],
    "ntfs-ext":  ["alternate_data_streams"],
    "alternate-data-stream-type": [],
    "pdf-ext": [],
    "raster-image-ext": [],
    "windows-pebinary-ext": ["sections"],
    "windows-pe-optional-header-type": [],
    "windows-pe-section-type": [],
    "ipv4-addr": ["resolves_to_refs", "belongs_to_refs"],
    "ipv6-addr": ["resolves_to_refs", "belongs_to_refs"],
    "mac-addr": [],
    "mutex": [],
    "network-traffic": [ "protocols", "encapsulates_refs"],
    "http-request-ext": [],
    "icmp-ext": [],
    "socket-ext": [],
    "tcp-ext": [],
    "process": ["opened_connection_refs", "child_refs"],
    "windows-process-ext": [],
    "windows-service-ext": ["descriptions", "service_dll_refs"],
    "software": ["languages"],
    "url": [],
    "user-account": [],
    "unix-account-ext": ["groups"],
    "windows-registry-key": ["values"],
    "windows-registry-value-type": [],
    "x509-certificate": [],
    "x509-v3-extensions-type": []
}