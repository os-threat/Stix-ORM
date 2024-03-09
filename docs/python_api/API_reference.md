# API Reference
## ```stixorm.module.definitions.attack.classes```
*class* **AttackCampaign**

For more detailed information on this object's properties, see
    `the MITRE ATT&CK Stix specifications <https://github.com/mitre-attack/attack-stix-data/blob/master/USAGE.md>`__.

**Properties:**
- **type** (*TypeProperty*)
- **spec_version** (*StringProperty*)
- **id** (*IDProperty*)
- **created_by_ref** (*ReferenceProperty*)
- **created** (*TimestampProperty*)
- **modified** (*TimestampProperty*)
- **name** (*StringProperty, required*)
- **description** (*StringProperty*)
- **x_mitre_version** (*StringProperty*)
- **x_mitre_contributors** (*ListProperty*)
- **x_mitre_modified_by_ref** (*StringProperty*)
- **x_mitre_domains** (*ListProperty*)
- **x_mitre_attack_spec_version** (*StringProperty*)
- **x_mitre_first_seen_citation** (*StringProperty*)
- **x_mitre_last_seen_citation** (*StringProperty*)
- **x_mitre_aliases** (*StringProperty*)
- **aliases** (*ListProperty*)
- **first_seen** (*TimestampProperty*)
- **last_seen** (*TimestampProperty*)
- **objective** (*StringProperty*)
- **revoked** (*BooleanProperty*)
- **x_mitre_deprecated** (*BooleanProperty*)
- **labels** (*ListProperty*)
- **confidence** (*IntegerProperty*)
- **lang** (*StringProperty*)
- **external_references** (*ListProperty*)
- **object_marking_refs** (*ListProperty*)
- **granular_markings** (*ListProperty*)
- **extensions** (*ExtensionsProperty*)
<br><br>

*class* **AttackIdentity**

For more detailed information on this object's properties, see
    `the STIX 2.1 specification <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_wh296fiwpklp>`__.

**Properties:**
- **type** (*TypeProperty*)
- **spec_version** (*StringProperty*)
- **id** (*IDProperty*)
- **created_by_ref** (*ReferenceProperty*)
- **created** (*TimestampProperty*)
- **modified** (*TimestampProperty*)
- **name** (*StringProperty, required*)
- **description** (*StringProperty*)
- **x_mitre_version** (*StringProperty*)
- **x_mitre_contributors** (*ListProperty*)
- **x_mitre_modified_by_ref** (*StringProperty*)
- **x_mitre_domains** (*ListProperty*)
- **x_mitre_attack_spec_version** (*StringProperty*)
- **roles** (*ListProperty*)
- **identity_class** (*OpenVocabProperty*)
- **sectors** (*ListProperty*)
- **contact_information** (*StringProperty*)
- **revoked** (*BooleanProperty*)
- **labels** (*ListProperty*)
- **confidence** (*IntegerProperty*)
- **lang** (*StringProperty*)
- **external_references** (*ListProperty*)
- **object_marking_refs** (*ListProperty*)
- **granular_markings** (*ListProperty*)
- **extensions** (*ExtensionsProperty*)
<br><br>

*class* **AttackMarking**

For more detailed information on this object's properties, see
    `the STIX 2.1 specification <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_k5fndj2c7c1k>`__.

**Properties:**
- **type** (*TypeProperty*)
- **spec_version** (*StringProperty*)
- **id** (*IDProperty*)
- **created_by_ref** (*ReferenceProperty*)
- **created** (*TimestampProperty*)
- **definition_type** (*StringProperty*)
- **name** (*StringProperty*)
- **definition** (*MarkingProperty*)
- **x_mitre_version** (*StringProperty*)
- **x_mitre_contributors** (*ListProperty*)
- **x_mitre_modified_by_ref** (*StringProperty*)
- **x_mitre_domains** (*ListProperty*)
- **x_mitre_attack_spec_version** (*StringProperty*)
- **external_references** (*ListProperty*)
- **object_marking_refs** (*ListProperty*)
- **granular_markings** (*ListProperty*)
- **extensions** (*ExtensionsProperty*)
<br><br>

*class* **AttackRelation**

For more detailed information on this object's properties, see
    `the MITRE ATT&CK Stix specifications <https://github.com/mitre-attack/attack-stix-data/blob/master/USAGE.md>`__.

**Properties:**
- **type** (*TypeProperty*)
- **spec_version** (*StringProperty*)
- **id** (*IDProperty*)
- **created_by_ref** (*ReferenceProperty*)
- **created** (*TimestampProperty*)
- **modified** (*TimestampProperty*)
- **relationship_type** (*StringProperty, required*)
- **description** (*StringProperty*)
- **x_mitre_version** (*StringProperty*)
- **x_mitre_contributors** (*ListProperty*)
- **x_mitre_modified_by_ref** (*StringProperty*)
- **x_mitre_domains** (*ListProperty*)
- **x_mitre_attack_spec_version** (*StringProperty*)
- **x_mitre_platforms** (*ListProperty*)
- **source_ref** (*ThreatReference, required*)
- **target_ref** (*ThreatReference, required*)
- **start_time** (*TimestampProperty*)
- **stop_time** (*TimestampProperty*)
- **revoked** (*BooleanProperty*)
- **x_mitre_deprecated** (*BooleanProperty*)
- **labels** (*ListProperty*)
- **confidence** (*IntegerProperty*)
- **lang** (*StringProperty*)
- **external_references** (*ListProperty*)
- **object_marking_refs** (*ListProperty*)
- **granular_markings** (*ListProperty*)
- **extensions** (*ExtensionsProperty*)
<br><br>

*class* **Collection**

For more detailed information on this object's properties, see
    `the MITRE ATT&CK Stix specifications <https://github.com/mitre-attack/attack-stix-data/blob/master/USAGE.md>`__.

**Properties:**
- **type** (*TypeProperty*)
- **spec_version** (*StringProperty*)
- **id** (*IDProperty*)
- **created_by_ref** (*ReferenceProperty*)
- **created** (*TimestampProperty*)
- **modified** (*TimestampProperty*)
- **name** (*StringProperty, required*)
- **description** (*StringProperty*)
- **x_mitre_version** (*StringProperty*)
- **x_mitre_contributors** (*ListProperty*)
- **x_mitre_modified_by_ref** (*StringProperty*)
- **x_mitre_domains** (*ListProperty*)
- **x_mitre_attack_spec_version** (*StringProperty*)
- **revoked** (*BooleanProperty*)
- **x_mitre_deprecated** (*BooleanProperty*)
- **labels** (*ListProperty*)
- **confidence** (*IntegerProperty*)
- **lang** (*StringProperty*)
- **external_references** (*ListProperty*)
- **object_marking_refs** (*ListProperty*)
- **granular_markings** (*ListProperty*)
- **extensions** (*ExtensionsProperty*)
- **x_mitre_contents** (*ListProperty*)
<br><br>

*class* **DataComponent**

For more detailed information on this object's properties, see
    `the MITRE ATT&CK Stix specifications <https://github.com/mitre-attack/attack-stix-data/blob/master/USAGE.md>`__.

**Properties:**
- **type** (*TypeProperty*)
- **spec_version** (*StringProperty*)
- **id** (*IDProperty*)
- **created_by_ref** (*ReferenceProperty*)
- **created** (*TimestampProperty*)
- **modified** (*TimestampProperty*)
- **name** (*StringProperty, required*)
- **description** (*StringProperty*)
- **x_mitre_version** (*StringProperty*)
- **x_mitre_contributors** (*ListProperty*)
- **x_mitre_modified_by_ref** (*StringProperty*)
- **x_mitre_domains** (*ListProperty*)
- **x_mitre_attack_spec_version** (*StringProperty*)
- **revoked** (*BooleanProperty*)
- **x_mitre_deprecated** (*BooleanProperty*)
- **labels** (*ListProperty*)
- **confidence** (*IntegerProperty*)
- **lang** (*StringProperty*)
- **external_references** (*ListProperty*)
- **object_marking_refs** (*ListProperty*)
- **granular_markings** (*ListProperty*)
- **extensions** (*ExtensionsProperty*)
- **x_mitre_data_source_ref** (*StringProperty*)
<br><br>

*class* **DataSource**

For more detailed information on this object's properties, see
    `the MITRE ATT&CK Stix specifications <https://github.com/mitre-attack/attack-stix-data/blob/master/USAGE.md>`__.

**Properties:**
- **type** (*TypeProperty*)
- **spec_version** (*StringProperty*)
- **id** (*IDProperty*)
- **created_by_ref** (*ReferenceProperty*)
- **created** (*TimestampProperty*)
- **modified** (*TimestampProperty*)
- **name** (*StringProperty, required*)
- **description** (*StringProperty*)
- **x_mitre_version** (*StringProperty*)
- **x_mitre_contributors** (*ListProperty*)
- **x_mitre_modified_by_ref** (*StringProperty*)
- **x_mitre_domains** (*ListProperty*)
- **x_mitre_attack_spec_version** (*StringProperty*)
- **revoked** (*BooleanProperty*)
- **x_mitre_deprecated** (*BooleanProperty*)
- **labels** (*ListProperty*)
- **confidence** (*IntegerProperty*)
- **lang** (*StringProperty*)
- **external_references** (*ListProperty*)
- **object_marking_refs** (*ListProperty*)
- **granular_markings** (*ListProperty*)
- **extensions** (*ExtensionsProperty*)
- **x_mitre_platforms** (*ListProperty*)
- **x_mitre_collection_layers** (*ListProperty*)
<br><br>

*class* **Group**

For more detailed information on this object's properties, see
    `the MITRE ATT&CK Stix specifications <https://github.com/mitre-attack/attack-stix-data/blob/master/USAGE.md>`__.

**Properties:**
- **type** (*TypeProperty*)
- **spec_version** (*StringProperty*)
- **id** (*IDProperty*)
- **created_by_ref** (*ReferenceProperty*)
- **created** (*TimestampProperty*)
- **modified** (*TimestampProperty*)
- **name** (*StringProperty, required*)
- **description** (*StringProperty*)
- **x_mitre_version** (*StringProperty*)
- **x_mitre_contributors** (*ListProperty*)
- **x_mitre_modified_by_ref** (*StringProperty*)
- **x_mitre_domains** (*ListProperty*)
- **x_mitre_attack_spec_version** (*StringProperty*)
- **aliases** (*ListProperty*)
- **first_seen** (*TimestampProperty*)
- **last_seen** (*TimestampProperty*)
- **goals** (*ListProperty*)
- **resource_level** (*OpenVocabProperty*)
- **primary_motivation** (*OpenVocabProperty*)
- **secondary_motivations** (*ListProperty*)
- **revoked** (*BooleanProperty*)
- **x_mitre_deprecated** (*BooleanProperty*)
- **labels** (*ListProperty*)
- **confidence** (*IntegerProperty*)
- **lang** (*StringProperty*)
- **external_references** (*ListProperty*)
- **object_marking_refs** (*ListProperty*)
- **granular_markings** (*ListProperty*)
- **extensions** (*ExtensionsProperty*)
<br><br>

*class* **Matrix**

For more detailed information on this object's properties, see
    `the MITRE ATT&CK Stix specifications <https://github.com/mitre-attack/attack-stix-data/blob/master/USAGE.md>`__.

**Properties:**
- **type** (*TypeProperty*)
- **spec_version** (*StringProperty*)
- **id** (*IDProperty*)
- **created_by_ref** (*ReferenceProperty*)
- **created** (*TimestampProperty*)
- **modified** (*TimestampProperty*)
- **name** (*StringProperty, required*)
- **description** (*StringProperty*)
- **x_mitre_version** (*StringProperty*)
- **x_mitre_contributors** (*ListProperty*)
- **x_mitre_modified_by_ref** (*StringProperty*)
- **x_mitre_domains** (*ListProperty*)
- **x_mitre_attack_spec_version** (*StringProperty*)
- **revoked** (*BooleanProperty*)
- **x_mitre_deprecated** (*BooleanProperty*)
- **labels** (*ListProperty*)
- **confidence** (*IntegerProperty*)
- **lang** (*StringProperty*)
- **external_references** (*ListProperty*)
- **object_marking_refs** (*ListProperty*)
- **granular_markings** (*ListProperty*)
- **extensions** (*ExtensionsProperty*)
- **tactic_refs** (*ListProperty*)
<br><br>

*class* **Mitigation**

For more detailed information on this object's properties, see
    `the MITRE ATT&CK Stix specifications <https://github.com/mitre-attack/attack-stix-data/blob/master/USAGE.md>`__.

**Properties:**
- **type** (*TypeProperty*)
- **spec_version** (*StringProperty*)
- **id** (*IDProperty*)
- **created_by_ref** (*ReferenceProperty*)
- **created** (*TimestampProperty*)
- **modified** (*TimestampProperty*)
- **name** (*StringProperty, required*)
- **description** (*StringProperty*)
- **x_mitre_version** (*StringProperty*)
- **x_mitre_contributors** (*ListProperty*)
- **x_mitre_modified_by_ref** (*StringProperty*)
- **x_mitre_domains** (*ListProperty*)
- **x_mitre_attack_spec_version** (*StringProperty*)
- **revoked** (*BooleanProperty*)
- **x_mitre_deprecated** (*BooleanProperty*)
- **labels** (*ListProperty*)
- **confidence** (*IntegerProperty*)
- **lang** (*StringProperty*)
- **external_references** (*ListProperty*)
- **object_marking_refs** (*ListProperty*)
- **granular_markings** (*ListProperty*)
- **extensions** (*ExtensionsProperty*)
<br><br>

*class* **ObjectVersion**

For more detailed information on this object's properties, see
    `the MITRE ATT&CK Stix specifications <https://github.com/mitre-attack/attack-stix-data/blob/master/USAGE.md>`__.

**Properties:**
- **object_ref** (*ThreatReference*)
- **object_modified** (*TimestampProperty*)
<br><br>

*class* **SoftwareMalware**

For more detailed information on this object's properties, see
    `the MITRE ATT&CK Stix specifications <https://github.com/mitre-attack/attack-stix-data/blob/master/USAGE.md>`__.

**Properties:**
- **type** (*TypeProperty*)
- **spec_version** (*StringProperty*)
- **id** (*IDProperty*)
- **created_by_ref** (*ReferenceProperty*)
- **created** (*TimestampProperty*)
- **modified** (*TimestampProperty*)
- **name** (*StringProperty*)
- **description** (*StringProperty*)
- **x_mitre_version** (*StringProperty*)
- **x_mitre_contributors** (*ListProperty*)
- **x_mitre_modified_by_ref** (*StringProperty*)
- **x_mitre_domains** (*ListProperty*)
- **x_mitre_attack_spec_version** (*StringProperty*)
- **malware_types** (*ListProperty*)
- **is_family** (*BooleanProperty, required*)
- **aliases** (*ListProperty*)
- **kill_chain_phases** (*ListProperty*)
- **first_seen** (*TimestampProperty*)
- **last_seen** (*TimestampProperty*)
- **operating_system_refs** (*ListProperty*)
- **architecture_execution_envs** (*ListProperty*)
- **implementation_languages** (*ListProperty*)
- **capabilities** (*ListProperty*)
- **sample_refs** (*ListProperty*)
- **revoked** (*BooleanProperty*)
- **x_mitre_deprecated** (*BooleanProperty*)
- **labels** (*ListProperty*)
- **confidence** (*IntegerProperty*)
- **lang** (*StringProperty*)
- **external_references** (*ListProperty*)
- **object_marking_refs** (*ListProperty*)
- **granular_markings** (*ListProperty*)
- **extensions** (*ExtensionsProperty*)
- **x_mitre_platforms** (*ListProperty*)
- **x_mitre_aliases** (*ListProperty*)
<br><br>

*class* **SoftwareTool**

For more detailed information on this object's properties, see
    `the MITRE ATT&CK Stix specifications <https://github.com/mitre-attack/attack-stix-data/blob/master/USAGE.md>`__.

**Properties:**
- **type** (*TypeProperty*)
- **spec_version** (*StringProperty*)
- **id** (*IDProperty*)
- **created_by_ref** (*ReferenceProperty*)
- **created** (*TimestampProperty*)
- **modified** (*TimestampProperty*)
- **name** (*StringProperty, required*)
- **description** (*StringProperty*)
- **x_mitre_version** (*StringProperty*)
- **x_mitre_contributors** (*ListProperty*)
- **x_mitre_modified_by_ref** (*StringProperty*)
- **x_mitre_domains** (*ListProperty*)
- **x_mitre_attack_spec_version** (*StringProperty*)
- **tool_types** (*ListProperty*)
- **aliases** (*ListProperty*)
- **kill_chain_phases** (*ListProperty*)
- **tool_version** (*StringProperty*)
- **revoked** (*BooleanProperty*)
- **x_mitre_deprecated** (*BooleanProperty*)
- **labels** (*ListProperty*)
- **confidence** (*IntegerProperty*)
- **lang** (*StringProperty*)
- **external_references** (*ListProperty*)
- **object_marking_refs** (*ListProperty*)
- **granular_markings** (*ListProperty*)
- **extensions** (*ExtensionsProperty*)
- **x_mitre_platforms** (*ListProperty*)
- **x_mitre_aliases** (*ListProperty*)
<br><br>

*class* **SubTechnique**

For more detailed information on this object's properties, see
    `the MITRE ATT&CK Stix specifications <https://github.com/mitre-attack/attack-stix-data/blob/master/USAGE.md>`__.

**Properties:**
- **type** (*TypeProperty*)
- **spec_version** (*StringProperty*)
- **id** (*IDProperty*)
- **created_by_ref** (*ReferenceProperty*)
- **created** (*TimestampProperty*)
- **modified** (*TimestampProperty*)
- **name** (*StringProperty, required*)
- **description** (*StringProperty*)
- **x_mitre_version** (*StringProperty*)
- **x_mitre_contributors** (*ListProperty*)
- **x_mitre_modified_by_ref** (*StringProperty*)
- **x_mitre_domains** (*ListProperty*)
- **x_mitre_attack_spec_version** (*StringProperty*)
- **aliases** (*ListProperty*)
- **kill_chain_phases** (*ListProperty*)
- **x_mitre_network_requirements** (*BooleanProperty*)
- **revoked** (*BooleanProperty*)
- **x_mitre_deprecated** (*BooleanProperty*)
- **labels** (*ListProperty*)
- **confidence** (*IntegerProperty*)
- **lang** (*StringProperty*)
- **external_references** (*ListProperty*)
- **object_marking_refs** (*ListProperty*)
- **granular_markings** (*ListProperty*)
- **extensions** (*ExtensionsProperty*)
- **x_mitre_detection** (*StringProperty*)
- **x_mitre_platforms** (*ListProperty*)
- **x_mitre_data_sources** (*ListProperty*)
- **x_mitre_is_subtechnique** (*BooleanProperty*)
- **x_mitre_system_requirements** (*ListProperty*)
- **x_mitre_tactic_type** (*ListProperty*)
- **x_mitre_permissions_required** (*ListProperty*)
- **x_mitre_effective_permissions** (*ListProperty*)
- **x_mitre_defense_bypassed** (*ListProperty*)
- **x_mitre_remote_support** (*BooleanProperty*)
- **x_mitre_impact_type** (*ListProperty*)
<br><br>

*class* **Tactic**

For more detailed information on this object's properties, see
    `the MITRE ATT&CK Stix specifications <https://github.com/mitre-attack/attack-stix-data/blob/master/USAGE.md>`__.

**Properties:**
- **type** (*TypeProperty*)
- **spec_version** (*StringProperty*)
- **id** (*IDProperty*)
- **created_by_ref** (*ReferenceProperty*)
- **created** (*TimestampProperty*)
- **modified** (*TimestampProperty*)
- **name** (*StringProperty, required*)
- **description** (*StringProperty*)
- **x_mitre_version** (*StringProperty*)
- **x_mitre_contributors** (*ListProperty*)
- **x_mitre_modified_by_ref** (*StringProperty*)
- **x_mitre_domains** (*ListProperty*)
- **x_mitre_attack_spec_version** (*StringProperty*)
- **revoked** (*BooleanProperty*)
- **x_mitre_deprecated** (*BooleanProperty*)
- **labels** (*ListProperty*)
- **confidence** (*IntegerProperty*)
- **lang** (*StringProperty*)
- **external_references** (*ListProperty*)
- **object_marking_refs** (*ListProperty*)
- **granular_markings** (*ListProperty*)
- **extensions** (*ExtensionsProperty*)
- **x_mitre_shortname** (*StringProperty*)
<br><br>

*class* **Technique**

For more detailed information on this object's properties, see
    `the MITRE ATT&CK Stix specifications <https://github.com/mitre-attack/attack-stix-data/blob/master/USAGE.md>`__.

**Properties:**
- **type** (*TypeProperty*)
- **spec_version** (*StringProperty*)
- **id** (*IDProperty*)
- **created_by_ref** (*ReferenceProperty*)
- **created** (*TimestampProperty*)
- **modified** (*TimestampProperty*)
- **name** (*StringProperty, required*)
- **description** (*StringProperty*)
- **x_mitre_version** (*StringProperty*)
- **x_mitre_contributors** (*ListProperty*)
- **x_mitre_modified_by_ref** (*StringProperty*)
- **x_mitre_domains** (*ListProperty*)
- **x_mitre_attack_spec_version** (*StringProperty*)
- **x_mitre_deprecated** (*BooleanProperty*)
- **x_mitre_network_requirements** (*BooleanProperty*)
- **aliases** (*ListProperty*)
- **kill_chain_phases** (*ListProperty*)
- **revoked** (*BooleanProperty*)
- **labels** (*ListProperty*)
- **confidence** (*IntegerProperty*)
- **lang** (*StringProperty*)
- **external_references** (*ListProperty*)
- **object_marking_refs** (*ListProperty*)
- **granular_markings** (*ListProperty*)
- **extensions** (*ExtensionsProperty*)
- **x_mitre_detection** (*StringProperty*)
- **x_mitre_platforms** (*ListProperty*)
- **x_mitre_data_sources** (*ListProperty*)
- **x_mitre_is_subtechnique** (*BooleanProperty*)
- **x_mitre_system_requirements** (*ListProperty*)
- **x_mitre_tactic_type** (*ListProperty*)
- **x_mitre_permissions_required** (*ListProperty*)
- **x_mitre_effective_permissions** (*ListProperty*)
- **x_mitre_defense_bypassed** (*ListProperty*)
- **x_mitre_remote_support** (*BooleanProperty*)
- **x_mitre_impact_type** (*ListProperty*)
<br><br>


## ```stixorm.module.definitions.os_threat.classes```
*class* **Anecdote**

For more detailed information on this object's properties, see
    `the xxxxxxxxx`__.

**Properties:**
- **type** (*TypeProperty*)
- **spec_version** (*StringProperty*)
- **id** (*IDProperty*)
- **value** (*StringProperty, required*)
- **report_date** (*TimestampProperty*)
- **provided_by_ref** (*ReferenceProperty*)
- **object_marking_refs** (*ListProperty*)
- **granular_markings** (*ListProperty*)
- **defanged** (*BooleanProperty*)
- **extensions** (*ExtensionsProperty*)
<br><br>

*class* **AnecdoteExt**

For more detailed information on this object's properties, see
    `the __.

**Properties:**
- **extension_type** (*StringProperty*)
<br><br>

*class* **Availability**

For more detailed information on this object's properties, see
    `the  https://github.com/dod-cyber-crime-center/cti-stix-common-objects/blob/incident_rework/extension-definition-specifications/incident-core/Incident%20Extension%20Suite.adoc`__.

**Properties:**
- **availability_impact** (*IntegerProperty*)
<br><br>

*class* **Confidentiality**

For more detailed information on this object's properties, see
    `the  https://github.com/dod-cyber-crime-center/cti-stix-common-objects/blob/incident_rework/extension-definition-specifications/incident-core/Incident%20Extension%20Suite.adoc`__.

**Properties:**
- **information_type** (*StringProperty*)
- **loss_type** (*StringProperty*)
- **record_count** (*IntegerProperty*)
- **record_size** (*IntegerProperty*)
<br><br>

*class* **ContactNumber**

For more detailed information on this object's properties, see
    `the OS-Threat documentation`__.

**Properties:**
- **description** (*StringProperty*)
- **contact_number_type** (*StringProperty, required*)
- **contact_number** (*StringProperty, required*)
<br><br>

*class* **EmailContact**

For more detailed information on this object's properties, see
    `the OS-Threat documentation`__.

**Properties:**
- **description** (*StringProperty*)
- **digital_contact_type** (*StringProperty, required*)
- **email_address_ref** (*ReferenceProperty, required*)
<br><br>

*class* **Event**

For more detailed information on this object's properties, see
    `the https://github.com/os-threat/stix-extensions/wiki/2.-Description-of-Incident-Model`__.

**Properties:**
- **type** (*TypeProperty*)
- **spec_version** (*StringProperty*)
- **id** (*IDProperty*)
- **created_by_ref** (*ReferenceProperty*)
- **created** (*TimestampProperty*)
- **modified** (*TimestampProperty*)
- **status** (*StringProperty*)
- **changed_objects** (*ListProperty*)
- **description** (*StringProperty*)
- **end_time** (*TimestampProperty*)
- **end_time_fidelity** (*StringProperty*)
- **event_types** (*ListProperty*)
- **goal** (*StringProperty*)
- **name** (*StringProperty*)
- **sighting_refs** (*ListProperty*)
- **start_time** (*TimestampProperty*)
- **start_time_fidelity** (*StringProperty*)
- **labels** (*ListProperty*)
- **confidence** (*IntegerProperty*)
- **lang** (*StringProperty*)
- **external_references** (*ListProperty*)
- **object_marking_refs** (*ListProperty*)
- **granular_markings** (*ListProperty*)
- **extensions** (*ThreatExtensionsProperty*)
<br><br>

*class* **EventCoreExt**

For more detailed information on this object's properties, see
    `the  https://github.com/os-threat/stix-extensions/wiki/2.-Description-of-Incident-Model`__.

**Properties:**
- **extension_type** (*StringProperty*)
<br><br>

*class* **External**

For more detailed information on this object's properties, see
    `the  https://github.com/dod-cyber-crime-center/cti-stix-common-objects/blob/incident_rework/extension-definition-specifications/incident-core/Incident%20Extension%20Suite.adoc`__.

**Properties:**
- **impact_type** (*StringProperty*)
<br><br>

*class* **Feed**

For more detailed information on this object's properties, see
    `the OS-Threat documentation`__.

**Properties:**
- **type** (*TypeProperty*)
- **spec_version** (*StringProperty*)
- **id** (*IDProperty*)
- **created_by_ref** (*ReferenceProperty*)
- **created** (*TimestampProperty*)
- **modified** (*TimestampProperty*)
- **name** (*StringProperty, required*)
- **description** (*StringProperty*)
- **paid** (*BooleanProperty*)
- **free** (*BooleanProperty*)
- **labels** (*ListProperty*)
- **confidence** (*IntegerProperty*)
- **lang** (*StringProperty*)
- **external_references** (*ListProperty*)
- **object_marking_refs** (*ListProperty*)
- **granular_markings** (*ListProperty*)
- **extensions** (*ExtensionsProperty*)
- **contents** (*ListProperty*)
<br><br>

*class* **Feeds**

For more detailed information on this object's properties, see
    `the OS-Threat documentation`__.

**Properties:**
- **type** (*TypeProperty*)
- **spec_version** (*StringProperty*)
- **id** (*IDProperty*)
- **created_by_ref** (*ReferenceProperty*)
- **created** (*TimestampProperty*)
- **modified** (*TimestampProperty*)
- **name** (*StringProperty, required*)
- **description** (*StringProperty*)
- **paid** (*BooleanProperty*)
- **free** (*BooleanProperty*)
- **labels** (*ListProperty*)
- **confidence** (*IntegerProperty*)
- **lang** (*StringProperty*)
- **external_references** (*ListProperty*)
- **object_marking_refs** (*ListProperty*)
- **granular_markings** (*ListProperty*)
- **extensions** (*ExtensionsProperty*)
- **contained** (*ListProperty*)
<br><br>

*class* **IdentityContact**

For more detailed information on this object's properties, see
    `the

**Properties:**
- **extension_type** (*StringProperty, required*)
- **contact_numbers** (*ListProperty*)
- **email_addresses** (*ListProperty*)
- **first_name** (*StringProperty*)
- **last_name** (*StringProperty*)
- **middle_name** (*StringProperty*)
- **prefix** (*StringProperty*)
- **social_media_accounts** (*ListProperty*)
- **suffix** (*StringProperty*)
- **team** (*StringProperty*)
<br><br>

*class* **Impact**

For more detailed information on this object's properties, see
    `the https://github.com/os-threat/stix-extensions/wiki/2.-Description-of-Incident-Model`__.

**Properties:**
- **type** (*TypeProperty*)
- **spec_version** (*StringProperty*)
- **id** (*IDProperty*)
- **created_by_ref** (*ReferenceProperty*)
- **created** (*TimestampProperty*)
- **modified** (*TimestampProperty*)
- **impact_category** (*StringProperty*)
- **criticality** (*IntegerProperty*)
- **description** (*StringProperty*)
- **end_time** (*TimestampProperty*)
- **end_time_fidelity** (*StringProperty*)
- **impacted_entity_counts** (*DictionaryProperty*)
- **impacted_refs** (*ListProperty*)
- **recoverability** (*StringProperty*)
- **start_time** (*TimestampProperty*)
- **start_time_fidelity** (*StringProperty*)
- **superseded_by_ref** (*ThreatReference*)
- **labels** (*ListProperty*)
- **confidence** (*IntegerProperty*)
- **lang** (*StringProperty*)
- **external_references** (*ListProperty*)
- **object_marking_refs** (*ListProperty*)
- **granular_markings** (*ListProperty*)
- **extensions** (*ThreatExtensionsProperty*)
<br><br>

*class* **ImpactCoreExt**

For more detailed information on this object's properties, see
    `the  https://github.com/os-threat/stix-extensions/wiki/2.-Description-of-Incident-Model`__.

**Properties:**
- **extension_type** (*StringProperty*)
<br><br>

*class* **IncidentCoreExt**

For more detailed information on this object's properties, see
    `the https://github.com/os-threat/stix-extensions/wiki/2.-Description-of-Incident-Model`__.

**Properties:**
- **extension_type** (*StringProperty*)
- **investigation_status** (*StringProperty*)
- **blocked** (*BooleanProperty*)
- **malicious** (*BooleanProperty*)
- **criticality** (*IntegerProperty*)
- **determination** (*StringProperty*)
- **incident_types** (*ListProperty*)
- **impacted_entity_counts** (*DictionaryProperty*)
- **recoverability** (*ListProperty*)
- **scores** (*ListProperty*)
- **sequence_start_refs** (*ListProperty*)
- **sequence_refs** (*ListProperty*)
- **task_refs** (*ListProperty*)
- **event_refs** (*ListProperty*)
- **impact_refs** (*ListProperty*)
- **other_object_refs** (*ListProperty*)
<br><br>

*class* **IncidentScoreObject**

For more detailed information on this object's properties, see
    `the https://github.com/os-threat/stix-extensions/wiki/2.-Description-of-Incident-Model`__.

**Properties:**
- **name** (*StringProperty*)
- **value** (*IntegerProperty*)
- **description** (*StringProperty*)
<br><br>

*class* **Integrity**

For more detailed information on this object's properties, see
    `the  https://github.com/dod-cyber-crime-center/cti-stix-common-objects/blob/incident_rework/extension-definition-specifications/incident-core/Incident%20Extension%20Suite.adoc`__.

**Properties:**
- **alteration** (*StringProperty*)
- **information_type** (*StringProperty*)
- **record_count** (*IntegerProperty*)
- **record_size** (*IntegerProperty*)
<br><br>

*class* **Monetary**

For more detailed information on this object's properties, see
    `the  https://github.com/dod-cyber-crime-center/cti-stix-common-objects/blob/incident_rework/extension-definition-specifications/incident-core/Incident%20Extension%20Suite.adoc`__.

**Properties:**
- **variety** (*StringProperty*)
- **conversion_rate** (*FloatProperty*)
- **conversion_time** (*TimestampProperty*)
- **currency** (*StringProperty*)
- **currency_actual** (*StringProperty*)
- **max_amount** (*FloatProperty*)
- **min_amount** (*FloatProperty*)
<br><br>

*class* **Physical**

For more detailed information on this object's properties, see
    `the  https://github.com/dod-cyber-crime-center/cti-stix-common-objects/blob/incident_rework/extension-definition-specifications/incident-core/Incident%20Extension%20Suite.adoc`__.

**Properties:**
- **impact_type** (*StringProperty*)
- **asset_type** (*StringProperty*)
<br><br>

*class* **Sequence**

For more detailed information on this object's properties, see
    `the https://github.com/os-threat/stix-extensions/wiki/2.-Description-of-Incident-Model`__.

**Properties:**
- **type** (*TypeProperty*)
- **spec_version** (*StringProperty*)
- **id** (*IDProperty*)
- **created_by_ref** (*ReferenceProperty*)
- **created** (*TimestampProperty*)
- **modified** (*TimestampProperty*)
- **sequenced_object** (*ThreatReference*)
- **sequence_type** (*StringProperty*)
- **step_type** (*StringProperty*)
- **on_completion** (*ThreatReference*)
- **on_success** (*ThreatReference*)
- **on_failure** (*ThreatReference*)
- **next_steps** (*ListProperty*)
- **labels** (*ListProperty*)
- **confidence** (*IntegerProperty*)
- **lang** (*StringProperty*)
- **external_references** (*ListProperty*)
- **object_marking_refs** (*ListProperty*)
- **granular_markings** (*ListProperty*)
- **extensions** (*ThreatExtensionsProperty*)
<br><br>

*class* **SequenceExt**

For more detailed information on this object's properties, see
    `the  https://github.com/os-threat/stix-extensions/wiki/2.-Description-of-Incident-Model`__.

**Properties:**
- **extension_type** (*StringProperty*)
<br><br>

*class* **SightingAlert**

For more detailed information on this object's properties, see
    `the  https://github.com/dod-cyber-crime-center/cti-stix-common-objects/blob/incident_rework/extension-definition-specifications/incident-core/Incident%20Extension%20Suite.adoc`__.

**Properties:**
- **name** (*StringProperty*)
- **log** (*StringProperty*)
- **system_id** (*StringProperty*)
- **source** (*StringProperty*)
- **product** (*StringProperty*)
- **format** (*StringProperty*)
<br><br>

*class* **SightingAnecdote**

For more detailed information on this object's properties, see
    `the  https://github.com/dod-cyber-crime-center/cti-stix-common-objects/blob/incident_rework/extension-definition-specifications/incident-core/Incident%20Extension%20Suite.adoc`__.

**Properties:**
- **person_name** (*StringProperty*)
- **person_context** (*StringProperty*)
- **report_submission** (*StringProperty*)
<br><br>

*class* **SightingContext**

For more detailed information on this object's properties, see
    `the  https://github.com/dod-cyber-crime-center/cti-stix-common-objects/blob/incident_rework/extension-definition-specifications/incident-core/Incident%20Extension%20Suite.adoc`__.

**Properties:**
- **name** (*StringProperty*)
- **description** (*StringProperty*)
- **value** (*StringProperty*)
<br><br>

*class* **SightingEnrichment**

For more detailed information on this object's properties, see
    `the  https://github.com/dod-cyber-crime-center/cti-stix-common-objects/blob/incident_rework/extension-definition-specifications/incident-core/Incident%20Extension%20Suite.adoc`__.

**Properties:**
- **name** (*StringProperty*)
- **url** (*StringProperty*)
- **paid** (*BooleanProperty*)
- **value** (*StringProperty*)
<br><br>

*class* **SightingEvidence**

For more detailed information on this object's properties, see
    `the https://github.com/os-threat/stix-extensions/wiki/2.-Description-of-Incident-Model`__.

**Properties:**
- **extension_type** (*StringProperty*)
<br><br>

*class* **SightingExclusion**

For more detailed information on this object's properties, see
    `the  https://github.com/dod-cyber-crime-center/cti-stix-common-objects/blob/incident_rework/extension-definition-specifications/incident-core/Incident%20Extension%20Suite.adoc`__.

**Properties:**
- **source** (*StringProperty*)
- **channel** (*StringProperty*)
<br><br>

*class* **SightingExternal**

For more detailed information on this object's properties, see
    `the  https://github.com/dod-cyber-crime-center/cti-stix-common-objects/blob/incident_rework/extension-definition-specifications/incident-core/Incident%20Extension%20Suite.adoc`__.

**Properties:**
- **source** (*StringProperty*)
- **version** (*StringProperty*)
- **last_update** (*TimestampProperty*)
- **pattern** (*StringProperty*)
- **pattern_type** (*StringProperty*)
- **payload** (*StringProperty*)
- **valid_from** (*TimestampProperty*)
- **valid_until** (*TimestampProperty*)
<br><br>

*class* **SightingFramework**

For more detailed information on this object's properties, see
    `the  https://github.com/dod-cyber-crime-center/cti-stix-common-objects/blob/incident_rework/extension-definition-specifications/incident-core/Incident%20Extension%20Suite.adoc`__.

**Properties:**
- **framework** (*StringProperty*)
- **version** (*StringProperty*)
- **domain** (*StringProperty*)
- **comparison** (*StringProperty*)
- **comparison_approach** (*StringProperty*)
<br><br>

*class* **SightingHunt**

For more detailed information on this object's properties, see
    `the  https://github.com/dod-cyber-crime-center/cti-stix-common-objects/blob/incident_rework/extension-definition-specifications/incident-core/Incident%20Extension%20Suite.adoc`__.

**Properties:**
- **name** (*StringProperty*)
- **playbook_id** (*StringProperty*)
- **rule** (*StringProperty*)
<br><br>

*class* **SocialMediaContact**

For more detailed information on this object's properties, see
    `the OS-Threat documentation`__.

**Properties:**
- **description** (*StringProperty*)
- **digital_contact_type** (*StringProperty, required*)
- **user_account_ref** (*ReferenceProperty, required*)
<br><br>

*class* **StateChangeObject**

For more detailed information on this object's properties, see
    `the https://github.com/os-threat/stix-extensions/wiki/2.-Description-of-Incident-Model`__.

**Properties:**
- **state_change_type** (*StringProperty*)
- **initial_ref** (*ThreatReference*)
- **result_ref** (*ThreatReference*)
<br><br>

*class* **Task**

For more detailed information on this object's properties, see
    `the https://github.com/os-threat/stix-extensions/wiki/2.-Description-of-Incident-Model`__.

**Properties:**
- **type** (*TypeProperty*)
- **spec_version** (*StringProperty*)
- **id** (*IDProperty*)
- **created_by_ref** (*ReferenceProperty*)
- **created** (*TimestampProperty*)
- **modified** (*TimestampProperty*)
- **changed_objects** (*ListProperty*)
- **task_types** (*ListProperty*)
- **outcome** (*StringProperty*)
- **description** (*StringProperty*)
- **end_time** (*TimestampProperty*)
- **end_time_fidelity** (*StringProperty*)
- **error** (*StringProperty*)
- **impacted_entity_counts** (*DictionaryProperty*)
- **name** (*StringProperty, required*)
- **priority** (*IntegerProperty*)
- **start_time** (*TimestampProperty*)
- **start_time_fidelity** (*StringProperty*)
- **owner** (*ReferenceProperty*)
- **labels** (*ListProperty*)
- **confidence** (*IntegerProperty*)
- **lang** (*StringProperty*)
- **external_references** (*ListProperty*)
- **object_marking_refs** (*ListProperty*)
- **granular_markings** (*ListProperty*)
- **extensions** (*ThreatExtensionsProperty*)
<br><br>

*class* **TaskCoreExt**

For more detailed information on this object's properties, see
    `the  https://github.com/os-threat/stix-extensions/wiki/2.-Description-of-Incident-Model`__.

**Properties:**
- **extension_type** (*StringProperty*)
<br><br>

*class* **ThreatSubObject**

For more detailed information on this object's properties, see
    `the OS-Threat documentation`__.

**Properties:**
- **object_ref** (*ThreatReference*)
- **created** (*TimestampProperty*)
- **modified** (*TimestampProperty*)
<br><br>

*class* **Traceability**

For more detailed information on this object's properties, see
    `the  https://github.com/dod-cyber-crime-center/cti-stix-common-objects/blob/incident_rework/extension-definition-specifications/incident-core/Incident%20Extension%20Suite.adoc`__.

**Properties:**
- **traceability_impact** (*StringProperty*)
<br><br>

## ```stixorm.module.definitions.stix21.classes```
*class* **Identity**

For more detailed information on this object's properties, see
    `the STIX 2.1 specification <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_wh296fiwpklp>`__.

**Properties:**
- **type** (*TypeProperty*)
- **spec_version** (*StringProperty*)
- **id** (*IDProperty*)
- **created_by_ref** (*ReferenceProperty*)
- **created** (*TimestampProperty*)
- **modified** (*TimestampProperty*)
- **name** (*StringProperty, required*)
- **description** (*StringProperty*)
- **roles** (*ListProperty*)
- **identity_class** (*OpenVocabProperty*)
- **sectors** (*ListProperty*)
- **contact_information** (*StringProperty*)
- **revoked** (*BooleanProperty*)
- **labels** (*ListProperty*)
- **confidence** (*IntegerProperty*)
- **lang** (*StringProperty*)
- **external_references** (*ListProperty*)
- **object_marking_refs** (*ListProperty*)
- **granular_markings** (*ListProperty*)
- **extensions** (*ThreatExtensionsProperty*)
<br><br>

*class* **Incident**

For more detailed information on this object's properties, see
    `the STIX 2.1 specification <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_sczfhw64pjxt>`__.

**Properties:**
- **type** (*TypeProperty*)
- **spec_version** (*StringProperty*)
- **id** (*IDProperty*)
- **created_by_ref** (*ReferenceProperty*)
- **created** (*TimestampProperty*)
- **modified** (*TimestampProperty*)
- **name** (*StringProperty, required*)
- **description** (*StringProperty*)
- **kill_chain_phases** (*ListProperty*)
- **revoked** (*BooleanProperty*)
- **labels** (*ListProperty*)
- **confidence** (*IntegerProperty*)
- **lang** (*StringProperty*)
- **external_references** (*ListProperty*)
- **object_marking_refs** (*ListProperty*)
- **granular_markings** (*ListProperty*)
- **extensions** (*ThreatExtensionsProperty*)
<br><br>

*class* **Note**

For more detailed information on this object's properties, see
    `the STIX 2.1 specification <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_gudodcg1sbb9>`__.

**Properties:**
- **type** (*TypeProperty*)
- **spec_version** (*StringProperty*)
- **id** (*IDProperty*)
- **created_by_ref** (*ReferenceProperty*)
- **created** (*TimestampProperty*)
- **modified** (*TimestampProperty*)
- **abstract** (*StringProperty*)
- **content** (*StringProperty, required*)
- **authors** (*ListProperty*)
- **object_refs** (*ListProperty, required*)
- **revoked** (*BooleanProperty*)
- **labels** (*ListProperty*)
- **confidence** (*IntegerProperty*)
- **lang** (*StringProperty*)
- **external_references** (*ListProperty*)
- **object_marking_refs** (*ListProperty*)
- **granular_markings** (*ListProperty*)
- **extensions** (*ExtensionsProperty*)
<br><br>

*class* **ObservedData**

For more detailed information on this object's properties, see
    `the STIX 2.1 specification <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_p49j1fwoxldc>`__.

**Properties:**
- **type** (*TypeProperty*)
- **spec_version** (*StringProperty*)
- **id** (*IDProperty*)
- **created_by_ref** (*ReferenceProperty*)
- **created** (*TimestampProperty*)
- **modified** (*TimestampProperty*)
- **first_observed** (*TimestampProperty, required*)
- **last_observed** (*TimestampProperty, required*)
- **number_observed** (*IntegerProperty, required*)
- **objects** (*ObservableProperty*)
- **object_refs** (*ListProperty, required*)
- **revoked** (*BooleanProperty*)
- **labels** (*ListProperty*)
- **confidence** (*IntegerProperty*)
- **lang** (*StringProperty*)
- **external_references** (*ListProperty*)
- **object_marking_refs** (*ListProperty*)
- **granular_markings** (*ListProperty*)
- **extensions** (*ExtensionsProperty*)
<br><br>

*class* **Relationship**

For more detailed information on this object's properties, see
    `the STIX 2.1 specification <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_e2e1szrqfoan>`__.

**Properties:**
- **type** (*TypeProperty*)
- **spec_version** (*StringProperty*)
- **id** (*IDProperty*)
- **created_by_ref** (*ReferenceProperty*)
- **created** (*TimestampProperty*)
- **modified** (*TimestampProperty*)
- **relationship_type** (*StringProperty, required*)
- **description** (*StringProperty*)
- **source_ref** (*ThreatReference, required*)
- **target_ref** (*ThreatReference, required*)
- **start_time** (*TimestampProperty*)
- **stop_time** (*TimestampProperty*)
- **revoked** (*BooleanProperty*)
- **labels** (*ListProperty*)
- **confidence** (*IntegerProperty*)
- **lang** (*StringProperty*)
- **external_references** (*ListProperty*)
- **object_marking_refs** (*ListProperty*)
- **granular_markings** (*ListProperty*)
- **extensions** (*ExtensionsProperty*)
<br><br>

*class* **Report**

For more detailed information on this object's properties, see
    `the STIX 2.1 specification <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_n8bjzg1ysgdq>`__.

**Properties:**
- **type** (*TypeProperty*)
- **spec_version** (*StringProperty*)
- **id** (*IDProperty*)
- **created_by_ref** (*ReferenceProperty*)
- **created** (*TimestampProperty*)
- **modified** (*TimestampProperty*)
- **name** (*StringProperty, required*)
- **description** (*StringProperty*)
- **report_types** (*ListProperty*)
- **published** (*TimestampProperty, required*)
- **object_refs** (*ListProperty, required*)
- **revoked** (*BooleanProperty*)
- **labels** (*ListProperty*)
- **confidence** (*IntegerProperty*)
- **lang** (*StringProperty*)
- **external_references** (*ListProperty*)
- **object_marking_refs** (*ListProperty*)
- **granular_markings** (*ListProperty*)
- **extensions** (*ExtensionsProperty*)
<br><br>

*class* **Sighting**

For more detailed information on this object's properties, see
    `the STIX 2.1 specification <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_a795guqsap3r>`__.

**Properties:**
- **type** (*TypeProperty*)
- **spec_version** (*StringProperty*)
- **id** (*IDProperty*)
- **created_by_ref** (*ReferenceProperty*)
- **created** (*TimestampProperty*)
- **modified** (*TimestampProperty*)
- **description** (*StringProperty*)
- **first_seen** (*TimestampProperty*)
- **last_seen** (*TimestampProperty*)
- **count** (*IntegerProperty*)
- **sighting_of_ref** (*ReferenceProperty, required*)
- **observed_data_refs** (*ListProperty*)
- **where_sighted_refs** (*ListProperty*)
- **summary** (*BooleanProperty*)
- **revoked** (*BooleanProperty*)
- **labels** (*ListProperty*)
- **confidence** (*IntegerProperty*)
- **lang** (*StringProperty*)
- **external_references** (*ListProperty*)
- **object_marking_refs** (*ListProperty*)
- **granular_markings** (*ListProperty*)
- **extensions** (*ThreatExtensionsProperty*)
<br><br>

