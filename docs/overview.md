# Stix-ORM Overview



The Stix-ORM Library is an open-source Python Library built on top of the [OASIS Stix2 Python Library](https://stix2.readthedocs.io/en/latest/index.html) in order to make it simple to use TypeDB as a [DataStore](https://stix2.readthedocs.io/en/latest/guide/datastore.html), and extend it to suit additional protocols, such as Mitre ATT&CK, OASIS CACAO, OCA Kestrel, and custom objects (e.g. case management, feed management etc).



## What is it?

The [OASIS Stix2 Python Library](https://stix2.readthedocs.io/en/latest/index.html) is designed to make it as easy as possible to produce and consume Stix 2.1 content. It is comprised of three layers:

1. Object Layer: Is where Python objects representing the Stix 2,1 data types (SDO, SCO and SRO), and sub-objects (external references, kill-chain phases, extensions etc.) are create and can be sereialised and deserialised to and from their JSON representation

2. Environment Layer: Components that make it easier to handle Stix 2.1 data as part of alarger applications, including DataSink's for storing data, DataSource's for retrieving data, and Object Factory's to create al of the common properties and markings

3. Workbench Layer: Python functions for use in an interctive environment (e.g. Jupyter Notebook) to enable comparison of objects, searching for objects and comparison of graphs.



The [OS-Threat Stix-ORM Library]() integrates with the OASIS Stix 2 Python Library to:

1. Provide a TypeDB DataSource and DataSink capability to store and retrieve Stix objects using simple python verbs, add, get, delete etc., including a simple reasoning system

2. Extend the Python Object, Parse, TypeDB DataSource and DataSink capabilities to additional cybersecurity protocols, such as MITRE ATT&CK, enabling validation of incoming objects, and the ability to create new correct objects

3. Enable custom objects, Stix extensions and new language protocols to be added relatively easily, so the library can be extended easily by users and researchers. 

4. Load common data assets, Stix - TLP-markings, common objects, MITRE ATT&CK, CVE's

5. Produce a platform for further developments and collaboration



The OS-Threat Stix-ORM library can be installed using pip, and is well documented.



An image of these concepts is shown below.

![](img/Library_overview.png)



## What are the Benefits?

[TypeDB is without a doubt, the most powerful datastore for cybersecurity](typedb_benefits.md), because:

1. Semantic Hypergraph: Enables elegant, succinct representation of intricate cybersecurity objects and relationships

2. Fully Normalised Attributes: Data is only written once (e.g. Stix-ID, hash etc.), as attrbutes are normalised as a database guarantee

3. Unique Data Modelling: Unique modelling capabilities of attributes owning attributes (used in key-value store), and relations able to play roles in other relations

4. Class hierarchy on Entities, Relations and Attributes: Enables rich behavioural modelling of objects, sub-objects, properties, relations and linkages

5. When->Then Horn Logic rule system, enabling inference over large datasets dynamically triggered at query time, with an included example

6. Elegant query of complex objects through class hierarchy combined with rulesets



## Near-term Feature Roadmap

Very quickly we aim to add the following features to the system.

1. Add support for OASIS CACAO and OCA Kestrel protocols

2. Add support for Stix Patterns, and extend the method to all objects and properties

3. Add support for open vocabulary words to be selectively added

4. Add support for Stix extensions, and the ability to import Stix extensions

5. Add support for Detections, Mitigations and Tests connected to TTP's, and NIST Controls

6. Add import capability for all rulesets, tests and controls (e.g. Control Compass and Engenuity CTID)



The documentation system contains the following sections:

- [Using the Stix-ORM](using/configuration.md)

- [How the ORM Works](orm/orm_oveview.md)

- [Protcols Supported](protocols/_orig.md)

- [Interacting with Stix-ORM](interactions/overview.md)



The current supported objects can be viewed here







## Total Objects in the System



###  Domain Object's Types

#### OASIS Stix 2.1 

| Icon | Object Type | Icon | Object Type | Icon | Object Type  |
|:----------:|:-----------|:----------:|:-----------|:----------:|:----------- |
| ![attack-pattern](./protocols/stix21/icons/stix2_attack_pattern_icon_tiny_round_v1.png) | [attack-pattern](./protocols/stix21/sdo/Attack-Pattern.md)| ![campaign](./protocols/stix21/icons/stix2_campaign_icon_tiny_round_v1.png) | [campaign](./protocols/stix21/sdo/Campaign.md)| ![course-of-action'](./protocols/stix21/icons/stix2_course_of_action_icon_tiny_round_v1.png) | [course-of-action'](./protocols/stix21/sdo/Course-of-Action.md) |
| ![grouping](./protocols/stix21/icons/stix2_grouping_icon_tiny_round_v1.png) | [grouping](./protocols/stix21/sdo/Grouping.md)| ![identity](./protocols/stix21/icons/stix2_identity_icon_tiny_round_v1.png) | [identity](./protocols/stix21/sdo/Identity.md)| ![incident](./protocols/stix21/icons/stix2_incident_icon_tiny_round_v1.png) | [incident](./protocols/stix21/sdo/Incident.md) |
| ![indicator](./protocols/stix21/icons/stix2_indicator_icon_tiny_round_v1.png) | [indicator](./protocols/stix21/sdo/Indicator.md)| ![infrastructure](./protocols/stix21/icons/stix2_infrastructure_icon_tiny_round_v1.png) | [infrastructure](./protocols/stix21/sdo/Infrastructure.md)| ![intrusion-set](./protocols/stix21/icons/stix2_intrusion_set_icon_tiny_round_v1.png) | [intrusion-set](./protocols/stix21/sdo/Intrusion-Set.md) |
| ![location](./protocols/stix21/icons/stix2_location_icon_tiny_round_v1.png) | [location](./protocols/stix21/sdo/Location.md)| ![malware](./protocols/stix21/icons/stix2_malware_icon_tiny_round_v1.png) | [malware](./protocols/stix21/sdo/Malware.md)| ![malware-analysis](./protocols/stix21/icons/stix2_malware_analysis_icon_tiny_round_v1.png) | [malware-analysis](./protocols/stix21/sdo/Malware-Analysis.md) |
| ![note](./protocols/stix21/icons/stix2_note_icon_tiny_round_v1.png) | [note](./protocols/stix21/sdo/Note.md)| ![observed-data](./protocols/stix21/icons/stix2_observed_data_icon_tiny_round_v1.png) | [observed-data](./protocols/stix21/sdo/Observed-Data.md)| ![opinion](./protocols/stix21/icons/stix2_opinion_icon_tiny_round_v1.png) | [opinion](./protocols/stix21/sdo/Opinion.md) |
| ![report](./protocols/stix21/icons/stix2_report_icon_tiny_round_v1.png) | [report](./protocols/stix21/sdo/Report.md)| ![threat-actor](./protocols/stix21/icons/stix2_report_icon_tiny_round_v1.png) | [threat-actor](./protocols/stix21/sdo/Threat-Actor.md)| ![tool](./protocols/stix21/icons/stix2_tool_icon_tiny_round_v1.png) | [tool](./protocols/stix21/sdo/Tool.md) |
| ![vulnerability](./protocols/stix21/icons/stix2_vulnerability_icon_tiny_round_v1.png) | [vulnerability](./protocols/stix21/sdo/Vulnerability.md)| ![]() | []()| ![]() | []() |



#### MITRE ATT&CK 

| Icon | Object Type | Icon | Object Type | Icon | Object Type  |
|:----------:|:-----------|:----------:|:-----------|:----------:|:----------- |
| ![matrix](./protocols/attack/icons/attack_icon_matrix.png) | [matrix]()| ![tactic](./protocols/attack/icons/attack_icon_tactic.png) | [tactic]()| ![technique](./protocols/attack/icons/attack_icon_technique.png) | [technique]() |
| ![subtechnique](./protocols/attack/icons/attack_icon_subtechnique.png) | [subtechnique]()| ![mitigation](./protocols/attack/icons/attack_icon_mitigation.png) | [mitigation]()| ![group](./protocols/attack/icons/attack_icon_group.png) | [group]() |
| ![software-malware](./protocols/attack/icons/attack_icon_software.png) | [software-malware]()| ![software-tool](./protocols/attack/icons/attack_icon_software.png) | [software-tool]()| ![collection](./protocols/attack/icons/attack_icon_collection.png) | [collection]() |
| ![data-source](./protocols/attack/icons/attack_icon_data_source.png) | [data-source]()| ![data-component](./protocols/attack/icons/attack_icon_data_component.png) | [data-component]()| ![attack-campaign](./protocols/attack/icons/attack_icon_campaign.png) | [attack-campaign]() |




###  Cyber Observable Object Types

#### OASIS Stix 2.1 

| Icon | Object Type | Icon | Object Type | Icon | Object Type  |
|:----------:|:-----------|:----------:|:-----------|:----------:|:----------- |
| ![artifact](./protocols/stix21/icons/stix2_artifact_icon_tiny_round_v1.png) | [artifact](./protocols/stix21/sco/Artifact.md)| ![autonomous-system](./protocols/stix21/icons/stix2_autonomous_system_icon_tiny_round_v1.png) | [autonomous-system](./protocols/stix21/sco/Autonomous-System.md)| ![directory](./protocols/stix21/icons/stix2_directory_icon_tiny_round_v1.png) | [directory](./protocols/stix21/sco/Directory.md) |
| ![domain-name](./protocols/stix21/icons/stix2_domain_name_icon_tiny_round_v1.png) | [domain-name](./protocols/stix21/sco/Domain-Name.md)| ![email-addr](./protocols/stix21/icons/stix2_email_addr_icon_tiny_round_v1.png) | [email-addr](./protocols/stix21/sco/Email-Address.md)| ![email-message](./protocols/stix21/icons/stix2_email_message_icon_tiny_round_v1.png) | [email-message](./protocols/stix21/sco/Email-Message.md) |
| ![file](./protocols/stix21/icons/stix2_file_icon_tiny_round_v1.png) | [file](./protocols/stix21/sco/File.md)| ![ipv4-addr](./protocols/stix21/icons/stix2_ipv4_addr_icon_tiny_round_v1.png) | [ipv4-addr](./protocols/stix21/sco/IPv4-Address.md)| ![ipv6-addr](./protocols/stix21/icons/stix2_ipv6_addr_icon_tiny_round_v1.png) | [ipv6-addr](./protocols/stix21/sco/IPv6-Address.md) |
| ![mac-addr](./protocols/stix21/icons/stix2_mac_addr_icon_tiny_round_v1.png) | [mac-addr](./protocols/stix21/sco/MAC-Address.md)| ![mutex](./protocols/stix21/icons/stix2_mutex_icon_tiny_round_v1.png) | [mutex](./protocols/stix21/sco/Mutex.md)| ![network-traffic](./protocols/stix21/icons/stix2_network_traffic_icon_tiny_round_v1.png) | [network-traffic](./protocols/stix21/sco/Network-Traffic.md) |
| ![process](./protocols/stix21/icons/stix2_process_icon_tiny_round_v1.png) | [process](./protocols/stix21/sco/Process.md)| ![software](./protocols/stix21/icons/stix2_software_icon_tiny_round_v1.png) | [software](./protocols/stix21/sco/Software.md)| ![url](./protocols/stix21/icons/stix2_url_icon_tiny_round_v1.png) | [url](./protocols/stix21/sco/URL.md) |
| ![user-account](./protocols/stix21/icons/stix2_user_account_icon_tiny_round_v1.png) | [user-account](./protocols/stix21/sco/User-Account.md)| ![windows-registry-key](./protocols/stix21/icons/stix2_windows_registry_key_icon_tiny_round_v1.png) | [windows-registry-key](./protocols/stix21/sco/Windows-Regaistry-Key.md)| ![x509-certificate](./protocols/stix21/icons/stix2_x509_certificate_icon_tiny_round_v1.png) | [x509-certificate](./protocols/stix21/sco/X.509-Certificate.md) |




###  Relationship Object Types

#### OASIS Stix 2.1 

| Icon | Object Type | Icon | Object Type | Icon | Object Type  |
|:----------:|:-----------|:----------:|:-----------|:----------:|:----------- |
| ![stix-core-relationship](./protocols/stix21/icons/stix2_relationship_icon_tiny_round_v1.png) | [stix-core-relationship]()| ![sighting](./protocols/stix21/icons/stix2_sighting_icon_tiny_round_v1.png) | [sighting]()| ![]() | []() |



#### MITRE ATT&CK 

| Icon | Object Type | Icon | Object Type | Icon | Object Type  |
|:----------:|:-----------|:----------:|:-----------|:----------:|:----------- |
| ![]() | [attack-relation]()| ![]() | []()| ![]() | []() |




###  Sub-Object Types

#### OASIS Stix 2.1 

| Icon | Object Type | Icon | Object Type | Icon | Object Type  |
|:----------:|:-----------|:----------:|:-----------|:----------:|:----------- |
| ![]() | [alternate-data-stream](./protocols/stix21/sub/File-NTFS.md)| ![]() | [archive-ext](./protocols/stix21/sub/File-Archive.md)| ![]() | [email-mime-part](./protocols/stix21/sub/Email-MIME-Component.md) |
| ![]() | [external-reference]()| ![]() | [hash_typeql_dict]()| ![]() | [http-request-ext](./protocols/stix21/sub/Network-HTTP.md) |
| ![]() | [icmp-ext](./protocols/stix21/sub/Network-ICMP.md)| ![]() | [kill-chain-phase]()| ![]() | [ntfs-ext](./protocols/stix21/sub/File-NTFS.md) |
| ![]() | [pdf-ext](./protocols/stix21/sub/File-PDF)| ![]() | [raster-image-ext](./protocols/stix21/sub/File-Raster-Image.md)| ![]() | [socket-ext](./protocols/stix21/sub/Network-Socket.md) |
| ![]() | [tcp-ext](./protocols/stix21/sub/Network-TCP.md)| ![]() | [unix-account-ext](./protocols/stix21/sub/User-UNIX-Account.md)| ![]() | [windows-pe-optional-header-type](./protocols/stix21/sub/File-Windows-PE-Binary.md) |
| ![]() | [windows-pe-section]()| ![]() | [windows-pebinary-ext](./protocols/stix21/sub/File-Windows-PE-Binary.md)| ![]() | [windows-process-ext](./protocols/stix21/sub/Process-Windows-Process.md) |
| ![]() | [windows-registry-value-type](./protocols/stix21/sub/Windows-Registry-Value.md)| ![]() | [windows-service-ext](./protocols/stix21/sub/Process-Windows-Service.md)| ![]() | [x509-v3-extension](./protocols/stix21/sub/X.509-Certificate Extension.md) |



#### MITRE ATT&CK 

| Icon | Object Type | Icon | Object Type | Icon | Object Type  |
|:----------:|:-----------|:----------:|:-----------|:----------:|:----------- |
| ![]() | [object-version]()| ![]() | []()| ![]() | []() |



